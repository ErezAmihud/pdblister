//! Regression test for file handle exhaustion in `pdblister manifest`.
//!
//! The manifest command used to hold a `DirEntry` for every file in the tree
//! at once. On Unix a `DirEntry` keeps its parent directory's handle open, so
//! scanning a tree with more directories than the process's file handle limit
//! made `read_dir` fail with EMFILE and silently dropped entries from the
//! manifest. This test scans such a tree under a lowered fd limit and checks
//! that every file still makes it into the manifest.
//!
//! Unix-only: the fd limit is imposed with the shell's `ulimit -n`.
#![cfg(unix)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// Number of directories (each holding one PE file) in the generated tree.
/// Must comfortably exceed `FD_LIMIT` for the test to be meaningful.
const NUM_DIRS: usize = 1024;

/// Soft file handle limit imposed on the pdblister process.
const FD_LIMIT: usize = 256;

/// Build a minimal PE image containing an RSDS codeview entry referencing
/// `pdb_name`, just enough for `get_pdb` to extract a manifest line from it.
fn make_pe(pdb_name: &str, guid_seed: u64) -> Vec<u8> {
    const NUM_TABLES: u32 = 16;
    // Field offsets below follow the packed structs in src/pe.rs.
    let opt_size = 112 + NUM_TABLES as usize * 8;
    let sec_table_off = 0x40 + 0x18 + opt_size; // 328
    let debug_raw_off = (sec_table_off + 40) as u32; // 368
    let cv_off = debug_raw_off + 28; // 396

    // MZHeader
    let mut mz = [0u8; 0x40];
    mz[0..2].copy_from_slice(b"MZ");
    mz[60..64].copy_from_slice(&0x40u32.to_le_bytes()); // new_header

    // PEHeader
    let mut pe = Vec::with_capacity(0x18);
    pe.extend_from_slice(b"PE\0\0");
    pe.extend_from_slice(&0x8664u16.to_le_bytes()); // machine (AMD64)
    pe.extend_from_slice(&1u16.to_le_bytes()); // num_sections
    pe.extend_from_slice(&0x5F00_0000u32.to_le_bytes()); // timestamp
    pe.extend_from_slice(&[0u8; 8]); // ptr_symtable, num_smtable
    pe.extend_from_slice(&(opt_size as u16).to_le_bytes());
    pe.extend_from_slice(&0x22u16.to_le_bytes()); // characteristics

    // WindowsPEHeader64
    let mut opt = [0u8; 112];
    opt[0..2].copy_from_slice(&0x20Bu16.to_le_bytes()); // magic (PE32+)
    opt[24..32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes()); // image_base
    opt[32..36].copy_from_slice(&0x1000u32.to_le_bytes()); // section_align
    opt[36..40].copy_from_slice(&0x200u32.to_le_bytes()); // file_align
    opt[56..60].copy_from_slice(&0x3000u32.to_le_bytes()); // size_of_image
    opt[60..64].copy_from_slice(&0x400u32.to_le_bytes()); // size_of_headers
    opt[68..70].copy_from_slice(&2u16.to_le_bytes()); // subsystem
    opt[108..112].copy_from_slice(&NUM_TABLES.to_le_bytes());

    // Data directories; entry 6 is the debug directory.
    let mut datadirs = [0u8; (NUM_TABLES * 8) as usize];
    datadirs[48..52].copy_from_slice(&0x1000u32.to_le_bytes()); // vaddr
    datadirs[52..56].copy_from_slice(&28u32.to_le_bytes()); // size

    // One section mapping vaddr 0x1000 to the debug directory's file offset.
    let mut section = [0u8; 40];
    section[0..8].copy_from_slice(b".rdata\0\0");
    section[8..12].copy_from_slice(&0x200u32.to_le_bytes()); // vsize
    section[12..16].copy_from_slice(&0x1000u32.to_le_bytes()); // vaddr
    section[16..20].copy_from_slice(&0x200u32.to_le_bytes()); // raw_data_size
    section[20..24].copy_from_slice(&debug_raw_off.to_le_bytes());

    // ImageDebugDirectory (type 2 = codeview)
    let cv_size = 24 + pdb_name.len() as u32 + 1;
    let mut debug_dir = [0u8; 28];
    debug_dir[12..16].copy_from_slice(&2u32.to_le_bytes()); // typ
    debug_dir[16..20].copy_from_slice(&cv_size.to_le_bytes()); // size_of_data
    debug_dir[24..28].copy_from_slice(&cv_off.to_le_bytes());

    // CodeviewEntry followed by the null-terminated PDB path.
    let mut cv = Vec::with_capacity(cv_size as usize);
    cv.extend_from_slice(b"RSDS");
    cv.extend_from_slice(&(guid_seed as u32).to_le_bytes()); // guid_a
    cv.extend_from_slice(&((guid_seed >> 32) as u16).to_le_bytes()); // guid_b
    cv.extend_from_slice(&((guid_seed >> 48) as u16).to_le_bytes()); // guid_c
    cv.extend_from_slice(&guid_seed.to_le_bytes()); // guid_d
    cv.extend_from_slice(&1u32.to_le_bytes()); // age
    cv.extend_from_slice(pdb_name.as_bytes());
    cv.push(0);

    let mut out = Vec::new();
    out.extend_from_slice(&mz);
    out.extend_from_slice(&pe);
    out.extend_from_slice(&opt);
    out.extend_from_slice(&datadirs);
    out.extend_from_slice(&section);
    out.extend_from_slice(&debug_dir);
    out.extend_from_slice(&cv);
    out
}

/// Temporary directory that is removed on drop.
struct TempTree(PathBuf);

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn manifest_survives_low_file_handle_limit() {
    let root = std::env::temp_dir().join(format!("pdblister-fd-limit-test-{}", std::process::id()));
    let _guard = TempTree(root.clone());

    let tree = root.join("tree");
    for i in 0..NUM_DIRS {
        let dir = tree.join(format!("dir{i:05}"));
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join(format!("mod{i:05}.dll")),
            make_pe(&format!("mod{i:05}.pdb"), i as u64 + 1),
        )
        .unwrap();
    }

    // Lower the soft fd limit for the child only, then exec pdblister.
    let manifest = root.join("manifest");
    let status = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "ulimit -n {FD_LIMIT} && exec \"$0\" manifest \"$1\" \"$2\""
        ))
        .arg(env!("CARGO_BIN_EXE_pdblister"))
        .arg(&tree)
        .arg(&manifest)
        .status()
        .expect("failed to spawn pdblister");
    assert!(status.success(), "pdblister manifest exited with {status}");

    let contents = fs::read_to_string(&manifest).expect("manifest file was not created");
    let mut names: Vec<&str> = contents
        .lines()
        .map(|line| line.split(',').next().unwrap())
        .collect();
    names.sort_unstable();

    assert_eq!(
        names.len(),
        NUM_DIRS,
        "manifest is missing entries; likely file handle exhaustion while scanning"
    );
    for (i, name) in names.iter().enumerate() {
        assert_eq!(*name, format!("mod{i:05}.pdb"));
    }
}
