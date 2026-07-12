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

use object::pe;
use object::write::pe::{NtHeaders, Writer};
use object::{LittleEndian as LE, U16, U32};

/// Number of directories (each holding one PE file) in the generated tree.
/// Must comfortably exceed `FD_LIMIT` for the test to be meaningful.
const NUM_DIRS: usize = 1024;

/// Soft file handle limit imposed on the pdblister process.
const FD_LIMIT: usize = 256;

/// Build a minimal PE image containing an RSDS codeview debug entry
/// referencing `pdb_name`, just enough for `get_pdb` to extract a manifest
/// line from it.
fn make_pe(pdb_name: &str, guid_seed: u64) -> Vec<u8> {
    // RSDS codeview record: signature, GUID, age, then the PDB path.
    let mut cv = Vec::new();
    cv.extend_from_slice(b"RSDS");
    cv.extend_from_slice(&(guid_seed as u32).to_le_bytes());
    cv.extend_from_slice(&((guid_seed >> 32) as u16).to_le_bytes());
    cv.extend_from_slice(&((guid_seed >> 48) as u16).to_le_bytes());
    cv.extend_from_slice(&guid_seed.to_le_bytes());
    cv.extend_from_slice(&1u32.to_le_bytes()); // age
    cv.extend_from_slice(pdb_name.as_bytes());
    cv.push(0);

    let debug_dir_len = std::mem::size_of::<pe::ImageDebugDirectory>() as u32;
    let section_len = debug_dir_len + cv.len() as u32;

    let mut out = Vec::new();
    let mut writer = Writer::new(true, 0x1000, 0x200, &mut out);

    writer.reserve_dos_header();
    writer.reserve_nt_headers(pe::IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
    writer.reserve_section_headers(1);
    let range = writer.reserve_section(
        *b".rdata\0\0",
        pe::IMAGE_SCN_CNT_INITIALIZED_DATA | pe::IMAGE_SCN_MEM_READ,
        section_len,
        section_len,
    );
    writer.set_data_directory(
        pe::IMAGE_DIRECTORY_ENTRY_DEBUG,
        range.virtual_address,
        debug_dir_len,
    );

    writer.write_empty_dos_header().unwrap();
    writer.write_nt_headers(NtHeaders {
        machine: pe::IMAGE_FILE_MACHINE_AMD64,
        time_date_stamp: 0x5F00_0000,
        characteristics: pe::IMAGE_FILE_EXECUTABLE_IMAGE,
        major_linker_version: 0,
        minor_linker_version: 0,
        address_of_entry_point: 0,
        image_base: 0x1_4000_0000,
        major_operating_system_version: 0,
        minor_operating_system_version: 0,
        major_image_version: 0,
        minor_image_version: 0,
        major_subsystem_version: 0,
        minor_subsystem_version: 0,
        subsystem: pe::IMAGE_SUBSYSTEM_WINDOWS_CUI,
        dll_characteristics: 0,
        size_of_stack_reserve: 0,
        size_of_stack_commit: 0,
        size_of_heap_reserve: 0,
        size_of_heap_commit: 0,
    });
    writer.write_section_headers();

    // The section holds the debug directory itself, immediately followed by
    // the codeview record it points at.
    let debug_dir = pe::ImageDebugDirectory {
        characteristics: U32::new(LE, 0),
        time_date_stamp: U32::new(LE, 0),
        major_version: U16::new(LE, 0),
        minor_version: U16::new(LE, 0),
        typ: U32::new(LE, pe::IMAGE_DEBUG_TYPE_CODEVIEW),
        size_of_data: U32::new(LE, cv.len() as u32),
        address_of_raw_data: U32::new(LE, range.virtual_address + debug_dir_len),
        pointer_to_raw_data: U32::new(LE, range.file_offset + debug_dir_len),
    };
    let mut content = object::bytes_of(&debug_dir).to_vec();
    content.extend_from_slice(&cv);
    writer.write_section(range.file_offset, &content);

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
