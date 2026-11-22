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

#[path = "support/pe_builder.rs"]
mod pe_builder;

use pe_builder::make_pe;

/// Number of directories (each holding one PE file) in the generated tree.
/// Must comfortably exceed `FD_LIMIT` for the test to be meaningful.
const NUM_DIRS: usize = 1024;

/// Soft file handle limit imposed on the pdblister process.
const FD_LIMIT: usize = 256;

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
            make_pe(&format!("mod{i:05}.pdb"), i as u64 + 1, true),
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
    assert!(status.success(), "{}", "pdblister manifest exited with {status}");

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
