//! Generates the directory trees that the CodSpeed benchmarks in
//! `codspeed.yml` scan with `pdblister manifest`.
//!
//! Usage: `cargo run --release --example gen_bench_tree -- [OUTPUT_DIR]`
//! (defaults to `target/bench-data`). The output is deterministic and the
//! output directory is recreated on every run.

use std::fs;
use std::path::{Path, PathBuf};

#[path = "../tests/support/pe_builder.rs"]
mod pe_builder;

use pe_builder::make_pe;

/// Small deterministic PRNG (SplitMix64) so the trees are identical on
/// every machine.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next() as u8).collect()
    }
}

/// Write a PE with a codeview entry. About a third of them are 32-bit.
fn write_pe(dir: &Path, stem: &str, ext: &str, rng: &mut Rng) {
    let seed = rng.next();
    let is_64 = seed % 3 != 0;
    let image = make_pe(&format!("{stem}.pdb"), seed, is_64);
    fs::write(dir.join(format!("{stem}.{ext}")), image).unwrap();
}

/// Write a file that is not a PE image, as found next to binaries in real
/// install trees (resources, configs, data blobs).
fn write_other(dir: &Path, stem: &str, idx: usize, rng: &mut Rng) {
    match idx % 4 {
        0 => fs::write(
            dir.join(format!("{stem}.ini")),
            format!("[{stem}]\nEnabled=1\nPath=C:\\Program Files\\{stem}\n"),
        ),
        1 => fs::write(dir.join(format!("{stem}.dat")), rng.bytes(4096)),
        // Starts with an MZ signature but has no valid PE header.
        2 => {
            let mut data = b"MZ".to_vec();
            data.extend(rng.bytes(510));
            fs::write(dir.join(format!("{stem}.bin")), data)
        }
        _ => fs::write(dir.join(format!("{stem}.txt")), rng.bytes(256)),
    }
    .unwrap();
}

/// A wide, shallow tree similar to `C:\Windows\System32`: many files in the
/// root and a few subdirectories, with PEs mixed among other files.
fn gen_system32(root: &Path, rng: &mut Rng) {
    fs::create_dir_all(root).unwrap();
    for i in 0..3000 {
        let ext = if i % 5 == 0 { "exe" } else { "dll" };
        write_pe(root, &format!("mod{i:04}"), ext, rng);
        write_other(root, &format!("res{i:04}"), i, rng);
    }

    for d in 0..40 {
        let dir = root.join(format!("sub{d:02}"));
        fs::create_dir_all(&dir).unwrap();
        for i in 0..25 {
            write_pe(&dir, &format!("sub{d:02}_mod{i:02}"), "dll", rng);
            write_other(&dir, &format!("sub{d:02}_res{i:02}"), i, rng);
        }
    }
}

/// A deep tree of 16 x 16 x 8 directories, each holding one PE and one
/// other file, to stress the directory walk.
fn gen_deep(root: &Path, rng: &mut Rng) {
    for a in 0..16 {
        for b in 0..16 {
            for c in 0..8 {
                let dir = root.join(format!("a{a:02}/b{b:02}/c{c}"));
                fs::create_dir_all(&dir).unwrap();
                let stem = format!("m{a:02}{b:02}{c}");
                write_pe(&dir, &stem, "dll", rng);
                write_other(&dir, &stem, a + b + c, rng);
            }
        }
    }
}

fn main() {
    let out: PathBuf = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target/bench-data"));

    if out.exists() {
        fs::remove_dir_all(&out).unwrap();
    }

    let mut rng = Rng(0x5EED);
    gen_system32(&out.join("system32"), &mut rng);
    gen_deep(&out.join("deep"), &mut rng);

    println!("Generated benchmark trees in {}", out.display());
}
