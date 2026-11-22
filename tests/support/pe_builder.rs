//! Builds minimal PE images for tests and benchmark fixtures.
//!
//! Shared by `tests/` and `examples/gen_bench_tree.rs` through `#[path]`.

use object::pe;
use object::write::pe::{NtHeaders, Writer};
use object::{LittleEndian as LE, U16, U32};

/// Build a minimal PE image containing an RSDS codeview debug entry
/// referencing `pdb_name`, just enough for `get_pdb` to extract a manifest
/// line from it. `is_64` selects an AMD64 (PE32+) or i386 (PE32) image.
pub fn make_pe(pdb_name: &str, guid_seed: u64, is_64: bool) -> Vec<u8> {
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
    let mut writer = Writer::new(is_64, 0x1000, 0x200, &mut out);

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

    let (machine, image_base) = if is_64 {
        (pe::IMAGE_FILE_MACHINE_AMD64, 0x1_4000_0000)
    } else {
        (pe::IMAGE_FILE_MACHINE_I386, 0x40_0000)
    };

    writer.write_empty_dos_header().unwrap();
    writer.write_nt_headers(NtHeaders {
        machine,
        time_date_stamp: 0x5F00_0000,
        characteristics: pe::IMAGE_FILE_EXECUTABLE_IMAGE,
        major_linker_version: 0,
        minor_linker_version: 0,
        address_of_entry_point: 0,
        image_base,
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
