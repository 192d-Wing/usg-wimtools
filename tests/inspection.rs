use std::io::Cursor;
use usg_wimtools::{CLASSIC_VERSION, HEADER_SIZE, Header, Wim};

fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn descriptor(bytes: &mut [u8], at: usize, offset: u64, size: u64, flags: u8) {
    bytes[at..at + 8].copy_from_slice(&(size | (u64::from(flags) << 56)).to_le_bytes());
    bytes[at + 8..at + 16].copy_from_slice(&offset.to_le_bytes());
    bytes[at + 16..at + 24].copy_from_slice(&size.to_le_bytes());
}

// Synthetic envelope, deliberately not a bootable image. The metadata payload
// is opaque because this milestone checks ranges rather than metadata contents.
fn fixture() -> Vec<u8> {
    let xml: Vec<u8> = std::iter::once(0xfeffu16)
        .chain("<WIM><IMAGE INDEX=\"1\"><NAME>Test 🦀</NAME></IMAGE></WIM>".encode_utf16())
        .flat_map(u16::to_le_bytes)
        .collect();
    let mut bytes = vec![0; 266];
    bytes[..8].copy_from_slice(b"MSWIM\0\0\0");
    put32(&mut bytes, 8, HEADER_SIZE as u32);
    put32(&mut bytes, 12, CLASSIC_VERSION);
    bytes[40] = 1;
    bytes[42] = 1;
    put32(&mut bytes, 44, 1);
    descriptor(&mut bytes, 48, 216, 50, 0);
    descriptor(&mut bytes, 72, 266, xml.len() as u64, 0);
    descriptor(&mut bytes, 216, 208, 8, 2);
    bytes[240] = 1;
    put32(&mut bytes, 242, 1);
    bytes.extend(xml);
    bytes
}

#[test]
fn reads_header_xml_and_resource_ranges() {
    let mut wim = Wim::open(Cursor::new(fixture())).unwrap();
    assert_eq!(wim.header.image_count, 1);
    assert!(wim.xml_text().unwrap().contains("Test 🦀"));
    let report = wim.check_structure().unwrap();
    assert_eq!(report.lookup_entries, 1);
    assert_eq!(report.metadata_entries, 1);
    assert!(!report.integrity_table_present);
}

#[test]
fn accepts_metadata_flag_on_plain_lookup_and_xml_resources() {
    let mut bytes = fixture();
    bytes[55] = 2;
    bytes[79] = 2;
    let mut wim = Wim::open(Cursor::new(bytes)).unwrap();
    assert!(wim.xml_text().unwrap().contains("Test 🦀"));
    assert_eq!(wim.check_structure().unwrap().metadata_entries, 1);
}

#[test]
fn rejects_every_truncated_header_without_panicking() {
    let bytes = fixture();
    for end in 0..HEADER_SIZE {
        assert!(Header::parse(&bytes[..end]).is_err());
        assert!(Wim::open(Cursor::new(&bytes[..end])).is_err());
    }
}

#[test]
fn rejects_bad_magic_and_unknown_header_size() {
    let mut bytes = fixture();
    bytes[0] = 0;
    assert!(Wim::open(Cursor::new(bytes)).is_err());
    let mut bytes = fixture();
    put32(&mut bytes, 8, 224);
    assert!(Wim::open(Cursor::new(bytes)).is_err());
}

#[test]
fn rejects_out_of_file_and_overflowing_resource_ranges() {
    for offset in [1, 10000, u64::MAX - 1] {
        let mut bytes = fixture();
        descriptor(&mut bytes, 72, offset, 8, 0);
        assert!(Wim::open(Cursor::new(bytes)).is_err());
    }
}

#[test]
fn rejects_inconsistent_image_and_boot_counts() {
    for (at, value) in [(44, 2), (120, 2), (120, 1)] {
        let mut bytes = fixture();
        put32(&mut bytes, at, value);
        assert!(
            Wim::open(Cursor::new(bytes))
                .unwrap()
                .check_structure()
                .is_err()
        );
    }
}

#[test]
fn unsupported_formats_never_report_a_successful_check() {
    for (at, value) in [
        (12, 0x0001_0e00),
        (16, 8),
        (16, 0x0008_0002),
        (16, 0x40),
        (16, 0x8000_0000),
    ] {
        let mut bytes = fixture();
        put32(&mut bytes, at, value);
        assert!(
            Wim::open(Cursor::new(bytes))
                .unwrap()
                .check_structure()
                .is_err()
        );
    }
    let mut bytes = fixture();
    bytes[42] = 2;
    assert!(
        Wim::open(Cursor::new(bytes))
            .unwrap()
            .check_structure()
            .is_err()
    );
}

#[test]
fn rejects_bad_lookup_alignment_part_and_sizes() {
    let mut bytes = fixture();
    descriptor(&mut bytes, 48, 216, 49, 0);
    assert!(
        Wim::open(Cursor::new(bytes))
            .unwrap()
            .check_structure()
            .is_err()
    );
    let mut bytes = fixture();
    bytes[240] = 2;
    assert!(
        Wim::open(Cursor::new(bytes))
            .unwrap()
            .check_structure()
            .is_err()
    );
    let mut bytes = fixture();
    bytes[232] = 9;
    assert!(
        Wim::open(Cursor::new(bytes))
            .unwrap()
            .check_structure()
            .is_err()
    );
}

#[test]
fn rejects_compressed_or_malformed_xml() {
    let mut bytes = fixture();
    bytes[79] = 4;
    assert!(Wim::open(Cursor::new(bytes)).unwrap().xml_text().is_err());
    let mut bytes = fixture();
    bytes[266] = 0;
    assert!(Wim::open(Cursor::new(bytes)).unwrap().xml_text().is_err());
    let mut bytes = fixture();
    // Isolated UTF-16 high surrogate at the end of the text.
    let len = bytes.len();
    bytes[len - 2..].copy_from_slice(&0xd800u16.to_le_bytes());
    assert!(Wim::open(Cursor::new(bytes)).unwrap().xml_text().is_err());
}

#[test]
fn checks_classic_compressed_container_without_claiming_decompression() {
    for codec in [0x0002_0002, 0x0004_0002] {
        let mut bytes = fixture();
        put32(&mut bytes, 16, codec);
        put32(&mut bytes, 20, 32768);
        assert!(
            Wim::open(Cursor::new(bytes))
                .unwrap()
                .check_structure()
                .is_ok()
        );
    }
}

#[test]
fn file_cli_handles_unicode_and_spaces_without_mutation() {
    use std::{fs, process::Command};
    let directory = std::env::temp_dir().join(format!("usg-wimtools-{}", std::process::id()));
    fs::create_dir_all(&directory).unwrap();
    let path = directory.join("test 🦀 image.wim");
    let bytes = fixture();
    fs::write(&path, &bytes).unwrap();
    for command in ["info", "xml", "check-structure"] {
        let result = Command::new(env!("CARGO_BIN_EXE_usg-wimtools"))
            .arg(command)
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }
    let result = Command::new(env!("CARGO_BIN_EXE_usg-wimtools"))
        .arg("add-driver")
        .arg(&path)
        .output()
        .unwrap();
    assert!(!result.status.success());
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn verifies_plain_resource_and_rejects_changed_content() {
    let mut bytes = fixture();
    let payload_offset = bytes.len() as u64;
    bytes.extend_from_slice(b"abc");
    descriptor(&mut bytes, 216, payload_offset, 3, 0);
    bytes[246..266].copy_from_slice(&[
        0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2,
        0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
    ]);
    let mut wim = Wim::open(Cursor::new(bytes.clone())).unwrap();
    let entry = wim.lookup_entry(0).unwrap();
    assert_eq!(wim.read_verified(&entry).unwrap(), b"abc");
    *bytes.last_mut().unwrap() = b'd';
    let mut wim = Wim::open(Cursor::new(bytes)).unwrap();
    let entry = wim.lookup_entry(0).unwrap();
    assert!(wim.read_verified(&entry).is_err());
    assert!(wim.lookup_entry(1).is_err());
}

#[test]
fn parses_directory_entries_and_rejects_bad_offsets() {
    let mut data = vec![0u8; 240];
    put32(&mut data, 0, 8);
    data[8..16].copy_from_slice(&104u64.to_le_bytes());
    put32(&mut data, 16, 0x10);
    data[24..32].copy_from_slice(&120u64.to_le_bytes());
    data[120..128].copy_from_slice(&112u64.to_le_bytes());
    data[220..222].copy_from_slice(&6u16.to_le_bytes());
    for (i, ch) in "abc".encode_utf16().enumerate() {
        data[222 + i * 2..224 + i * 2].copy_from_slice(&ch.to_le_bytes());
    }
    let result = usg_wimtools::find_image_path(&data, "abc").unwrap();
    assert_eq!(result.name, "abc");
    assert!(usg_wimtools::find_image_path(&data, "../abc").is_err());
    assert!(usg_wimtools::directory_entries(&data, usize::MAX).is_err());
    data[220..222].copy_from_slice(&255u16.to_le_bytes());
    assert!(usg_wimtools::find_image_path(&data, "abc").is_err());
}
