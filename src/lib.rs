#![forbid(unsafe_code)]
//! Read-only WIM inspection based on Microsoft's published WIM format.
//! Structural checks do not establish cryptographic integrity or bootability.

use std::io::{self, Read, Seek, SeekFrom};

pub const HEADER_SIZE: usize = 208;
pub const CLASSIC_VERSION: u32 = 0x0001_0d00;
const XML_LIMIT: u64 = 16 * 1024 * 1024;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
fn unsupported(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message.into())
}
fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}
fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("fixed internal layout"))
}
fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("fixed internal layout"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resource {
    pub stored_size: u64,
    pub flags: u8,
    pub offset: u64,
    pub original_size: u64,
}

impl Resource {
    fn parse(bytes: &[u8]) -> Self {
        Self {
            stored_size: u64_at(bytes, 0) & 0x00ff_ffff_ffff_ffff,
            flags: bytes[7],
            offset: u64_at(bytes, 8),
            original_size: u64_at(bytes, 16),
        }
    }

    pub fn is_absent(self) -> bool {
        self.stored_size == 0 && self.flags == 0 && self.offset == 0 && self.original_size == 0
    }

    fn check_bounds(self, file_size: u64, name: &str) -> io::Result<()> {
        if self.is_absent() {
            return Ok(());
        }
        let end = self
            .offset
            .checked_add(self.stored_size)
            .ok_or_else(|| invalid(format!("{name}: offset overflow")))?;
        if self.offset < HEADER_SIZE as u64 || end > file_size {
            return Err(invalid(format!("{name}: resource outside file payload")));
        }
        Ok(())
    }

    fn require_plain(self, name: &str) -> io::Result<()> {
        // The metadata bit does not imply compression. Windows-generated
        // lookup and XML resources can carry it even when stored verbatim.
        if self.flags & !0x02 != 0 {
            return Err(unsupported(format!(
                "{name}: resource flags 0x{:02x} are unsupported",
                self.flags
            )));
        }
        if self.stored_size != self.original_size {
            return Err(invalid(format!("{name}: uncompressed sizes disagree")));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Header {
    pub version: u32,
    pub flags: u32,
    pub chunk_size: u32,
    /// Raw on-disk GUID bytes; no platform GUID representation is assumed.
    pub guid: [u8; 16],
    pub part_number: u16,
    pub total_parts: u16,
    pub image_count: u32,
    pub lookup: Resource,
    pub xml: Resource,
    pub boot_metadata: Resource,
    pub boot_index: u32,
    pub integrity: Resource,
}

impl Header {
    pub fn parse(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() < HEADER_SIZE {
            return Err(invalid("truncated WIM header"));
        }
        if &bytes[..8] != b"MSWIM\0\0\0" {
            return Err(invalid("not a standard MSWIM file"));
        }
        if u32_at(bytes, 8) != HEADER_SIZE as u32 {
            return Err(unsupported("only 208-byte WIM headers are supported"));
        }
        Ok(Self {
            version: u32_at(bytes, 12),
            flags: u32_at(bytes, 16),
            chunk_size: u32_at(bytes, 20),
            guid: bytes[24..40].try_into().unwrap(),
            part_number: u16_at(bytes, 40),
            total_parts: u16_at(bytes, 42),
            image_count: u32_at(bytes, 44),
            lookup: Resource::parse(&bytes[48..72]),
            xml: Resource::parse(&bytes[72..96]),
            boot_metadata: Resource::parse(&bytes[96..120]),
            boot_index: u32_at(bytes, 120),
            integrity: Resource::parse(&bytes[124..148]),
        })
    }

    fn check_supported(&self) -> io::Result<()> {
        if self.version != CLASSIC_VERSION {
            return Err(unsupported(format!(
                "WIM version 0x{:08x} is inspectable, but cannot be checked",
                self.version
            )));
        }
        if self.part_number != 1 || self.total_parts != 1 || self.flags & 8 != 0 {
            return Err(unsupported("split/spanned WIM checking is not implemented"));
        }
        if self.flags & 0x40 != 0 {
            return Err(invalid("WIM header marks a write in progress"));
        }
        // Only compression, read-only, reparse-fixup, XPRESS, LZX.
        if self.flags & !0x0006_0086 != 0 {
            return Err(unsupported(format!(
                "unsupported WIM flags 0x{:08x}",
                self.flags
            )));
        }
        let codec = self.flags & 0x0006_0000;
        if self.flags & 2 != 0 {
            if !matches!(codec, 0x0002_0000 | 0x0004_0000) || self.chunk_size != 32768 {
                return Err(unsupported(
                    "only classic 32-KiB XPRESS/LZX resource layouts can be checked",
                ));
            }
        } else if codec != 0 || self.chunk_size != 0 {
            return Err(invalid("compression fields disagree with header flags"));
        }
        if self.boot_index > self.image_count {
            return Err(invalid("boot index exceeds image count"));
        }
        if (self.boot_index == 0) != self.boot_metadata.is_absent() {
            return Err(invalid("boot index and boot metadata disagree"));
        }
        Ok(())
    }
}

pub struct Wim<R> {
    reader: R,
    pub header: Header,
    pub file_size: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct StructureReport {
    pub lookup_entries: u64,
    pub metadata_entries: u64,
    pub integrity_table_present: bool,
}

impl<R: Read + Seek> Wim<R> {
    pub fn open(mut reader: R) -> io::Result<Self> {
        let file_size = reader.seek(SeekFrom::End(0))?;
        reader.seek(SeekFrom::Start(0))?;
        let mut bytes = [0; HEADER_SIZE];
        reader.read_exact(&mut bytes)?;
        let header = Header::parse(&bytes)?;
        for (name, resource) in [
            ("lookup", header.lookup),
            ("XML", header.xml),
            ("boot metadata", header.boot_metadata),
            ("integrity", header.integrity),
        ] {
            resource.check_bounds(file_size, name)?;
        }
        Ok(Self {
            reader,
            header,
            file_size,
        })
    }

    /// Decodes the XML resource as text. Does not parse or validate XML semantics.
    pub fn xml_text(&mut self) -> io::Result<String> {
        let resource = self.header.xml;
        if resource.is_absent() {
            return Err(invalid("WIM has no XML resource"));
        }
        resource.require_plain("XML")?;
        if resource.stored_size > XML_LIMIT {
            return Err(unsupported("XML resource exceeds the 16-MiB safety limit"));
        }
        if resource.stored_size < 2 || !resource.stored_size.is_multiple_of(2) {
            return Err(invalid(
                "XML must contain a BOM and whole UTF-16 code units",
            ));
        }
        self.reader.seek(SeekFrom::Start(resource.offset))?;
        let mut bytes = vec![0; resource.stored_size as usize];
        self.reader.read_exact(&mut bytes)?;
        if bytes[..2] != [0xff, 0xfe] {
            return Err(unsupported("only UTF-16LE XML with a BOM is supported"));
        }
        let units: Vec<u16> = bytes[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        String::from_utf16(&units).map_err(|_| invalid("invalid UTF-16 in XML resource"))
    }

    /// Checks header consistency and lookup resource ranges, not resource hashes,
    /// compressed contents, directory metadata, XML semantics, or bootability.
    pub fn check_structure(&mut self) -> io::Result<StructureReport> {
        self.header.check_supported()?;
        let table = self.header.lookup;
        if table.is_absent() {
            return Err(invalid("missing resource lookup table"));
        }
        table.require_plain("lookup")?;
        if !table.stored_size.is_multiple_of(50) {
            return Err(invalid("lookup size is not a multiple of 50 bytes"));
        }
        self.xml_text()?;
        self.reader.seek(SeekFrom::Start(table.offset))?;
        let entries = table.stored_size / 50;
        let mut metadata = 0;
        let mut boot_found = self.header.boot_metadata.is_absent();
        for index in 0..entries {
            let mut bytes = [0; 50];
            self.reader.read_exact(&mut bytes)?;
            let resource = Resource::parse(&bytes[..24]);
            if resource.flags & !0x07 != 0 {
                return Err(unsupported(format!(
                    "lookup entry {index}: unsupported resource flags"
                )));
            }
            if resource.flags & 1 != 0 {
                continue; // Free entries do not describe live resources.
            }
            if u16_at(&bytes, 24) != 1 {
                return Err(invalid(format!(
                    "lookup entry {index}: invalid part number"
                )));
            }
            resource.check_bounds(self.file_size, "lookup entry")?;
            if resource.is_absent() {
                return Err(invalid("live lookup entry has no resource"));
            }
            if resource.flags & 4 == 0 && resource.stored_size != resource.original_size {
                return Err(invalid("uncompressed lookup resource sizes disagree"));
            }
            if resource.flags & 4 != 0 && self.header.flags & 2 == 0 {
                return Err(invalid("compressed resource in an uncompressed WIM"));
            }
            if resource.flags & 2 != 0 {
                metadata += 1;
                if resource == self.header.boot_metadata {
                    boot_found = true;
                }
            }
        }
        if metadata != u64::from(self.header.image_count) {
            return Err(invalid("metadata resource count differs from image count"));
        }
        if !boot_found {
            return Err(invalid("boot metadata not found in lookup table"));
        }
        Ok(StructureReport {
            lookup_entries: entries,
            metadata_entries: metadata,
            integrity_table_present: !self.header.integrity.is_absent(),
        })
    }
}
