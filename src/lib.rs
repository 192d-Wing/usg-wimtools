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

mod lzx;
mod sha1;

#[derive(Clone, Debug)]
pub struct LookupEntry {
    pub resource: Resource,
    pub hash: [u8; 20],
    pub part: u16,
}
impl<R: Read + Seek> Wim<R> {
    /// Read a specific lookup record by its zero-based ordinal.
    pub fn lookup_entry(&mut self, index: u64) -> io::Result<LookupEntry> {
        self.header.check_supported()?;
        let table = self.header.lookup;
        table.require_plain("lookup")?;
        if !table.stored_size.is_multiple_of(50) || index >= table.stored_size / 50 {
            return Err(invalid("lookup index out of range"));
        }
        self.reader
            .seek(SeekFrom::Start(table.offset + index * 50))?;
        let mut raw = [0u8; 50];
        self.reader.read_exact(&mut raw)?;
        let entry = LookupEntry {
            resource: Resource::parse(&raw[..24]),
            part: u16_at(&raw, 24),
            hash: raw[30..50].try_into().unwrap(),
        };
        if entry.part != 1 || entry.resource.flags & !0x06 != 0 || entry.resource.is_absent() {
            return Err(unsupported("unsupported lookup entry"));
        }
        entry
            .resource
            .check_bounds(self.file_size, "lookup entry")?;
        Ok(entry)
    }
    /// Decode and SHA-1 verify one lookup resource, in memory, capped at 128 MiB.
    pub fn read_verified(&mut self, entry: &LookupEntry) -> io::Result<Vec<u8>> {
        self.header.check_supported()?;
        let r = entry.resource;
        if entry.part != 1 || r.flags & !0x06 != 0 || r.is_absent() {
            return Err(unsupported("unsupported resource"));
        }
        r.check_bounds(self.file_size, "resource")?;
        const LIMIT: u64 = 128 * 1024 * 1024;
        if r.original_size > LIMIT || r.stored_size > LIMIT {
            return Err(unsupported("resource exceeds 128 MiB limit"));
        }
        self.reader.seek(SeekFrom::Start(r.offset))?;
        let mut stored = vec![0; r.stored_size as usize];
        self.reader.read_exact(&mut stored)?;
        let mut output = Vec::with_capacity(r.original_size as usize);
        if r.flags & 4 == 0 {
            r.require_plain("resource")?;
            output = stored;
        } else {
            if self.header.flags & 0x0006_0000 != 0x0004_0000 || self.header.chunk_size != 32768 {
                return Err(unsupported(
                    "only 32 KiB LZX resource decoding is supported",
                ));
            }
            let count = r.original_size.div_ceil(32768) as usize;
            if count == 0 {
                return Err(invalid("empty compressed resource"));
            }
            let width = if r.original_size > u32::MAX as u64 {
                8
            } else {
                4
            };
            let table_size = (count - 1)
                .checked_mul(width)
                .ok_or_else(|| invalid("chunk table overflow"))?;
            if table_size > stored.len() {
                return Err(invalid("truncated chunk table"));
            }
            let data = &stored[table_size..];
            let mut start = 0usize;
            for i in 0..count {
                let end = if i + 1 == count {
                    data.len()
                } else if width == 4 {
                    u32_at(&stored, i * width) as usize
                } else {
                    usize::try_from(u64_at(&stored, i * width))
                        .map_err(|_| invalid("chunk offset too large"))?
                };
                if end < start || end > data.len() {
                    return Err(invalid("invalid chunk table offset"));
                }
                let expected = (r.original_size as usize - output.len()).min(32768);
                let chunk = &data[start..end];
                if chunk.len() == expected {
                    output.extend_from_slice(chunk);
                } else if chunk.len() < expected {
                    output.extend_from_slice(&lzx::decompress(chunk, expected)?);
                } else {
                    return Err(invalid("compressed chunk larger than output"));
                }
                start = end;
            }
        }
        if output.len() as u64 != r.original_size {
            return Err(invalid("resource size mismatch"));
        }
        if sha1::digest(&output) != entry.hash {
            return Err(invalid("resource SHA-1 mismatch"));
        }
        Ok(output)
    }
}

#[derive(Debug)]
pub struct DirectoryEntry {
    pub name: String,
    pub attributes: u32,
    pub children_offset: u64,
    pub hash: [u8; 20],
    /// Offset of the directory entry within its image metadata resource.
    pub metadata_offset: usize,
}
impl<R: Read + Seek> Wim<R> {
    /// Metadata lookup entries follow image order for ordinary, single-part WIMs.
    pub fn image_metadata(&mut self, image: u32) -> io::Result<Vec<u8>> {
        if image == 0 || image > self.header.image_count {
            return Err(invalid("image index out of range"));
        }
        let mut seen = 0;
        let count = self.header.lookup.stored_size / 50;
        for i in 0..count {
            let entry = self.lookup_entry(i)?;
            if entry.resource.flags & 2 != 0 {
                seen += 1;
                if seen == image {
                    return self.read_verified(&entry);
                }
            }
        }
        Err(invalid("image metadata resource missing"))
    }
    pub fn find_hash(&mut self, hash: &[u8; 20]) -> io::Result<LookupEntry> {
        for i in 0..self.header.lookup.stored_size / 50 {
            let e = self.lookup_entry(i)?;
            if &e.hash == hash {
                return Ok(e);
            }
        }
        Err(invalid("file resource not found in lookup table"))
    }
}
/// List one directory in a verified image metadata resource. Does not interpret
/// security descriptors or alternate stream content.
pub fn directory_entries(metadata: &[u8], offset: usize) -> io::Result<Vec<DirectoryEntry>> {
    let mut pos = offset;
    let mut entries = Vec::new();
    loop {
        let head = metadata
            .get(
                pos..pos
                    .checked_add(8)
                    .ok_or_else(|| invalid("directory offset overflow"))?,
            )
            .ok_or_else(|| invalid("truncated directory"))?;
        let len = u64_at(head, 0);
        if len == 0 {
            return Ok(entries);
        }
        let len = usize::try_from(len).map_err(|_| invalid("entry too large"))?;
        if len < 102 {
            return Err(invalid("short directory entry"));
        }
        let end = pos
            .checked_add(len)
            .ok_or_else(|| invalid("directory entry overflow"))?;
        let entry = metadata
            .get(pos..end)
            .ok_or_else(|| invalid("truncated directory entry"))?;
        let streams = u16_at(entry, 96);
        let name_len = usize::from(u16_at(entry, 100));
        if !name_len.is_multiple_of(2) || 102 + name_len > entry.len() {
            return Err(invalid("invalid directory name length"));
        }
        let units: Vec<u16> = entry[102..102 + name_len]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let name = String::from_utf16(&units).map_err(|_| invalid("invalid UTF-16 filename"))?;
        if name.contains(['/', '\\', '\0']) {
            return Err(invalid("invalid WIM filename"));
        }
        entries.push(DirectoryEntry {
            name,
            attributes: u32_at(entry, 8),
            children_offset: u64_at(entry, 16),
            hash: entry[64..84].try_into().unwrap(),
            metadata_offset: pos,
        });
        pos = end;
        for _ in 0..streams {
            let head = metadata
                .get(
                    pos..pos
                        .checked_add(8)
                        .ok_or_else(|| invalid("stream overflow"))?,
                )
                .ok_or_else(|| invalid("truncated stream entry"))?;
            let size = usize::try_from(u64_at(head, 0)).map_err(|_| invalid("stream too large"))?;
            if size < 38 {
                return Err(invalid("short alternate stream entry"));
            }
            pos = pos
                .checked_add(size)
                .filter(|&p| p <= metadata.len())
                .ok_or_else(|| invalid("truncated stream entry"))?;
        }
        if entries.len() > 1_000_000 {
            return Err(unsupported("directory entry limit exceeded"));
        }
    }
}
pub fn root_offset(metadata: &[u8]) -> io::Result<usize> {
    if metadata.len() < 8 {
        return Err(invalid("truncated security metadata"));
    }
    let size = u32_at(metadata, 0) as usize;
    if size < 8 {
        return Err(invalid("invalid security table length"));
    }
    let offset = size
        .checked_add(7)
        .ok_or_else(|| invalid("security size overflow"))?
        & !7;
    if offset >= metadata.len() {
        return Err(invalid("root entry outside metadata"));
    }
    Ok(offset)
}
/// Resolve a slash-separated image path. Reparse points are not traversed.
pub fn find_image_path(metadata: &[u8], path: &str) -> io::Result<DirectoryEntry> {
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    if parts.is_empty()
        || parts
            .iter()
            .any(|p| *p == "." || *p == ".." || p.contains('\\'))
    {
        return Err(invalid("invalid image path"));
    }
    let root = directory_entries(metadata, root_offset(metadata)?)?;
    let mut next = root
        .first()
        .ok_or_else(|| invalid("missing image root"))?
        .children_offset;
    for (i, part) in parts.iter().enumerate() {
        let offset = usize::try_from(next).map_err(|_| invalid("directory offset too large"))?;
        if offset == 0 {
            return Err(invalid("image path not found"));
        }
        let entries = directory_entries(metadata, offset)?;
        let entry = entries
            .into_iter()
            .find(|e| e.name.eq_ignore_ascii_case(part))
            .ok_or_else(|| invalid(format!("image path component not found: {part}")))?;
        if i + 1 == parts.len() {
            return Ok(entry);
        }
        if entry.attributes & 0x10 == 0 || entry.attributes & 0x400 != 0 {
            return Err(invalid(
                "image path contains a non-directory or reparse point",
            ));
        }
        next = entry.children_offset;
    }
    Err(invalid("image path not found"))
}

mod export;
pub use export::{export_one, replace_file};

pub mod inf;

pub mod registry;

pub mod manifest;
