//! Experimental single-image export preserving existing resource bytes.
use crate::{HEADER_SIZE, Wim, invalid, sha1, u16_at, u32_at, u64_at, unsupported};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

type Hash = [u8; 20];

fn references(data: &[u8]) -> io::Result<HashMap<Hash, u32>> {
    let root = crate::root_offset(data)?;
    let mut dirs = vec![root];
    let mut visited = HashSet::new();
    let mut counts = HashMap::<Hash, u32>::new();
    while let Some(mut pos) = dirs.pop() {
        if !visited.insert(pos) {
            return Err(invalid("duplicate or cyclic directory offset"));
        }
        loop {
            let head = data
                .get(
                    pos..pos
                        .checked_add(8)
                        .ok_or_else(|| invalid("directory offset overflow"))?,
                )
                .ok_or_else(|| invalid("truncated directory"))?;
            let len = usize::try_from(u64_at(head, 0)).map_err(|_| invalid("entry too large"))?;
            if len == 0 {
                break;
            }
            if len < 102 {
                return Err(invalid("short metadata entry"));
            }
            let end = pos
                .checked_add(len)
                .filter(|&e| e <= data.len())
                .ok_or_else(|| invalid("truncated metadata entry"))?;
            let entry = &data[pos..end];
            let name = usize::from(u16_at(entry, 100));
            if !name.is_multiple_of(2) || 102 + name > len {
                return Err(invalid("invalid metadata filename"));
            }
            let attrs = u32_at(entry, 8);
            let child = usize::try_from(u64_at(entry, 16))
                .map_err(|_| invalid("child offset too large"))?;
            if child != 0 {
                if attrs & 0x10 == 0 || attrs & 0x400 != 0 {
                    return Err(unsupported("unsupported child metadata"));
                }
                dirs.push(child);
            }
            add_ref(&mut counts, &entry[64..84])?;
            let streams = u16_at(entry, 96);
            pos = end;
            for _ in 0..streams {
                let head = data
                    .get(
                        pos..pos
                            .checked_add(38)
                            .ok_or_else(|| invalid("stream offset overflow"))?,
                    )
                    .ok_or_else(|| invalid("truncated alternate stream"))?;
                let size = usize::try_from(u64_at(head, 0))
                    .map_err(|_| invalid("stream size overflow"))?;
                if size < 38 || pos.checked_add(size).is_none_or(|e| e > data.len()) {
                    return Err(invalid("invalid alternate stream size"));
                }
                let name_len = usize::from(u16_at(head, 36));
                if !name_len.is_multiple_of(2) || 38 + name_len > size {
                    return Err(invalid("invalid stream name size"));
                }
                add_ref(&mut counts, &head[16..36])?;
                pos += size;
            }
        }
    }
    Ok(counts)
}
fn add_ref(map: &mut HashMap<Hash, u32>, bytes: &[u8]) -> io::Result<()> {
    let hash: Hash = bytes.try_into().unwrap();
    if hash != [0; 20] {
        let n = map.entry(hash).or_default();
        *n = n
            .checked_add(1)
            .ok_or_else(|| invalid("reference count overflow"))?;
    }
    Ok(())
}
fn selected_xml(source: &str, index: u32, total: u64) -> io::Result<Vec<u8>> {
    let doc = roxmltree::Document::parse(source)
        .map_err(|e| invalid(format!("invalid image XML: {e}")))?;
    let root = doc.root_element();
    if root.tag_name().name() != "WIM" || root.tag_name().namespace().is_some() {
        return Err(unsupported("unsupported XML root"));
    }
    let mut selected = None;
    for child in root
        .children()
        .filter(|n| n.is_element() && n.tag_name().name() == "IMAGE")
    {
        let id = child
            .attribute("INDEX")
            .ok_or_else(|| invalid("image XML missing INDEX"))?
            .parse::<u32>()
            .map_err(|_| invalid("invalid image XML index"))?;
        if id == index && selected.replace(child).is_some() {
            return Err(invalid("duplicate image XML index"));
        }
    }
    let node = selected.ok_or_else(|| invalid("image index missing from XML"))?;
    let range = node.range();
    let attr = node
        .attributes()
        .find(|a| a.name() == "INDEX")
        .ok_or_else(|| invalid("missing image index"))?;
    let value = attr.range_value();
    if value.start < range.start || value.end > range.end {
        return Err(invalid("invalid XML attribute range"));
    }
    let image = format!(
        "{}1{}",
        &source[range.start..value.start],
        &source[value.end..range.end]
    );
    let xml = format!("<WIM><TOTALBYTES>{total}</TOTALBYTES>{image}</WIM>");
    let mut out = vec![0xff, 0xfe];
    for c in xml.encode_utf16() {
        out.extend_from_slice(&c.to_le_bytes());
    }
    Ok(out)
}
fn descriptor(header: &mut [u8], at: usize, size: u64, offset: u64) -> io::Result<()> {
    if size >= 1u64 << 56 {
        return Err(unsupported("resource too large"));
    }
    header[at..at + 8].copy_from_slice(&(size | (2u64 << 56)).to_le_bytes());
    header[at + 8..at + 16].copy_from_slice(&offset.to_le_bytes());
    header[at + 16..at + 24].copy_from_slice(&size.to_le_bytes());
    Ok(())
}
struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// Create an experimental single-image export without overwriting output.
/// Copies original payload bytes verbatim, including unused orphaned resources.
pub fn export_one(source: &Path, destination: &Path, index: u32) -> io::Result<()> {
    match fs::symlink_metadata(destination) {
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "destination already exists",
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let source_file = File::open(source)?;
    let mut wim = Wim::open(source_file)?;
    wim.check_structure()?;
    if !wim.header.integrity.is_absent() || wim.header.boot_index != 0 {
        return Err(unsupported(
            "bootable WIMs or WIMs with integrity tables are not supported for export",
        ));
    }
    let metadata = wim.image_metadata(index)?;
    let mut refs = references(&metadata)?;
    let xml = wim.xml_text()?;
    let table = wim.header.lookup;
    let mut records = Vec::new();
    let mut meta_count = 0u32;
    let mut found_meta = false;
    let mut used = HashSet::new();
    for i in 0..table.stored_size / 50 {
        wim.reader.seek(SeekFrom::Start(table.offset + i * 50))?;
        let mut row = [0u8; 50];
        wim.reader.read_exact(&mut row)?;
        let flags = row[7];
        if flags & 1 != 0 {
            continue;
        }
        let hash: Hash = row[30..50].try_into().unwrap();
        if flags & 2 != 0 {
            meta_count += 1;
            if meta_count == index {
                row[26..30].copy_from_slice(&1u32.to_le_bytes());
                records.extend_from_slice(&row);
                found_meta = true;
            }
        } else if let Some(count) = refs.remove(&hash) {
            if u32_at(&row, 26) < count {
                return Err(invalid("source reference count too small"));
            }
            row[26..30].copy_from_slice(&count.to_le_bytes());
            records.extend_from_slice(&row);
            used.insert(hash);
        } else if used.contains(&hash) {
            return Err(unsupported("duplicate lookup resource hash"));
        }
    }
    if !found_meta || !refs.is_empty() {
        return Err(invalid(format!(
            "{} referenced resources missing",
            refs.len()
        )));
    }
    let end = wim.file_size;
    let xml_offset = end
        .checked_add(records.len() as u64)
        .ok_or_else(|| invalid("output offset overflow"))?;
    let xml_bytes = selected_xml(&xml, index, xml_offset)?;
    wim.reader.seek(SeekFrom::Start(0))?;
    let mut header = [0u8; HEADER_SIZE];
    wim.reader.read_exact(&mut header)?;
    header[44..48].copy_from_slice(&1u32.to_le_bytes());
    descriptor(&mut header, 48, records.len() as u64, end)?;
    descriptor(&mut header, 72, xml_bytes.len() as u64, xml_offset)?;
    header[96..148].fill(0);
    let mut seed = Vec::new();
    seed.extend_from_slice(&wim.header.guid);
    seed.extend_from_slice(&index.to_le_bytes());
    seed.extend_from_slice(&std::process::id().to_le_bytes());
    seed.extend_from_slice(
        &SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .to_le_bytes(),
    );
    let hash = sha1::digest(&seed);
    header[24..40].copy_from_slice(&hash[..16]);
    header[31] = (header[31] & 0x0f) | 0x50;
    header[32] = (header[32] & 0x3f) | 0x80;
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = destination
        .file_name()
        .ok_or_else(|| invalid("output path lacks file name"))?;
    let mut tempname = name.to_os_string();
    tempname.push(format!(
        ".{}.{}.partial",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let guard = Temp(parent.join(tempname));
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&guard.0)?;
    wim.reader.seek(SeekFrom::Start(0))?;
    let copied = io::copy(&mut wim.reader, &mut file)?;
    if copied != end {
        return Err(invalid("source size changed during copy"));
    }
    // Compare every copied byte with the source before modifying the new header.
    wim.reader.seek(SeekFrom::Start(0))?;
    file.seek(SeekFrom::Start(0))?;
    let mut a = vec![0u8; 1024 * 1024];
    let mut b = vec![0u8; 1024 * 1024];
    let mut remaining = end;
    while remaining > 0 {
        let n = (remaining as usize).min(a.len());
        wim.reader.read_exact(&mut a[..n])?;
        file.read_exact(&mut b[..n])?;
        if a[..n] != b[..n] {
            return Err(invalid("source changed or copied bytes differ"));
        }
        remaining -= n as u64;
    }
    file.seek(SeekFrom::Start(end))?;
    file.write_all(&records)?;
    file.write_all(&xml_bytes)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&header)?;
    file.sync_all()?;
    let mut out = Wim::open(file.try_clone()?)?;
    out.check_structure()?;
    let actual = out.image_metadata(1)?;
    if actual != metadata {
        return Err(invalid("exported metadata differs from source"));
    }
    // A hard link publishes atomically without replacing an existing destination.
    fs::hard_link(&guard.0, destination)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn select_image_and_reindex() {
        let xml = "<WIM><TOTALBYTES>8</TOTALBYTES><IMAGE INDEX=\"1\"><NAME>One</NAME></IMAGE><IMAGE INDEX=\"6\"><NAME>Six</NAME></IMAGE></WIM>";
        let out = selected_xml(xml, 6, 55).unwrap();
        let units: Vec<_> = out[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|x| u16::from_le_bytes([x[0], x[1]]))
            .collect();
        let s = String::from_utf16(&units).unwrap();
        assert_eq!(
            s,
            "<WIM><TOTALBYTES>55</TOTALBYTES><IMAGE INDEX=\"1\"><NAME>Six</NAME></IMAGE></WIM>"
        );
        assert!(selected_xml(xml, 2, 0).is_err());
    }
    fn test_wim() -> Vec<u8> {
        let mut metadata = vec![0u8; 240];
        metadata[0..4].copy_from_slice(&8u32.to_le_bytes());
        metadata[8..16].copy_from_slice(&104u64.to_le_bytes());
        metadata[16..20].copy_from_slice(&16u32.to_le_bytes());
        metadata[24..32].copy_from_slice(&120u64.to_le_bytes());
        metadata[120..128].copy_from_slice(&112u64.to_le_bytes());
        metadata[184..204].copy_from_slice(&sha1::digest(b"abc"));
        metadata[220..222].copy_from_slice(&6u16.to_le_bytes());
        for (i, c) in "abc".encode_utf16().enumerate() {
            metadata[222 + i * 2..224 + i * 2].copy_from_slice(&c.to_le_bytes());
        }
        let mut header = [0u8; 208];
        header[..8].copy_from_slice(b"MSWIM\0\0\0");
        header[8..12].copy_from_slice(&208u32.to_le_bytes());
        header[12..16].copy_from_slice(&crate::CLASSIC_VERSION.to_le_bytes());
        header[40..42].copy_from_slice(&1u16.to_le_bytes());
        header[42..44].copy_from_slice(&1u16.to_le_bytes());
        header[44..48].copy_from_slice(&1u32.to_le_bytes());
        let table_offset = 208 + metadata.len() + 3;
        descriptor(&mut header, 48, 100, table_offset as u64).unwrap();
        let xml = selected_xml(
            "<WIM><IMAGE INDEX=\"1\"><NAME>Test</NAME></IMAGE></WIM>",
            1,
            (table_offset + 100) as u64,
        )
        .unwrap();
        descriptor(
            &mut header,
            72,
            xml.len() as u64,
            (table_offset + 100) as u64,
        )
        .unwrap();
        let mut table = [0u8; 100];
        descriptor(&mut table, 0, metadata.len() as u64, 208).unwrap();
        table[24..26].copy_from_slice(&1u16.to_le_bytes());
        table[26..30].copy_from_slice(&1u32.to_le_bytes());
        table[30..50].copy_from_slice(&sha1::digest(&metadata));
        descriptor(&mut table, 50, 3, (208 + metadata.len()) as u64).unwrap();
        table[57] = 0;
        table[74..76].copy_from_slice(&1u16.to_le_bytes());
        table[76..80].copy_from_slice(&1u32.to_le_bytes());
        table[80..100].copy_from_slice(&sha1::digest(b"abc"));
        let mut out = header.to_vec();
        out.extend(metadata);
        out.extend(b"abc");
        out.extend(table);
        out.extend(xml);
        out
    }
    #[test]
    fn export_roundtrip_and_no_overwrite() {
        let dir = std::env::temp_dir().join(format!("wim-export-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let source = dir.join("source.wim");
        let dest = dir.join("dest.wim");
        let original = test_wim();
        fs::write(&source, &original).unwrap();
        export_one(&source, &dest, 1).unwrap();
        assert_eq!(fs::read(&source).unwrap(), original);
        let mut wim = Wim::open(File::open(&dest).unwrap()).unwrap();
        wim.check_structure().unwrap();
        let meta = wim.image_metadata(1).unwrap();
        let entry = crate::find_image_path(&meta, "abc").unwrap();
        let resource = wim.find_hash(&entry.hash).unwrap();
        assert_eq!(wim.read_verified(&resource).unwrap(), b"abc");
        let written = fs::read(&dest).unwrap();
        assert!(export_one(&source, &dest, 1).is_err());
        assert_eq!(fs::read(&dest).unwrap(), written);
        let invalid_dest = dir.join("bad.wim");
        assert!(export_one(&source, &invalid_dest, 2).is_err());
        assert!(!invalid_dest.exists());
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 2);
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn rejects_cyclic_or_truncated_metadata() {
        let mut data = vec![0u8; 120];
        data[..4].copy_from_slice(&8u32.to_le_bytes());
        data[8..16].copy_from_slice(&104u64.to_le_bytes());
        data[16..20].copy_from_slice(&16u32.to_le_bytes());
        data[24..32].copy_from_slice(&8u64.to_le_bytes());
        assert!(references(&data).is_err());
        assert!(references(&data[..50]).is_err());
    }
}
