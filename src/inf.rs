//! Read-only INF inventory. This does not reproduce Windows driver selection.
use crate::{invalid, unsupported};
use std::{
    collections::BTreeSet,
    fs, io,
    path::{Path, PathBuf},
};
const MAX_INF_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug)]
pub struct InfInventory {
    pub path: PathBuf,
    pub class: Option<String>,
    pub driver_version: Option<String>,
    pub catalogs: Vec<String>,
    pub includes: Vec<String>,
    pub needs: Vec<String>,
    pub hardware_ids: Vec<String>,
    pub had_non_ascii_legacy_text: bool,
}

fn decode(bytes: &[u8]) -> io::Result<(String, bool)> {
    if bytes.starts_with(&[0xff, 0xfe]) || bytes.starts_with(&[0xfe, 0xff]) {
        let le = bytes[0] == 0xff;
        if !(bytes.len() - 2).is_multiple_of(2) {
            return Err(invalid("odd UTF-16 INF length"));
        }
        let units: Vec<u16> = bytes[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|v| {
                if le {
                    u16::from_le_bytes(*v)
                } else {
                    u16::from_be_bytes(*v)
                }
            })
            .collect();
        return Ok((
            String::from_utf16(&units).map_err(|_| invalid("invalid UTF-16 INF"))?,
            false,
        ));
    }
    if let Some(bytes) = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]) {
        return Ok((
            std::str::from_utf8(bytes)
                .map_err(|_| invalid("invalid UTF-8 INF"))?
                .to_owned(),
            false,
        ));
    }
    if bytes.iter().all(u8::is_ascii) {
        return Ok((String::from_utf8(bytes.to_vec()).unwrap(), false));
    }
    // Preserve ASCII syntax and flag undecoded legacy content rather than guess
    // a Windows ANSI code page. Non-ASCII identifiers are not matched.
    Ok((String::from_utf8_lossy(bytes).into_owned(), true))
}
fn uncomment(s: &str) -> &str {
    let mut quoted = false;
    for (i, c) in s.char_indices() {
        if c == '"' {
            quoted = !quoted;
        } else if c == ';' && !quoted {
            return &s[..i];
        }
    }
    s
}
fn split_values(s: &str) -> Vec<&str> {
    let mut quoted = false;
    let mut start = 0;
    let mut values = Vec::new();
    for (i, c) in s.char_indices() {
        if c == '"' {
            quoted = !quoted;
        } else if c == ',' && !quoted {
            values.push(s[start..i].trim().trim_matches('"'));
            start = i + 1;
        }
    }
    values.push(s[start..].trim().trim_matches('"'));
    values
}
fn candidate_id(s: &str) -> Option<String> {
    let s = s.trim().trim_matches('"');
    if !s.is_ascii() {
        return None;
    }
    let s = s.to_ascii_uppercase();
    let (bus, rest) = s.split_once('\\')?;
    if !matches!(
        bus,
        "PCI" | "USB" | "ACPI" | "HID" | "SCSI" | "SWD" | "ROOT"
    ) || rest.is_empty()
        || rest
            .bytes()
            .any(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'_' | b'&' | b'\\' | b'-' | b'.')))
    {
        return None;
    }
    Some(s)
}
/// Parse inventory fields and raw identifier candidates. No INF decorations,
/// model selection, substitutions, dependency resolution or signature verification.
pub fn inspect(path: &Path) -> io::Result<InfInventory> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(invalid("INF must be a regular file"));
    }
    if meta.len() > MAX_INF_BYTES {
        return Err(unsupported("INF exceeds 16 MiB"));
    }
    let (text, legacy) = decode(&fs::read(path)?)?;
    let mut section = String::new();
    let mut class = None;
    let mut version = None;
    let mut catalogs = BTreeSet::new();
    let mut includes = BTreeSet::new();
    let mut needs = BTreeSet::new();
    let mut ids = BTreeSet::new();
    let mut pending = String::new();
    for raw in text.lines() {
        let line = uncomment(raw).trim();
        let continuation = line.ends_with('\\');
        if continuation {
            pending.push_str(line.trim_end_matches('\\'));
            continue;
        }
        pending.push_str(line);
        let line = pending.trim();
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_ascii_lowercase();
        } else if let Some((key, value)) = line.split_once('=') {
            let key = key.trim().to_ascii_lowercase();
            let values = split_values(value);
            if section == "version" {
                if key == "class" {
                    class = Some(value.trim().trim_matches('"').to_owned());
                } else if key == "driverver" {
                    version = Some(value.trim().to_owned());
                } else if key == "catalogfile" || key.starts_with("catalogfile.") {
                    catalogs.insert(value.trim().trim_matches('"').to_owned());
                }
            }
            if key == "include" {
                includes.extend(
                    values
                        .iter()
                        .filter(|v| !v.is_empty())
                        .map(|v| v.to_string()),
                );
            }
            if key == "needs" {
                needs.extend(
                    values
                        .iter()
                        .filter(|v| !v.is_empty())
                        .map(|v| v.to_string()),
                );
            }
            // Candidate IDs are only read from CSV values, not comments or keys.
            for v in values {
                if let Some(id) = candidate_id(v) {
                    ids.insert(id);
                }
            }
        }
        pending.clear();
    }
    if !pending.is_empty() {
        return Err(invalid("unterminated INF continuation"));
    }
    Ok(InfInventory {
        path: path.to_owned(),
        class,
        driver_version: version,
        catalogs: catalogs.into_iter().collect(),
        includes: includes.into_iter().collect(),
        needs: needs.into_iter().collect(),
        hardware_ids: ids.into_iter().collect(),
        had_non_ascii_legacy_text: legacy,
    })
}
/// Search without following symlinks. Any unreadable/malformed INF fails the scan.
pub fn scan(root: &Path, id: Option<&str>) -> io::Result<(Vec<InfInventory>, usize)> {
    let filter = match id {
        Some(value) => Some(candidate_id(value).ok_or_else(|| invalid("invalid hardware ID"))?),
        None => None,
    };
    let meta = fs::symlink_metadata(root)?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(invalid("driver root must be a real directory"));
    }
    let mut dirs = vec![root.to_owned()];
    let mut found = Vec::new();
    let mut skipped = 0;
    while let Some(dir) = dirs.pop() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            let path = entry.path();
            if kind.is_symlink() {
                skipped += 1;
                continue;
            }
            if kind.is_dir() {
                dirs.push(path);
            } else if kind.is_file()
                && path
                    .extension()
                    .is_some_and(|x| x.eq_ignore_ascii_case("inf"))
            {
                let item = inspect(&path)?;
                if filter
                    .as_ref()
                    .is_none_or(|wanted| item.hardware_ids.contains(wanted))
                {
                    found.push(item);
                }
            }
        }
    }
    found.sort_by(|a, b| a.path.cmp(&b.path));
    Ok((found, skipped))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identifiers_are_exact_and_ascii_case_insensitive() {
        assert_eq!(
            candidate_id("pci\\ven_8086&dev_1234"),
            Some("PCI\\VEN_8086&DEV_1234".into())
        );
        assert!(candidate_id("PCI\\VEN_8086 &DEV_1234").is_none());
        assert!(candidate_id("not-a-device").is_none());
    }
    #[test]
    fn utf16_and_comments() {
        let text = "[Version]\r\nClass=Net\r\nCatalogFile.NTamd64=foo.cat\r\n[Models]\r\n%thing%=Install,PCI\\VEN_8086&DEV_1234 ; USB\\FAKE\r\nInclude=machine.inf,pci.inf\r\nNeeds=Install.HW\r\n";
        let mut data = vec![0xff, 0xfe];
        for c in text.encode_utf16() {
            data.extend_from_slice(&c.to_le_bytes());
        }
        let dir = std::env::temp_dir().join(format!("inf-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("TEST.INF");
        fs::write(&p, data).unwrap();
        let i = inspect(&p).unwrap();
        assert_eq!(i.class.as_deref(), Some("Net"));
        assert_eq!(i.catalogs, ["foo.cat"]);
        assert_eq!(i.includes, ["machine.inf", "pci.inf"]);
        assert_eq!(i.hardware_ids, ["PCI\\VEN_8086&DEV_1234"]);
        assert_eq!(
            scan(&dir, Some("pci\\ven_8086&dev_1234")).unwrap().0.len(),
            1
        );
        assert!(
            scan(&dir, Some("PCI\\VEN_8086&DEV_12"))
                .unwrap()
                .0
                .is_empty()
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
