//! Read-only INF inventory. This does not reproduce Windows driver selection.
use crate::{invalid, unsupported};
use std::{
    collections::{BTreeMap, BTreeSet},
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

/// A model entry explicitly referenced by a Manufacturer directive. This is a
/// candidate only; Windows chooses among eligible decorations and driver ranks.
#[derive(Debug)]
pub struct ModelMatch {
    pub model_section: String,
    pub install_section: String,
    pub description: String,
    pub matching_id: String,
    pub compatible_id: bool,
    pub min_build: Option<u32>,
    pub related_sections: Vec<String>,
}
#[derive(Debug)]
pub struct ModelReport {
    pub matches: Vec<ModelMatch>,
    pub warnings: Vec<String>,
}

type Sections = BTreeMap<String, Vec<(String, String)>>;
fn parse_sections(text: &str) -> io::Result<Sections> {
    let mut sections = Sections::new();
    let mut name = String::new();
    let mut pending = String::new();
    for raw in text.lines() {
        let line = uncomment(raw).trim();
        let continuation = line.ends_with('\\') && !line.ends_with('"');
        if continuation {
            pending.push_str(line.trim_end_matches('\\'));
            continue;
        }
        pending.push_str(line);
        let line = pending.trim();
        if line.starts_with('[') && line.ends_with(']') {
            name = line[1..line.len() - 1].trim().to_ascii_lowercase();
            sections.entry(name.clone()).or_default();
        } else if let Some((k, v)) = line.split_once('=')
            && !name.is_empty()
        {
            sections
                .entry(name.clone())
                .or_default()
                .push((k.trim().to_owned(), v.trim().to_owned()));
        } else if !line.is_empty() && !name.is_empty() {
            sections
                .entry(name.clone())
                .or_default()
                .push((line.to_owned(), String::new()));
        }
        pending.clear();
    }
    if !pending.is_empty() {
        return Err(invalid("unterminated INF continuation"));
    }
    Ok(sections)
}
fn expand(value: &str, strings: &BTreeMap<String, String>) -> io::Result<String> {
    let mut result = value.trim().trim_matches('"').to_owned();
    for _ in 0..8 {
        let Some(start) = result.find('%') else {
            return Ok(result);
        };
        let tail = &result[start + 1..];
        let Some(end) = tail.find('%') else {
            return Err(unsupported("unclosed INF string token"));
        };
        let key = tail[..end].to_ascii_lowercase();
        if key.is_empty() {
            return Err(unsupported("escaped percent is unsupported"));
        }
        let value = strings
            .get(&key)
            .ok_or_else(|| unsupported(format!("unresolved INF string: {key}")))?;
        result.replace_range(start..start + end + 2, value);
        if result.len() > 4096 {
            return Err(unsupported("expanded INF string too long"));
        }
    }
    if result.contains('%') {
        return Err(unsupported("recursive or excessive INF string expansion"));
    }
    Ok(result)
}
// Narrow documented TargetOSVersion subset: NTamd64 and NTamd64.major.minor
// with optional build and empty product/suite fields. Other decorations are
// surfaced as unresolved instead of guessed.
fn decoration(value: &str, build: u32) -> io::Result<Option<Option<u32>>> {
    let d = value.trim().to_ascii_lowercase();
    if d == "ntamd64" {
        return Ok(Some(None));
    }
    if d.starts_with("ntx86") || d.starts_with("ntarm") {
        return Ok(None);
    }
    let Some(rest) = d.strip_prefix("ntamd64.") else {
        return Err(unsupported(format!(
            "unsupported target decoration: {value}"
        )));
    };
    let p: Vec<_> = rest.split('.').collect();
    if p.len() < 2 || p.len() > 5 || p[0].is_empty() || p[1].is_empty() {
        return Err(unsupported(format!(
            "unsupported target decoration: {value}"
        )));
    }
    let major: u32 = p[0]
        .parse()
        .map_err(|_| unsupported("invalid target major version"))?;
    let minor: u32 = p[1]
        .parse()
        .map_err(|_| unsupported("invalid target minor version"))?;
    if p.get(2).is_some_and(|s| !s.is_empty()) || p.get(3).is_some_and(|s| !s.is_empty()) {
        return Err(unsupported(
            "product and suite target decorations are unsupported",
        ));
    }
    let min_build = match p.get(4) {
        Some(v) if !v.is_empty() => Some(
            v.parse::<u32>()
                .map_err(|_| unsupported("invalid target build"))?,
        ),
        _ => None,
    };
    if (major, minor) > (10, 0) || min_build.is_some_and(|b| b > build) {
        return Ok(None);
    }
    Ok(Some(min_build))
}
/// Find exact ID occurrences in declared x64 model sections relevant to Windows
/// 10.0 at the given build. Does not rank, select an installation section, or
/// verify package dependencies or signatures.
pub fn model_candidates(path: &Path, id: &str, build: u32) -> io::Result<ModelReport> {
    let id = candidate_id(id).ok_or_else(|| invalid("invalid hardware ID"))?;
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(invalid("INF must be a regular file"));
    }
    if meta.len() > MAX_INF_BYTES {
        return Err(unsupported("INF exceeds 16 MiB"));
    }
    let (text, legacy) = decode(&fs::read(path)?)?;
    let sections = parse_sections(&text)?;
    let mut strings = BTreeMap::new();
    if let Some(rows) = sections.get("strings") {
        for (k, v) in rows {
            let key = k.to_ascii_lowercase();
            if strings
                .insert(key, v.trim().trim_matches('"').to_string())
                .is_some()
            {
                return Err(invalid("duplicate INF string key"));
            }
        }
    }
    let mut warnings = Vec::new();
    if legacy {
        warnings.push("non-ASCII legacy text decoded lossily".into());
    }
    if sections.keys().any(|k| k.starts_with("strings.")) {
        warnings.push("localized Strings sections are not evaluated".into());
    }
    let manufacturers = sections
        .get("manufacturer")
        .ok_or_else(|| unsupported("INF has no Manufacturer section"))?;
    let mut matches = Vec::new();
    for (_, value) in manufacturers {
        let fields = split_values(value);
        if fields.len() < 2 {
            warnings.push("undecorated manufacturer models not evaluated".into());
            continue;
        }
        let base = match expand(fields[0], &strings) {
            Ok(s) => s,
            Err(e) => {
                warnings.push(e.to_string());
                continue;
            }
        };
        for dec in &fields[1..] {
            let dec = match expand(dec, &strings) {
                Ok(s) => s,
                Err(e) => {
                    warnings.push(e.to_string());
                    continue;
                }
            };
            let min = match decoration(&dec, build) {
                Ok(Some(x)) => x,
                Ok(None) => continue,
                Err(e) => {
                    warnings.push(e.to_string());
                    continue;
                }
            };
            let model = format!("{}.{}", base, dec).to_ascii_lowercase();
            let Some(rows) = sections.get(&model) else {
                warnings.push(format!("declared model section missing: {model}"));
                continue;
            };
            for (desc, value) in rows {
                let values = split_values(value);
                if values.len() < 2 {
                    continue;
                }
                let install = match expand(values[0], &strings) {
                    Ok(s) => s,
                    Err(e) => {
                        warnings.push(e.to_string());
                        continue;
                    }
                };
                for (idx, raw_id) in values[1..].iter().enumerate() {
                    let expanded = match expand(raw_id, &strings) {
                        Ok(s) => s,
                        Err(e) => {
                            warnings.push(e.to_string());
                            continue;
                        }
                    };
                    if candidate_id(&expanded).as_deref() != Some(id.as_str()) {
                        continue;
                    }
                    let description = match expand(desc, &strings) {
                        Ok(s) => s,
                        Err(e) => {
                            warnings.push(e.to_string());
                            desc.clone()
                        }
                    };
                    let prefix = install.to_ascii_lowercase();
                    let related = sections
                        .keys()
                        .filter(|k| *k == &prefix || k.starts_with(&(prefix.clone() + ".")))
                        .cloned()
                        .collect();
                    matches.push(ModelMatch {
                        model_section: model.clone(),
                        install_section: install.clone(),
                        description,
                        matching_id: id.clone(),
                        compatible_id: idx > 0,
                        min_build: min,
                        related_sections: related,
                    });
                }
            }
        }
    }
    warnings.sort();
    warnings.dedup();
    Ok(ModelReport { matches, warnings })
}

/// An observed package file. Presence is not a signature or integrity check.
#[derive(Debug)]
pub struct PackageFile {
    pub name: String,
    pub path: Option<PathBuf>,
    pub issue: Option<String>,
}
#[derive(Debug)]
pub struct PackageAudit {
    pub model: ModelMatch,
    pub files: Vec<PackageFile>,
    pub includes: Vec<String>,
    pub needs: Vec<String>,
    pub warnings: Vec<String>,
}

// Source media paths are interpreted relative to the INF directory. Do not
// follow links, accept parent traversal, drive paths, or ambiguous case matches.
pub(crate) fn find_relative(root: &Path, parts: &[String]) -> io::Result<Option<PathBuf>> {
    let mut at = root.to_owned();
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() || part == "." || part == ".." || part.contains(['/', '\\', ':']) {
            return Err(invalid("unsafe INF source path"));
        }
        let mut hit = None;
        for item in fs::read_dir(&at)? {
            let item = item?;
            let n = item.file_name();
            if n.to_str().is_some_and(|s| s.eq_ignore_ascii_case(part)) {
                if hit.is_some() {
                    return Err(invalid("ambiguous case-insensitive package path"));
                }
                if item.file_type()?.is_symlink() {
                    return Err(unsupported("package source path includes a symlink"));
                }
                hit = Some(item.path());
            }
        }
        let Some(next) = hit else { return Ok(None) };
        let ty = fs::metadata(&next)?;
        if i + 1 == parts.len() {
            if !ty.is_file() {
                return Err(invalid("package source is not a file"));
            }
        } else if !ty.is_dir() {
            return Err(invalid("package path component is not a directory"));
        }
        at = next;
    }
    Ok(Some(at))
}
fn path_parts(s: &str) -> io::Result<Vec<String>> {
    let mut parts = Vec::new();
    for p in s.split(['\\', '/']) {
        if p.is_empty() {
            continue;
        }
        if p == "." || p == ".." || p.contains(':') {
            return Err(invalid("unsafe INF source directory"));
        }
        parts.push(p.to_owned());
    }
    Ok(parts)
}
/// Audit declared x64 source files and candidate CopyFiles directives for a
/// single model candidate. Unsupported references are warnings, not success.
pub fn audit_package(path: &Path, id: &str, build: u32) -> io::Result<PackageAudit> {
    let report = model_candidates(path, id, build)?;
    if report.matches.len() != 1 {
        return Err(unsupported(format!(
            "audit requires exactly one model candidate; found {}",
            report.matches.len()
        )));
    }
    if !report.warnings.is_empty() {
        return Err(unsupported(format!(
            "unresolved model syntax: {}",
            report.warnings.join("; ")
        )));
    }
    let model = report.matches.into_iter().next().unwrap();
    let (text, legacy) = decode(&fs::read(path)?)?;
    let sections = parse_sections(&text)?;
    let mut warnings = Vec::new();
    if legacy {
        warnings.push("legacy text decoded lossily".into());
    }
    let mut strings = BTreeMap::new();
    if let Some(rows) = sections.get("strings") {
        for (k, v) in rows {
            strings.insert(
                k.to_ascii_lowercase(),
                v.trim().trim_matches('"').to_owned(),
            );
        }
    }
    let root = path
        .parent()
        .ok_or_else(|| invalid("INF has no parent directory"))?;
    let mut disks: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for sec in ["sourcedisksnames", "sourcedisksnames.amd64"] {
        if let Some(rows) = sections.get(sec) {
            for (id, val) in rows {
                let fields = split_values(val);
                let tag = fields.get(1).copied().unwrap_or("");
                if !tag.is_empty() {
                    warnings.push(format!("source disk {id} has tag or cabinet {tag}; cabinet fallback is not evaluated"));
                }
                let dir = fields.get(3).copied().unwrap_or("");
                let dir = if dir.contains('%') {
                    match expand(dir, &strings) {
                        Ok(v) => v,
                        Err(e) => {
                            warnings.push(e.to_string());
                            continue;
                        }
                    }
                } else {
                    dir.to_owned()
                };
                disks.insert(id.trim().to_ascii_lowercase(), path_parts(&dir)?);
            }
        }
    }
    let mut sources: BTreeMap<String, (String, Vec<String>)> = BTreeMap::new();
    for sec in ["sourcedisksfiles", "sourcedisksfiles.amd64"] {
        if let Some(rows) = sections.get(sec) {
            for (filename, val) in rows {
                if filename.contains(['%', '/', '\\', ':']) || filename == "." || filename == ".." {
                    warnings.push(format!("unsupported source filename: {filename}"));
                    continue;
                }
                let fields = split_values(val);
                let Some(disk) = fields.first() else { continue };
                let disk = disk.to_ascii_lowercase();
                let Some(mut dir) = disks.get(&disk).cloned() else {
                    warnings.push(format!("source disk not defined: {disk} for {filename}"));
                    continue;
                };
                let sub = fields.get(1).copied().unwrap_or("");
                let sub = if sub.contains('%') {
                    match expand(sub, &strings) {
                        Ok(v) => v,
                        Err(e) => {
                            warnings.push(e.to_string());
                            continue;
                        }
                    }
                } else {
                    sub.to_owned()
                };
                dir.extend(path_parts(&sub)?);
                dir.push(filename.to_owned());
                sources.insert(filename.to_ascii_lowercase(), (filename.to_owned(), dir));
            }
        }
    }
    if sources.is_empty() {
        warnings.push("no x64 or generic SourceDisksFiles entries found".into());
    }
    let mut includes = BTreeSet::new();
    let mut needs = BTreeSet::new();
    let mut copies = BTreeSet::new();
    for section in &model.related_sections {
        if let Some(rows) = sections.get(section) {
            for (k, v) in rows {
                if k.eq_ignore_ascii_case("include") {
                    includes.extend(split_values(v).iter().map(|x| x.to_string()));
                }
                if k.eq_ignore_ascii_case("needs") {
                    needs.extend(split_values(v).iter().map(|x| x.to_string()));
                }
                if k.eq_ignore_ascii_case("copyinf") {
                    warnings.push(format!("CopyINF not resolved in {section}: {v}"));
                }
                if !k.eq_ignore_ascii_case("copyfiles") {
                    continue;
                }
                for item in split_values(v) {
                    let item = if item.contains('%') {
                        match expand(item, &strings) {
                            Ok(x) => x,
                            Err(e) => {
                                warnings.push(e.to_string());
                                continue;
                            }
                        }
                    } else {
                        item.to_owned()
                    };
                    if let Some(file) = item.strip_prefix('@') {
                        copies.insert(file.to_ascii_lowercase());
                        continue;
                    }
                    let name = item.to_ascii_lowercase();
                    if let Some(files) = sections.get(&name) {
                        for (line, val) in files {
                            let text = if val.is_empty() {
                                line.clone()
                            } else {
                                format!("{line}={val}")
                            };
                            let fields = split_values(&text);
                            let filename = fields
                                .get(1)
                                .filter(|s| !s.is_empty())
                                .or_else(|| fields.first())
                                .copied()
                                .unwrap_or("");
                            if filename.contains('%') {
                                warnings.push(format!("unresolved CopyFiles entry: {filename}"));
                            } else if !filename.is_empty() {
                                copies.insert(filename.to_ascii_lowercase());
                            }
                        }
                    } else {
                        warnings.push(format!("missing or external CopyFiles section: {name}"));
                    }
                }
            }
        }
    }
    for c in &copies {
        if !sources.contains_key(c) {
            warnings.push(format!(
                "CopyFiles source not declared in x64 SourceDisksFiles: {c}"
            ));
        }
    }
    let mut files = Vec::new();
    for (_, (name, parts)) in sources {
        let resolved = find_relative(root, &parts)?;
        let issue = if resolved.is_none() {
            Some("source file not found at declared path".into())
        } else {
            None
        };
        files.push(PackageFile {
            name,
            path: resolved,
            issue,
        });
    }
    // Catalogue selection and trust require Windows-specific rules; report every
    // declared filename, not an asserted selected/trusted certificate.
    let inv = inspect(path)?;
    for cat in inv.catalogs {
        if cat.contains('%') {
            warnings.push(format!("catalog token unresolved: {cat}"));
            continue;
        }
        let resolved = find_relative(root, std::slice::from_ref(&cat))?;
        let issue = if resolved.is_none() {
            Some("catalog not found beside INF".into())
        } else {
            None
        };
        files.push(PackageFile {
            name: cat,
            path: resolved,
            issue,
        });
    }
    if files
        .iter()
        .all(|f| !f.name.to_ascii_lowercase().ends_with(".cat"))
    {
        warnings.push("no catalog file declared".into());
    }
    if !includes.is_empty() || !needs.is_empty() {
        warnings
            .push("Include/Needs dependencies require additional Windows INF resolution".into());
    }
    warnings.push("all related install sections are inspected as candidates; target section selection is not implemented".into());
    warnings.push("catalog signatures, CopyINF, external packages and complete dependency closure are not verified".into());
    warnings.sort();
    warnings.dedup();
    Ok(PackageAudit {
        model,
        files,
        includes: includes.into_iter().collect(),
        needs: needs.into_iter().collect(),
        warnings,
    })
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
    #[test]
    fn model_candidates_respect_build_architecture_and_substitution() {
        let text = "[Manufacturer]\n%vendor%=Models,NTamd64.10.0...19041,NTamd64.10.0...30000,NTx86\n[Models.NTamd64.10.0...19041]\n%name%=Install,%id%\n[Models.NTamd64.10.0...30000]\n%name%=Future,%id%\n[Models.NTx86]\n%name%=X86,%id%\n[Install.NTamd64]\nCopyFiles=x\n[Strings]\nvendor=Vendor\nname=Device\nid=PCI\\VEN_8086&DEV_7D0B\n";
        let dir = std::env::temp_dir().join(format!("inf-model-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("x.inf");
        fs::write(&p, text).unwrap();
        let r = model_candidates(&p, "PCI\\VEN_8086&DEV_7D0B", 26300).unwrap();
        assert_eq!(r.matches.len(), 1);
        assert_eq!(r.matches[0].description, "Device");
        assert_eq!(r.matches[0].install_section, "Install");
        assert_eq!(r.matches[0].min_build, Some(19041));
        assert_eq!(r.matches[0].related_sections, ["install.ntamd64"]);
        assert!(
            model_candidates(&p, "PCI\\VEN_8086&DEV_7D0B", 18000)
                .unwrap()
                .matches
                .is_empty()
        );
        assert!(
            model_candidates(&p, "PCI\\VEN_8086&DEV_7D0C", 26300)
                .unwrap()
                .matches
                .is_empty()
        );
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn unsupported_decorations_are_not_guessed() {
        assert!(decoration("NTamd64.10.0.1.0x80.19041", 26300).is_err());
        assert!(decoration("NTamd64.10.0...30000", 26300).unwrap().is_none());
        assert!(decoration("NTx86", 26300).unwrap().is_none());
        assert!(decoration("NTamd64.10.0...19041", 26300).unwrap().is_some());
    }
    #[test]
    fn reports_unsupported_decorations_and_ignores_unreferenced_sections() {
        let dir = std::env::temp_dir().join(format!("inf-warning-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("x.inf");
        let s = "[Manufacturer]\n%v%=Models,NTamd64.10.0.1.0x80.19041,NTamd64\n[Models.NTamd64]\n%a%=Install,PCI\\VEN_1234&DEV_0001\n[Unreferenced.NTamd64]\n%a%=Other,PCI\\VEN_9999&DEV_0001\n[Strings]\nv=Vendor\na=Device\n";
        fs::write(&p, s).unwrap();
        let report = model_candidates(&p, "PCI\\VEN_1234&DEV_0001", 26300).unwrap();
        assert_eq!(report.matches.len(), 1);
        assert!(!report.warnings.is_empty());
        assert!(
            model_candidates(&p, "PCI\\VEN_9999&DEV_0001", 26300)
                .unwrap()
                .matches
                .is_empty()
        );
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn audit_finds_declared_files_and_missing_copy_sources() {
        let dir = std::env::temp_dir().join(format!("inf-audit-test-{}", std::process::id()));
        fs::create_dir_all(dir.join("SubDir")).unwrap();
        let p = dir.join("driver.inf");
        let s = "[Version]\nCatalogFile=DRIVER.CAT\n[Manufacturer]\n%v%=Models,NTamd64.10.0...19041\n[Models.NTamd64.10.0...19041]\n%d%=Install,PCI\\VEN_1234&DEV_5678\n[Install.NTamd64]\nCopyFiles=@Direct.sys,CopySection\nInclude=machine.inf\nNeeds=NO_DRV\n[CopySection]\nrenamed.sys,actual.sys\nmissing.sys\n[SourceDisksNames]\n1=%disk%,,,SubDir\n[SourceDisksFiles.amd64]\nDirect.sys=1\nactual.sys=1\n[Strings]\nv=Vendor\nd=Device\ndisk=Disk\n";
        fs::write(&p, s).unwrap();
        for f in ["direct.sys", "ACTUAL.SYS"] {
            fs::write(dir.join("SubDir").join(f), b"test").unwrap();
        }
        fs::write(dir.join("driver.cat"), b"test").unwrap();
        let audit = audit_package(&p, "PCI\\VEN_1234&DEV_5678", 26300).unwrap();
        assert_eq!(audit.files.len(), 3);
        assert!(audit.files.iter().all(|f| f.path.is_some()));
        assert_eq!(audit.includes, ["machine.inf"]);
        assert_eq!(audit.needs, ["NO_DRV"]);
        assert!(audit.warnings.iter().any(|w| w.contains("missing.sys")));
        fs::remove_file(dir.join("SubDir").join("direct.sys")).unwrap();
        let audit = audit_package(&p, "PCI\\VEN_1234&DEV_5678", 26300).unwrap();
        assert!(
            audit
                .files
                .iter()
                .any(|f| f.name == "Direct.sys" && f.path.is_none())
        );
        assert!(audit_package(&p, "PCI\\VEN_0000&DEV_5678", 26300).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn audit_rejects_path_traversal() {
        assert!(path_parts("../escape").is_err());
        assert!(path_parts("C:\\Windows").is_err());
        assert_eq!(path_parts("\\drivers\\x64").unwrap(), ["drivers", "x64"]);
        let dir = std::env::temp_dir().join(format!("inf-audit-path-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        assert!(find_relative(&dir, &["..".into(), "escape.sys".into()]).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn audit_rejects_symlink_sources() {
        use std::os::unix::fs::symlink;
        let dir = std::env::temp_dir().join(format!("inf-symlink-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("actual.sys"), b"data").unwrap();
        symlink(dir.join("actual.sys"), dir.join("linked.sys")).unwrap();
        assert!(find_relative(&dir, &["linked.sys".into()]).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
}
