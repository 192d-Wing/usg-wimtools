//! Read-only driver-package snapshots. A hash manifest is not a trust signature.
use crate::{
    inf::{audit_package, find_relative},
    invalid, unsupported,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileRecord {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: u32,
    pub inf: String,
    pub hardware_id: String,
    pub windows_build: u32,
    pub model_section: String,
    pub install_section: String,
    pub files: Vec<FileRecord>,
    pub warnings: Vec<String>,
    pub trust_status: String,
}
pub(crate) fn safe_parts(path: &str) -> io::Result<Vec<String>> {
    if path.is_empty() || path.contains('\\') || path.contains(':') {
        return Err(invalid("invalid manifest path"));
    }
    let mut parts = Vec::new();
    for c in Path::new(path).components() {
        match c {
            Component::Normal(p) => {
                let p = p
                    .to_str()
                    .ok_or_else(|| invalid("non-UTF-8 manifest path"))?;
                if p.is_empty() || p == "." || p == ".." {
                    return Err(invalid("invalid manifest path component"));
                }
                parts.push(p.to_owned());
            }
            _ => {
                return Err(invalid(
                    "manifest paths must be relative and contain no parent components",
                ));
            }
        }
    }
    if parts.is_empty() {
        return Err(invalid("empty manifest path"));
    }
    Ok(parts)
}
fn relative(root: &Path, path: &Path) -> io::Result<String> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| invalid("source file outside package root"))?;
    let mut parts = Vec::new();
    for c in relative.components() {
        match c {
            Component::Normal(p) => parts.push(
                p.to_str()
                    .ok_or_else(|| unsupported("non-UTF-8 source path"))?,
            ),
            _ => return Err(invalid("unsafe source path")),
        }
    }
    let s = parts.join("/");
    safe_parts(&s)?;
    Ok(s)
}
fn file_record(root: &Path, path: &str) -> io::Result<FileRecord> {
    let parts = safe_parts(path)?;
    let file_path = find_relative(root, &parts)?
        .ok_or_else(|| invalid(format!("missing package file: {path}")))?;
    let mut file = File::open(file_path)?;
    let before = file.metadata()?;
    if !before.is_file() {
        return Err(invalid("package entry is not a regular file"));
    }
    let mut hash = Sha256::new();
    let mut size = 0u64;
    let mut buf = [0u8; 128 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        size = size
            .checked_add(n as u64)
            .ok_or_else(|| invalid("file length overflow"))?;
        hash.update(&buf[..n]);
    }
    let after = file.metadata()?;
    if before.len() != size
        || after.len() != size
        || before.modified().ok() != after.modified().ok()
    {
        return Err(invalid(format!("file changed during hashing: {path}")));
    }
    let digest = hash.finalize();
    let sha256 = digest.iter().map(|b| format!("{b:02x}")).collect();
    Ok(FileRecord {
        path: path.to_owned(),
        size,
        sha256,
    })
}
/// Audit and snapshot currently available file bytes. Missing files fail closed;
/// audit limitations remain explicitly recorded in the manifest.
pub fn create(inf: &Path, hardware_id: &str, build: u32) -> io::Result<Manifest> {
    let root = inf
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let root_meta = fs::symlink_metadata(root)?;
    if !root_meta.is_dir() || root_meta.file_type().is_symlink() {
        return Err(invalid("package root must be a real directory"));
    }
    let inf_name = inf
        .file_name()
        .and_then(|x| x.to_str())
        .ok_or_else(|| invalid("invalid INF filename"))?
        .to_string();
    safe_parts(&inf_name)?;
    let audit = audit_package(inf, hardware_id, build)?;
    let mut paths = BTreeSet::new();
    paths.insert(inf_name.clone());
    for file in audit.files {
        let p = file.path.ok_or_else(|| {
            invalid(format!(
                "cannot snapshot missing package file: {}",
                file.name
            ))
        })?;
        paths.insert(relative(root, &p)?);
    }
    let files = paths
        .into_iter()
        .map(|p| file_record(root, &p))
        .collect::<io::Result<Vec<_>>>()?;
    Ok(Manifest {
        schema: 1,
        inf: inf_name,
        hardware_id: hardware_id.to_ascii_uppercase(),
        windows_build: build,
        model_section: audit.model.model_section,
        install_section: audit.model.install_section,
        files,
        warnings: audit.warnings,
        trust_status: "NOT_VERIFIED".into(),
    })
}
/// Compare the snapshot and re-audit the current INF, including its file set.
/// The manifest itself is not authenticated; a matching result is not trust.
pub fn verify(root: &Path, manifest: &Manifest) -> io::Result<usize> {
    if manifest.schema != 1 || manifest.trust_status != "NOT_VERIFIED" {
        return Err(unsupported("unsupported manifest schema or trust state"));
    }
    if manifest.files.is_empty() || manifest.files.len() > 10_000 {
        return Err(invalid("invalid manifest file count"));
    }
    let mut seen = BTreeSet::new();
    for record in &manifest.files {
        safe_parts(&record.path)?;
        if !seen.insert(record.path.to_ascii_lowercase()) {
            return Err(invalid("duplicate manifest path"));
        }
        if record.sha256.len() != 64
            || !record
                .sha256
                .bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err(invalid("invalid SHA-256 string"));
        }
        let actual = file_record(root, &record.path)?;
        if &actual != record {
            return Err(invalid(format!(
                "package file differs from snapshot: {}",
                record.path
            )));
        }
    }
    let inf_path = find_relative(root, &safe_parts(&manifest.inf)?)?
        .ok_or_else(|| invalid("manifest INF missing"))?;
    let current = create(&inf_path, &manifest.hardware_id, manifest.windows_build)?;
    if &current != manifest {
        return Err(invalid("current package audit differs from manifest"));
    }
    Ok(manifest.files.len())
}
pub fn load(path: &Path) -> io::Result<Manifest> {
    let mut data = Vec::new();
    File::open(path)?
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut data)?;
    if data.len() > 4 * 1024 * 1024 {
        return Err(unsupported("manifest exceeds 4 MiB"));
    }
    serde_json::from_slice(&data).map_err(|e| invalid(format!("invalid manifest: {e}")))
}
/// Write a new manifest without replacing a destination, through a temporary.
pub fn save_new(path: &Path, manifest: &Manifest) -> io::Result<()> {
    struct Temp(PathBuf);
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }
    let mut bytes = serde_json::to_vec_pretty(manifest).map_err(|e| invalid(e.to_string()))?;
    bytes.push(b'\n');
    if bytes.len() > 4 * 1024 * 1024 {
        return Err(unsupported("manifest exceeds 4 MiB"));
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut name = path
        .file_name()
        .ok_or_else(|| invalid("missing output filename"))?
        .to_os_string();
    name.push(format!(
        ".{}.{}.partial",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let guard = Temp(parent.join(name));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&guard.0)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    if fs::read(&guard.0)? != bytes {
        return Err(invalid("manifest write verification failed"));
    }
    fs::hard_link(&guard.0, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn setup(name: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("manifest-{name}-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let inf = dir.join("driver.inf");
        fs::write(&inf,"[Version]\nCatalogFile=driver.cat\n[Manufacturer]\n%v%=Models,NTamd64.10.0...19041\n[Models.NTamd64.10.0...19041]\n%d%=Install,PCI\\VEN_1234&DEV_5678\n[Install.NTamd64]\nCopyFiles=@driver.sys\n[SourceDisksNames]\n1=Disk,,,\n[SourceDisksFiles.amd64]\ndriver.sys=1\n[Strings]\nv=Vendor\nd=Device\n").unwrap();
        fs::write(dir.join("driver.sys"), b"abc").unwrap();
        fs::write(dir.join("driver.cat"), b"catalog").unwrap();
        (dir, inf)
    }
    #[test]
    fn snapshot_detects_modified_and_missing_files() {
        let (dir, inf) = setup("modified");
        let snapshot = create(&inf, "PCI\\VEN_1234&DEV_5678", 26300).unwrap();
        assert_eq!(snapshot.files.len(), 3);
        assert_eq!(verify(&dir, &snapshot).unwrap(), 3);
        let driver = snapshot
            .files
            .iter()
            .find(|f| f.path == "driver.sys")
            .unwrap();
        assert_eq!(
            driver.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        fs::write(dir.join("driver.sys"), b"abd").unwrap();
        assert!(verify(&dir, &snapshot).is_err());
        fs::remove_file(dir.join("driver.sys")).unwrap();
        assert!(verify(&dir, &snapshot).is_err());
        assert!(create(&inf, "PCI\\VEN_1234&DEV_5678", 26300).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn rejects_untrusted_paths_and_modified_file_sets() {
        let (dir, inf) = setup("paths");
        let snapshot = create(&inf, "PCI\\VEN_1234&DEV_5678", 26300).unwrap();
        let text = serde_json::to_string(&snapshot).unwrap();
        let mut altered: Manifest = serde_json::from_str(&text).unwrap();
        altered.files[0].path = "../other".into();
        assert!(verify(&dir, &altered).is_err());
        let mut omitted: Manifest = serde_json::from_str(&text).unwrap();
        omitted.files.pop();
        assert!(verify(&dir, &omitted).is_err());
        let mut duplicate: Manifest = serde_json::from_str(&text).unwrap();
        duplicate.files.push(duplicate.files[0].clone());
        assert!(verify(&dir, &duplicate).is_err());
        assert!(safe_parts("C:/bad").is_err());
        assert!(safe_parts("/absolute").is_err());
        assert!(safe_parts("a/../bad").is_err());
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn save_load_is_non_overwriting() {
        let (dir, inf) = setup("save");
        let snapshot = create(&inf, "PCI\\VEN_1234&DEV_5678", 26300).unwrap();
        let path = dir.join("manifest.json");
        save_new(&path, &snapshot).unwrap();
        assert_eq!(load(&path).unwrap(), snapshot);
        assert!(save_new(&path, &snapshot).is_err());
        assert_eq!(load(&path).unwrap(), snapshot);
        assert!(!fs::read_dir(&dir).unwrap().any(|e| {
            e.unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".partial")
        }));
        fs::remove_dir_all(dir).unwrap();
    }
}
