//! Read-only image observations for planning future offline servicing.
use crate::{Wim, directory_entries, find_image_path, invalid};
use std::io::{self, Read, Seek};

#[derive(Debug)]
pub struct ImageObservation {
    pub path: &'static str,
    pub detail: String,
}
#[derive(Debug)]
pub struct ServicingInspection {
    pub observations: Vec<ImageObservation>,
    pub matching_repository_directories: Vec<String>,
}

/// Inspect selected conventional Windows paths. This is not a staging preflight
/// and does not establish that an image is Windows, valid, or serviceable.
pub fn inspect_image<R: Read + Seek>(
    wim: &mut Wim<R>,
    index: u32,
    inf_name: &str,
) -> io::Result<ServicingInspection> {
    if inf_name.is_empty()
        || !inf_name.is_ascii()
        || inf_name.contains(['/', '\\', ':'])
        || !inf_name.to_ascii_lowercase().ends_with(".inf")
    {
        return Err(invalid("expected a simple ASCII INF filename"));
    }
    wim.check_structure()?;
    let metadata = wim.image_metadata(index)?;
    let mut observations = Vec::new();
    let paths = [
        ("Windows/INF", true),
        ("Windows/System32/DriverStore", true),
        ("Windows/System32/DriverStore/FileRepository", true),
        ("Windows/System32/config/SYSTEM", false),
        ("Windows/System32/config/SOFTWARE", false),
    ];
    let mut matching_repository_directories = Vec::new();
    for (path, directory) in paths {
        let entry = find_image_path(&metadata, path)?;
        if entry.attributes & 0x400 != 0 || (entry.attributes & 0x10 != 0) != directory {
            return Err(invalid(format!("{path}: unexpected type or reparse point")));
        }
        let detail = if directory {
            if entry.children_offset == 0 {
                "directory, no child listing".to_string()
            } else {
                let offset = usize::try_from(entry.children_offset)
                    .map_err(|_| invalid("directory offset too large"))?;
                let entries = directory_entries(&metadata, offset)?;
                if path.ends_with("FileRepository") {
                    matching_repository_directories = entries
                        .iter()
                        .filter(|e| {
                            e.attributes & 0x10 != 0 && repository_name_matches(&e.name, inf_name)
                        })
                        .map(|e| e.name.clone())
                        .collect();
                    matching_repository_directories.sort();
                }
                format!("directory, {} immediate entries", entries.len())
            }
        } else {
            let resource = wim.find_hash(&entry.hash)?;
            format!(
                "file, {} uncompressed bytes",
                resource.resource.original_size
            )
        };
        observations.push(ImageObservation { path, detail });
    }
    Ok(ServicingInspection {
        observations,
        matching_repository_directories,
    })
}
fn repository_name_matches(name: &str, inf_name: &str) -> bool {
    let prefix = format!("{}_", inf_name.to_ascii_lowercase());
    name.to_ascii_lowercase().starts_with(&prefix)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn repository_prefix_requires_whole_inf_name() {
        assert!(repository_name_matches(
            "IASTORVD.INF_amd64_123",
            "iaStorVD.inf"
        ));
        assert!(!repository_name_matches(
            "iaStorVD.inf2_amd64",
            "iaStorVD.inf"
        ));
        assert!(!repository_name_matches("other.inf_amd64", "iaStorVD.inf"));
    }
}
