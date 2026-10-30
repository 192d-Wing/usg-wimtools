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

#[derive(Debug, PartialEq, Eq)]
pub struct ImageTarget {
    pub architecture: u32,
    pub major: u32,
    pub minor: u32,
    pub build: u32,
    pub edition: String,
    pub installation_type: String,
    pub product_type: String,
}
fn one_child<'a, 'input>(
    parent: roxmltree::Node<'a, 'input>,
    name: &str,
) -> io::Result<roxmltree::Node<'a, 'input>> {
    let mut nodes = parent.children().filter(|n| {
        n.is_element() && n.tag_name().namespace().is_none() && n.tag_name().name() == name
    });
    let node = nodes
        .next()
        .ok_or_else(|| invalid(format!("missing image XML {name}")))?;
    if nodes.next().is_some() {
        return Err(invalid(format!("duplicate image XML {name}")));
    }
    Ok(node)
}
/// Read the claimed Windows architecture and version from image XML.
/// XML is untrusted metadata and does not prove compatibility.
pub fn parse_target(xml: &str, index: u32) -> io::Result<ImageTarget> {
    let doc =
        roxmltree::Document::parse(xml).map_err(|e| invalid(format!("invalid image XML: {e}")))?;
    let root = doc.root_element();
    if root.tag_name().name() != "WIM" || root.tag_name().namespace().is_some() {
        return Err(invalid("unsupported image XML root"));
    }
    let mut selected = None;
    for node in root.children().filter(|n| {
        n.is_element() && n.tag_name().namespace().is_none() && n.tag_name().name() == "IMAGE"
    }) {
        let id = node
            .attribute("INDEX")
            .ok_or_else(|| invalid("missing image index"))?
            .parse::<u32>()
            .map_err(|_| invalid("invalid image index"))?;
        if id == index && selected.replace(node).is_some() {
            return Err(invalid("duplicate image index"));
        }
    }
    let image = selected.ok_or_else(|| invalid("image index not found"))?;
    let windows = one_child(image, "WINDOWS")?;
    let version = one_child(windows, "VERSION")?;
    let number = |n: roxmltree::Node<'_, '_>, field: &str| -> io::Result<u32> {
        one_child(n, field)?
            .text()
            .ok_or_else(|| invalid(format!("empty {field}")))?
            .trim()
            .parse()
            .map_err(|_| invalid(format!("invalid {field}")))
    };
    let text = |n: roxmltree::Node<'_, '_>, field: &str| -> io::Result<String> {
        Ok(one_child(n, field)?
            .text()
            .ok_or_else(|| invalid(format!("empty {field}")))?
            .trim()
            .to_owned())
    };
    Ok(ImageTarget {
        architecture: number(windows, "ARCH")?,
        major: number(version, "MAJOR")?,
        minor: number(version, "MINOR")?,
        build: number(version, "BUILD")?,
        edition: text(windows, "EDITIONID")?,
        installation_type: text(windows, "INSTALLATIONTYPE")?,
        product_type: text(windows, "PRODUCTTYPE")?,
    })
}
impl ImageTarget {
    /// Narrow comparison for the current x64 INF audit, which models Windows 10+.
    pub fn matches_snapshot(&self, snapshot: &crate::manifest::Manifest) -> bool {
        self.architecture == 9
            && self.major == 10
            && self.minor == 0
            && self.build == snapshot.windows_build
            && self.edition.eq_ignore_ascii_case("Professional")
            && self.installation_type.eq_ignore_ascii_case("Client")
            && self.product_type.eq_ignore_ascii_case("WinNT")
    }
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
    fn target_xml_rejects_ambiguity_and_mismatch() {
        let xml = "<WIM><IMAGE INDEX=\"1\"><WINDOWS><ARCH>9</ARCH><EDITIONID>Professional</EDITIONID><INSTALLATIONTYPE>Client</INSTALLATIONTYPE><PRODUCTTYPE>WinNT</PRODUCTTYPE><VERSION><MAJOR>10</MAJOR><MINOR>0</MINOR><BUILD>26300</BUILD></VERSION></WINDOWS></IMAGE></WIM>";
        assert_eq!(
            parse_target(xml, 1).unwrap(),
            ImageTarget {
                architecture: 9,
                major: 10,
                minor: 0,
                build: 26300
            }
        );
        let snapshot: crate::manifest::Manifest = serde_json::from_str(r#"{"schema":1,"inf":"a.inf","hardware_id":"EXAMPLE","windows_build":26300,"model_section":"x","install_section":"x","files":[],"warnings":[],"trust_status":"NOT_VERIFIED"}"#).unwrap();
        assert!(parse_target(xml, 1).unwrap().matches_snapshot(&snapshot));
        assert!(
            !parse_target(&xml.replace("<ARCH>9</ARCH>", "<ARCH>12</ARCH>"), 1)
                .unwrap()
                .matches_snapshot(&snapshot)
        );
        assert!(
            !parse_target(&xml.replace("26300", "26100"), 1)
                .unwrap()
                .matches_snapshot(&snapshot)
        );
        assert!(parse_target(xml, 2).is_err());
        assert!(
            parse_target(
                &xml.replace("<ARCH>9</ARCH>", "<ARCH>9</ARCH><ARCH>12</ARCH>"),
                1
            )
            .is_err()
        );
        assert!(parse_target(&xml.replace("26300", "bad"), 1).is_err());
        assert!(parse_target(&xml.replace("</WIM>", "<IMAGE INDEX=\"1\"/></WIM>"), 1).is_err());
    }
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
