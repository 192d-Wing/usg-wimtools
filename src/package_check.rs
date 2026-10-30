//! Experimental package comparison, not Windows driver-store validation.
use crate::{catalog, inf, invalid, manifest, unsupported};
use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};

#[derive(Debug)]
pub struct FileCheck {
    pub path: String,
    pub result: String,
    pub matched: bool,
}
#[derive(Debug)]
pub struct PackageCheck {
    pub files: Vec<FileCheck>,
    pub catalog_link: String,
    pub catalog_link_matches: bool,
    pub warnings: Vec<String>,
}
impl PackageCheck {
    pub fn comparisons_match(&self) -> bool {
        self.catalog_link_matches && self.files.iter().all(|f| f.matched)
    }
}

/// Re-audit an existing snapshot, check one unambiguous declared catalog, and
/// compare supported files. A match is not a trust or package completeness claim.
pub fn check(
    root: &Path,
    snapshot: &manifest::Manifest,
    catalog_name: &str,
    root_cert: impl Read,
) -> io::Result<PackageCheck> {
    manifest::verify(root, snapshot)?;
    let inf_parts = manifest::safe_parts(&snapshot.inf)?;
    let inf_path = inf::find_relative(root, &inf_parts)?.ok_or_else(|| invalid("INF missing"))?;
    let inventory = inf::inspect(&inf_path)?;
    if inventory.catalogs.len() != 1
        || inventory.catalogs[0].contains('%')
        || !inventory.catalogs[0].eq_ignore_ascii_case(catalog_name)
    {
        return Err(unsupported(
            "requires one unambiguous, explicitly named INF catalog",
        ));
    }
    let cat_parts = manifest::safe_parts(catalog_name)?;
    if cat_parts.len() != 1
        || !snapshot
            .files
            .iter()
            .any(|f| f.path.eq_ignore_ascii_case(catalog_name))
    {
        return Err(invalid("catalog is not a snapshot file beside the INF"));
    }
    let cat_path =
        inf::find_relative(root, &cat_parts)?.ok_or_else(|| invalid("catalog missing"))?;
    let mut catalog_bytes = Vec::new();
    File::open(cat_path)?
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut catalog_bytes)?;
    if catalog_bytes.len() > 16 * 1024 * 1024 {
        return Err(unsupported("catalog exceeds 16 MiB"));
    }
    let mut anchor = Vec::new();
    root_cert.take(1024 * 1024 + 1).read_to_end(&mut anchor)?;
    if anchor.len() > 1024 * 1024 {
        return Err(unsupported("issuer certificate exceeds 1 MiB"));
    }
    let link = catalog::verify_issuer_against_certificate(&catalog_bytes[..], &anchor[..]);
    let catalog_link_matches = link.is_ok();
    let catalog_link = match link {
        Ok(()) => "two certificate-signature links match supplied issuer key".to_owned(),
        Err(e) => format!("not verified: {e}"),
    };
    let mut files = Vec::new();
    for record in &snapshot.files {
        if record.path.eq_ignore_ascii_case(catalog_name) {
            continue;
        }
        let parts = manifest::safe_parts(&record.path)?;
        let path =
            inf::find_relative(root, &parts)?.ok_or_else(|| invalid("snapshot file missing"))?;
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let result = match ext.as_str() {
            "inf" => File::open(&path)
                .and_then(|f| catalog::compare_inf_bytes(&catalog_bytes[..], f))
                .map(|r| (r.matches, "raw INF SHA-256")),
            "sys" | "dll" | "exe" => File::open(&path)
                .and_then(|f| catalog::compare_pe(&catalog_bytes[..], f))
                .map(|r| (r.matches, "experimental PE SHA-256")),
            _ => Err(unsupported("file-type catalog hashing not implemented")),
        };
        let (matched, result) = match result {
            Ok((count, kind)) => (
                count > 0,
                format!("{kind}: {count} matching subject identifiers"),
            ),
            Err(e) => (false, format!("not checked: {e}")),
        };
        files.push(FileCheck {
            path: record.path.clone(),
            result,
            matched,
        });
    }
    // Re-check after comparisons; this does not guarantee protection against concurrent changes.
    manifest::verify(root, snapshot)?;
    Ok(PackageCheck {
        files,
        catalog_link,
        catalog_link_matches,
        warnings: snapshot.warnings.clone(),
    })
}
