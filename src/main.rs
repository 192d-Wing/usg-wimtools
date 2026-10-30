#![forbid(unsafe_code)]
use rust_image_tool::Wim;
use std::{
    env,
    fs::File,
    io::{self, Read, Write},
    process::ExitCode,
};

const HELP: &str = "rust-image-tool 0.1.0 — read-only WIM inspection\n\nUsage:\n  rust-image-tool info <image.wim>\n  rust-image-tool xml <image.wim>\n  rust-image-tool check-structure <image.wim>\n  rust-image-tool verify-resource <image.wim> <lookup-index>\n  rust-image-tool extract-resource <image.wim> <lookup-index> <output>\n  rust-image-tool extract-file <image.wim> <image-index> <image-path> <output>\n  rust-image-tool export-image <image.wim> <image-index> <output.wim>\n  rust-image-tool replace-file <image.wim> <image-path> <replacement-file> <new.wim>\n  rust-image-tool audit-catalog-package <package-dir> <manifest.json> <catalog-name> <issuer.der>\n  rust-image-tool verify-catalog-root-link <file.cat> <issuer.der>\n  rust-image-tool verify-catalog-issuer <file.cat>\n  rust-image-tool verify-catalog-signature <file.cat>\n  rust-image-tool check-catalog-content <file.cat>\n  rust-image-tool compare-catalog-inf-bytes <file.cat> <file.inf>\n  rust-image-tool compare-catalog-pe <file.cat> <file.exe-or-sys>\n  rust-image-tool pe-catalog-hash <file.exe-or-sys>\n  rust-image-tool list-catalog-ids <file.cat>\n  rust-image-tool inspect-catalog <file.cat>\n  rust-image-tool inspect-inf <file.inf>\n  rust-image-tool match-inf <file.inf> <hardware-id> <windows-build>\n  rust-image-tool audit-inf <file.inf> <hardware-id> <windows-build>\n  rust-image-tool manifest-inf <file.inf> <hardware-id> <windows-build> <manifest.json>\n  rust-image-tool verify-manifest <package-directory> <manifest.json>\n  rust-image-tool scan-drivers <directory> [hardware-id]\n  rust-image-tool hive-list <hive-file> <key-path>\n  rust-image-tool hive-get <hive-file> <key-path> <value-name>\n  rust-image-tool hive-copy-set-dword <hive-file> <key-path> <value-name> <decimal> <new-hive>\n\nStructural checks do not verify hashes, compressed data, or bootability.\nExport and file replacement are experimental. Driver injection is not implemented.";

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    let mut out = io::stdout().lock();
    if args.is_empty() || (args.len() == 1 && (args[0] == "--help" || args[0] == "-h")) {
        writeln!(out, "{HELP}")?;
        return Ok(());
    }
    if args.len() != 2
        && !(args.len() == 3
            && (args[0] == "verify-resource"
                || args[0] == "scan-drivers"
                || args[0] == "hive-list"
                || args[0] == "verify-manifest"
                || args[0] == "compare-catalog-pe"
                || args[0] == "compare-catalog-inf-bytes"
                || args[0] == "verify-catalog-root-link"))
        && !(args.len() == 4
            && (args[0] == "extract-resource"
                || args[0] == "export-image"
                || args[0] == "hive-get"
                || args[0] == "match-inf"
                || args[0] == "audit-inf"))
        && !(args.len() == 5
            && (args[0] == "extract-file"
                || args[0] == "replace-file"
                || args[0] == "manifest-inf"
                || args[0] == "audit-catalog-package"))
        && !(args.len() == 6 && args[0] == "hive-copy-set-dword")
    {
        return Err(format!("expected a command and image path\n\n{HELP}").into());
    }
    let command = args[0].to_str().ok_or("invalid command encoding")?;
    if !matches!(
        command,
        "info"
            | "xml"
            | "check-structure"
            | "verify-resource"
            | "extract-resource"
            | "extract-file"
            | "export-image"
            | "replace-file"
            | "audit-catalog-package"
            | "verify-catalog-root-link"
            | "verify-catalog-issuer"
            | "verify-catalog-signature"
            | "check-catalog-content"
            | "compare-catalog-inf-bytes"
            | "compare-catalog-pe"
            | "pe-catalog-hash"
            | "list-catalog-ids"
            | "inspect-catalog"
            | "inspect-inf"
            | "match-inf"
            | "audit-inf"
            | "manifest-inf"
            | "verify-manifest"
            | "scan-drivers"
            | "hive-list"
            | "hive-get"
            | "hive-copy-set-dword"
    ) {
        return Err(format!("unsupported command: {command}\n\n{HELP}").into());
    }
    if command == "verify-resource" && args.len() != 3 {
        return Err("verify-resource requires a lookup index".into());
    }
    if command == "extract-resource" && args.len() != 4 {
        return Err("extract-resource requires an index and output path".into());
    }
    if command == "extract-file" && args.len() != 5 {
        return Err("extract-file requires an image index, image path, and output path".into());
    }
    if command == "export-image" && args.len() != 4 {
        return Err("export-image requires an index and output path".into());
    }
    if command != "verify-resource"
        && command != "scan-drivers"
        && command != "match-inf"
        && command != "audit-inf"
        && command != "manifest-inf"
        && command != "verify-manifest"
        && command != "compare-catalog-pe"
        && command != "compare-catalog-inf-bytes"
        && command != "verify-catalog-root-link"
        && command != "audit-catalog-package"
        && command != "hive-list"
        && command != "hive-get"
        && command != "hive-copy-set-dword"
        && command != "extract-resource"
        && command != "extract-file"
        && command != "export-image"
        && command != "replace-file"
        && args.len() != 2
    {
        return Err("unexpected argument".into());
    }
    if command == "audit-catalog-package" {
        if args.len() != 5 {
            return Err(
                "expected package directory, snapshot, catalog name and issuer certificate".into(),
            );
        }
        let snapshot = rust_image_tool::manifest::load(std::path::Path::new(&args[2]))?;
        let name = args[3].to_str().ok_or("invalid catalog name")?;
        let report = rust_image_tool::package_check::check(
            std::path::Path::new(&args[1]),
            &snapshot,
            name,
            File::open(&args[4])?,
        )?;
        writeln!(out, "Catalog: {}", report.catalog_link)?;
        for f in &report.files {
            writeln!(
                out,
                "{} {}: {}",
                if f.matched {
                    "MATCH"
                } else {
                    "UNMATCHED/UNCHECKED"
                },
                f.path,
                f.result
            )?;
        }
        for warning in &report.warnings {
            writeln!(out, "WARNING: {warning}")?;
        }
        writeln!(
            out,
            "Experimental comparisons only; supplied root is not trusted automatically, and Windows hashing, catalog membership, trust, package completeness and compatibility are NOT verified."
        )?;
        if !report.comparisons_match() {
            return Err("one or more comparisons failed or were not performed".into());
        }
        return Ok(());
    }
    if command == "verify-catalog-root-link" {
        if args.len() != 3 {
            return Err("expected catalog and DER issuer certificate".into());
        }
        rust_image_tool::catalog::verify_issuer_against_certificate(
            File::open(&args[1])?,
            File::open(&args[2])?,
        )?;
        writeln!(
            out,
            "Catalog and two certificate signatures match the provided certificate key. The provided certificate is not independently trusted or validated. Certificate policy, time, revocation, timestamps, Windows trust, and file membership are NOT verified."
        )?;
        return Ok(());
    }
    if command == "verify-catalog-issuer" {
        rust_image_tool::catalog::verify_embedded_issuer(File::open(&args[1])?)?;
        writeln!(
            out,
            "Catalog signer signature and its certificate signature match the embedded issuer key. Certificate chain trust, identity, time, revocation, policy, and catalog membership are NOT verified."
        )?;
        return Ok(());
    }
    if command == "verify-catalog-signature" {
        rust_image_tool::catalog::verify_embedded_signer(File::open(&args[1])?)?;
        writeln!(
            out,
            "Content digest and RSA signature match an embedded certificate. Certificate chain, identity, time, revocation, policy, catalog membership and trust are NOT verified."
        )?;
        return Ok(());
    }
    if command == "check-catalog-content" {
        let matches = rust_image_tool::catalog::check_content_digest(File::open(&args[1])?)?;
        writeln!(
            out,
            "Content digest matches signer attribute: {matches}\nThe signer attribute is unauthenticated; signature, certificate and trust are NOT verified."
        )?;
        if !matches {
            return Err("catalog content digest mismatch".into());
        }
        return Ok(());
    }
    if command == "compare-catalog-inf-bytes" {
        if args.len() != 3 {
            return Err("expected catalog and INF paths".into());
        }
        let report = rust_image_tool::catalog::compare_inf_bytes(
            File::open(&args[1])?,
            File::open(&args[2])?,
        )?;
        write!(out, "Raw INF SHA-256: ")?;
        for byte in report.digest {
            write!(out, "{byte:02x}")?;
        }
        writeln!(
            out,
            "\nMatching catalog subject identifiers: {}\nExperimental byte comparison only; Windows SIP hashing, catalog membership, signatures, trust and compatibility are NOT verified.",
            report.matches
        )?;
        if report.matches == 0 {
            return Err("raw INF digest did not match any catalog subject identifier".into());
        }
        return Ok(());
    }
    if command == "compare-catalog-pe" {
        if args.len() != 3 {
            return Err("expected catalog and PE file paths".into());
        }
        let report =
            rust_image_tool::catalog::compare_pe(File::open(&args[1])?, File::open(&args[2])?)?;
        write!(out, "Experimental PE SHA-256: ")?;
        for byte in report.digest {
            write!(out, "{byte:02x}")?;
        }
        writeln!(
            out,
            "\nMatching catalog subject identifiers: {}\nCatalog signatures, trust, file membership and Windows compatibility are NOT verified.",
            report.matches
        )?;
        if report.matches == 0 {
            return Err("PE digest did not match any catalog subject identifier".into());
        }
        return Ok(());
    }
    if command == "pe-catalog-hash" {
        let hash = rust_image_tool::pe::authenticode_sha256(File::open(&args[1])?)?;
        write!(out, "PE SHA-256: ")?;
        for byte in hash {
            write!(out, "{byte:02x}")?;
        }
        writeln!(
            out,
            "\nExperimental digest only; catalog membership, signature and trust are NOT verified."
        )?;
        return Ok(());
    }
    if command == "list-catalog-ids" {
        let (algorithm, identifiers) =
            rust_image_tool::catalog::subject_identifiers(File::open(&args[1])?)?;
        writeln!(out, "Subject algorithm OID: {algorithm}")?;
        for id in &identifiers {
            for byte in id {
                write!(out, "{byte:02x}")?;
            }
            writeln!(out)?;
        }
        writeln!(
            out,
            "{} identifiers; file membership, signatures and trust are NOT verified.",
            identifiers.len()
        )?;
        return Ok(());
    }
    if command == "inspect-catalog" {
        let report = rust_image_tool::catalog::inspect(File::open(&args[1])?)?;
        writeln!(
            out,
            "Content type OID: {}\nDigest algorithm OIDs: {}\nCertificate records: {}\nSigner records: {}",
            report.content_type,
            report.digest_algorithms.join(", "),
            report.certificate_records,
            report.signer_records
        )?;
        writeln!(
            out,
            "Envelope structure only; signatures, certificate trust, catalog membership and contents are NOT verified."
        )?;
        return Ok(());
    }
    if command == "replace-file" {
        if args.len() != 5 {
            return Err("expected WIM, image path, replacement file, and output WIM".into());
        }
        let path = args[2].to_str().ok_or("invalid image path")?;
        rust_image_tool::replace_file(
            std::path::Path::new(&args[1]),
            path,
            std::path::Path::new(&args[3]),
            std::path::Path::new(&args[4]),
        )?;
        writeln!(
            out,
            "Experimental WIM created with a verified replacement; Windows deployment is not verified."
        )?;
        return Ok(());
    }
    if command == "manifest-inf" {
        if args.len() != 5 {
            return Err("expected INF path, hardware ID, build and manifest path".into());
        }
        let id = args[2].to_str().ok_or("invalid hardware ID")?;
        let build: u32 = args[3].to_str().ok_or("invalid Windows build")?.parse()?;
        let result = rust_image_tool::manifest::create(std::path::Path::new(&args[1]), id, build)?;
        rust_image_tool::manifest::save_new(std::path::Path::new(&args[4]), &result)?;
        writeln!(
            out,
            "Snapshot created for {} files; catalog trust and package completeness NOT verified.",
            result.files.len()
        )?;
        for warning in result.warnings {
            writeln!(out, "WARNING: {warning}")?;
        }
        return Ok(());
    }
    if command == "verify-manifest" {
        if args.len() != 3 {
            return Err("expected package directory and manifest path".into());
        }
        let result = rust_image_tool::manifest::load(std::path::Path::new(&args[2]))?;
        let count = rust_image_tool::manifest::verify(std::path::Path::new(&args[1]), &result)?;
        writeln!(
            out,
            "Snapshot matches {count} files and current audit; catalog trust and package completeness NOT verified."
        )?;
        return Ok(());
    }
    if command == "audit-inf" {
        if args.len() != 4 {
            return Err("expected INF path, hardware ID and Windows build".into());
        }
        let id = args[2].to_str().ok_or("invalid hardware ID")?;
        let build: u32 = args[3].to_str().ok_or("invalid Windows build")?.parse()?;
        let report =
            rust_image_tool::inf::audit_package(std::path::Path::new(&args[1]), id, build)?;
        writeln!(
            out,
            "Candidate: {}\nModels: {}\nInstall base: {}",
            report.model.description, report.model.model_section, report.model.install_section
        )?;
        for f in report.files {
            match (f.path, f.issue) {
                (Some(p), _) => writeln!(out, "PRESENT {}: {}", f.name, p.display())?,
                (_, Some(e)) => writeln!(out, "MISSING {}: {e}", f.name)?,
                _ => {}
            }
        }
        writeln!(
            out,
            "Include: {}\nNeeds: {}",
            report.includes.join(", "),
            report.needs.join(", ")
        )?;
        for warning in report.warnings {
            writeln!(out, "WARNING: {warning}")?;
        }
        writeln!(
            out,
            "Presence is not signature, catalog, package-completeness, or Windows compatibility verification."
        )?;
        return Ok(());
    }
    if command == "match-inf" {
        if args.len() != 4 {
            return Err("expected INF path, hardware ID and Windows build".into());
        }
        let id = args[2].to_str().ok_or("invalid hardware ID")?;
        let build: u32 = args[3].to_str().ok_or("invalid Windows build")?.parse()?;
        let report =
            rust_image_tool::inf::model_candidates(std::path::Path::new(&args[1]), id, build)?;
        writeln!(
            out,
            "{} model candidate(s) for x64 Windows 10.0 build {build}.",
            report.matches.len()
        )?;
        for item in report.matches {
            writeln!(
                out,
                "\n  Description: {}\n  Models section: {}\n  Install section base: {}\n  ID kind: {}\n  Minimum build: {}\n  Related install sections: {}",
                item.description,
                item.model_section,
                item.install_section,
                if item.compatible_id {
                    "compatible ID"
                } else {
                    "hardware ID"
                },
                item.min_build
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "unspecified".into()),
                item.related_sections.join(", ")
            )?;
        }
        for warning in report.warnings {
            writeln!(out, "WARNING: {warning}")?;
        }
        writeln!(
            out,
            "\nCandidates only: Windows selection/ranking, dependency resolution, and signatures are not verified."
        )?;
        return Ok(());
    }
    if command == "hive-copy-set-dword" {
        if args.len() != 6 {
            return Err(
                "expected hive path, key, value name, decimal DWORD and new output path".into(),
            );
        }
        let mut bytes = Vec::new();
        File::open(&args[1])?
            .take(128 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        let hive = rust_image_tool::registry::Hive::parse(bytes)?;
        let key = args[2].to_str().ok_or("invalid registry path")?;
        let name = args[3].to_str().ok_or("invalid registry value name")?;
        let number: u32 = args[4].to_str().ok_or("invalid DWORD")?.parse()?;
        let updated = hive.replace_inline_dword(key, name, number)?;
        rust_image_tool::registry::save_new(std::path::Path::new(&args[5]), &updated)?;
        writeln!(
            out,
            "Created experimental hive copy with one inline DWORD changed; Windows loading is not verified."
        )?;
        return Ok(());
    }
    if command == "hive-list" || command == "hive-get" {
        if (command == "hive-list" && args.len() != 3) || (command == "hive-get" && args.len() != 4)
        {
            return Err("invalid hive command arguments".into());
        }
        let mut bytes = Vec::new();
        File::open(&args[1])?
            .take(128 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        let hive = rust_image_tool::registry::Hive::parse(bytes)?;
        let path = args[2].to_str().ok_or("invalid registry path")?;
        let key = hive.key(path)?;
        if command == "hive-list" {
            writeln!(
                out,
                "Key: {} (REGF {}.{})",
                key.name, hive.major, hive.minor
            )?;
            for name in &key.subkeys {
                writeln!(out, "  key: {name}")?;
            }
            for value in &key.values {
                writeln!(
                    out,
                    "  value: {} type={} bytes={}",
                    if value.name.is_empty() {
                        "(default)"
                    } else {
                        &value.name
                    },
                    value.kind,
                    value.data.len()
                )?;
            }
        } else {
            let name = args[3].to_str().ok_or("invalid value name")?;
            let value = key
                .values
                .iter()
                .find(|v| v.name.eq_ignore_ascii_case(name))
                .ok_or("value not found")?;
            writeln!(out, "Type: {}\nBytes: {}", value.kind, value.data.len())?;
            if value.kind == 4 && value.data.len() == 4 {
                writeln!(
                    out,
                    "DWORD: {}",
                    u32::from_le_bytes(value.data[..4].try_into()?)
                )?;
            } else {
                for b in &value.data {
                    write!(out, "{b:02x}")?;
                }
                writeln!(out)?;
            }
        }
        return Ok(());
    }
    if command == "inspect-inf" || command == "scan-drivers" {
        let (items, skipped) = if command == "inspect-inf" {
            (
                vec![rust_image_tool::inf::inspect(std::path::Path::new(
                    &args[1],
                ))?],
                0,
            )
        } else {
            let id = args
                .get(2)
                .map(|s| s.to_str().ok_or("invalid hardware ID encoding"))
                .transpose()?;
            rust_image_tool::inf::scan(std::path::Path::new(&args[1]), id)?
        };
        writeln!(
            out,
            "{} INF candidate(s); {skipped} symlinks skipped.",
            items.len()
        )?;
        for inf in items {
            writeln!(
                out,
                "\n{}\n  Class: {}\n  DriverVer: {}\n  Catalogs: {}\n  Include: {}\n  Needs: {}\n  Candidate hardware IDs: {}{}",
                inf.path.display(),
                inf.class.as_deref().unwrap_or("unknown"),
                inf.driver_version.as_deref().unwrap_or("unknown"),
                inf.catalogs.join(", "),
                inf.includes.join(", "),
                inf.needs.join(", "),
                inf.hardware_ids.len(),
                if inf.had_non_ascii_legacy_text {
                    " (legacy non-ASCII text decoded lossily)"
                } else {
                    ""
                }
            )?;
            if command == "inspect-inf" {
                for id in &inf.hardware_ids {
                    writeln!(out, "    {id}")?;
                }
            }
        }
        writeln!(
            out,
            "\nRaw candidates only; Windows selection, OS applicability, dependencies, and catalog signatures have not been verified."
        )?;
        return Ok(());
    }
    if command == "export-image" {
        let index: u32 = args[2].to_str().ok_or("invalid image index")?.parse()?;
        rust_image_tool::export_one(
            std::path::Path::new(&args[1]),
            std::path::Path::new(&args[3]),
            index,
        )?;
        writeln!(
            out,
            "Experimental image export created; Windows deployment compatibility not yet verified."
        )?;
        return Ok(());
    }
    let mut wim = Wim::open(File::open(&args[1])?)?;
    match command {
        "info" => {
            let h = &wim.header;
            writeln!(
                out,
                "File bytes: {}\nVersion: 0x{:08x}\nFlags: 0x{:08x}\nChunk bytes: {}\nPart: {}/{}\nImages: {}\nBoot index: {}",
                wim.file_size,
                h.version,
                h.flags,
                h.chunk_size,
                h.part_number,
                h.total_parts,
                h.image_count,
                h.boot_index
            )?;
            for (name, r) in [
                ("Lookup", h.lookup),
                ("XML", h.xml),
                ("Boot metadata", h.boot_metadata),
                ("Integrity", h.integrity),
            ] {
                writeln!(
                    out,
                    "{name}: offset={}, stored={}, original={}, flags=0x{:02x}",
                    r.offset, r.stored_size, r.original_size, r.flags
                )?;
            }
            writeln!(
                out,
                "Header inspection only; image contents have not been verified."
            )?;
        }
        "xml" => {
            write!(out, "{}", wim.xml_text()?)?;
        }
        "extract-file" => {
            let index: u32 = args[2].to_str().ok_or("invalid image index")?.parse()?;
            let path = args[3].to_str().ok_or("invalid image path")?;
            let metadata = wim.image_metadata(index)?;
            let entry = rust_image_tool::find_image_path(&metadata, path)?;
            if entry.attributes & (0x10 | 0x400) != 0 {
                return Err("requested path is a directory or reparse point".into());
            }
            let data = if entry.hash == [0; 20] {
                Vec::new()
            } else {
                let resource = wim.find_hash(&entry.hash)?;
                wim.read_verified(&resource)?
            };
            let mut dest = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&args[4])?;
            dest.write_all(&data)?;
            writeln!(
                out,
                "Extracted {} bytes from image {index}; resource SHA-1 verified (empty files have no resource hash).",
                data.len()
            )?;
        }
        "verify-resource" | "extract-resource" => {
            let index: u64 = args[2].to_str().ok_or("invalid index")?.parse()?;
            let entry = wim.lookup_entry(index)?;
            let data = wim.read_verified(&entry)?;
            if command == "extract-resource" {
                let mut dest = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&args[3])?;
                dest.write_all(&data)?;
            }
            writeln!(
                out,
                "Verified lookup resource {index}: {} bytes, SHA-1 matches.",
                data.len()
            )?;
        }
        "check-structure" => {
            let report = wim.check_structure()?;
            writeln!(
                out,
                "Structural checks passed: {} lookup entries, {} image metadata resources.\nIntegrity table present: {} (hashes NOT checked).\nCompressed contents, metadata contents, XML semantics, and bootability NOT checked.",
                report.lookup_entries, report.metadata_entries, report.integrity_table_present
            )?;
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
