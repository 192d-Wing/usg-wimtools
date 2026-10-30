#![forbid(unsafe_code)]
use rust_image_tool::Wim;
use std::{
    env,
    fs::File,
    io::{self, Write},
    process::ExitCode,
};

const HELP: &str = "rust-image-tool 0.1.0 — read-only WIM inspection\n\nUsage:\n  rust-image-tool info <image.wim>\n  rust-image-tool xml <image.wim>\n  rust-image-tool check-structure <image.wim>\n  rust-image-tool verify-resource <image.wim> <lookup-index>\n  rust-image-tool extract-resource <image.wim> <lookup-index> <output>\n  rust-image-tool extract-file <image.wim> <image-index> <image-path> <output>\n  rust-image-tool export-image <image.wim> <image-index> <output.wim>\n  rust-image-tool inspect-inf <file.inf>\n  rust-image-tool scan-drivers <directory> [hardware-id]\n\nStructural checks do not verify hashes, compressed data, or bootability.\nExport is experimental. WIM editing and driver injection are not implemented.";

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    let mut out = io::stdout().lock();
    if args.is_empty() || (args.len() == 1 && (args[0] == "--help" || args[0] == "-h")) {
        writeln!(out, "{HELP}")?;
        return Ok(());
    }
    if args.len() != 2
        && !(args.len() == 3 && (args[0] == "verify-resource" || args[0] == "scan-drivers"))
        && !(args.len() == 4 && (args[0] == "extract-resource" || args[0] == "export-image"))
        && !(args.len() == 5 && args[0] == "extract-file")
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
            | "inspect-inf"
            | "scan-drivers"
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
        && command != "extract-resource"
        && command != "extract-file"
        && command != "export-image"
        && args.len() != 2
    {
        return Err("unexpected argument".into());
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
