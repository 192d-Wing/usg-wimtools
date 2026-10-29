#![forbid(unsafe_code)]
use rust_image_tool::Wim;
use std::{
    env,
    fs::File,
    io::{self, Write},
    process::ExitCode,
};

const HELP: &str = "rust-image-tool 0.1.0 — read-only WIM inspection\n\nUsage:\n  rust-image-tool info <image.wim>\n  rust-image-tool xml <image.wim>\n  rust-image-tool check-structure <image.wim>\n\nStructural checks do not verify hashes, compressed data, or bootability.\nImage writing and driver injection are not implemented.";

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    let mut out = io::stdout().lock();
    if args.is_empty() || (args.len() == 1 && (args[0] == "--help" || args[0] == "-h")) {
        writeln!(out, "{HELP}")?;
        return Ok(());
    }
    if args.len() != 2 {
        return Err(format!("expected a command and image path\n\n{HELP}").into());
    }
    let command = args[0].to_str().ok_or("invalid command encoding")?;
    if !matches!(command, "info" | "xml" | "check-structure") {
        return Err(format!("unsupported command: {command}\n\n{HELP}").into());
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
