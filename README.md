# Rust Image Tool

An independent, pure Rust foundation for portable Windows image tooling.
Targets macOS, Linux, and Windows. Requires Rust 1.99, edition 2024.
No external crates, native libraries, Windows servicing APIs, or subprocesses
are used by the implementation. Unsafe Rust is forbidden.

## Current milestone

This is a **read-only WIM inspector**, not a complete DISM replacement.
It cannot yet build the Dell Windows 11 image or inject drivers.

```sh
cargo run -- info /path/to/install.wim
cargo run -- xml /path/to/install.wim
cargo run -- check-structure /path/to/install.wim
```

Quote paths containing spaces. These commands also work in PowerShell with
Windows paths. `xml` emits decoded XML text; it does not parse XML or list
Windows editions separately. `info` exposes header fields and resource locations.

`check-structure` checks the classic WIM header, compression-field consistency,
resource bounds, lookup-record lengths and parts, metadata resource count,
boot-resource presence, and XML text encoding. It streams lookup records and
limits XML allocation to 16 MiB. Input files are opened read-only.

It does **not** check SHA-1 hashes, integrity-table contents, resource overlap,
directory/security metadata, compressed streams, XML semantics, or bootability.
A successful check only covers the stated structural checks.

Checking is limited to version `0x00010d00`, single-part ordinary WIM files,
uncompressed or classic 32-KiB XPRESS/LZX container layouts. No decompressor
is implemented. ESD/LZMS, solid resources, split WIM, resource-only images,
unknown flags/versions, and nonclassic compression layouts are unsupported
for checking. Header inspection can still expose some unsupported variants.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```

Automated tests use synthetic binary envelopes, including malformed input and a
CLI read-only check. Manual inspection also passed on real Windows 11 install
and boot WIMs; see [VALIDATION.md](VALIDATION.md). Neither establishes deployment
or driver-servicing compatibility.
Only macOS has been exercised locally; the CI matrix covers all three platforms.

## Roadmap toward the Dell image

1. Establish a Windows-generated fixture corpus and compare inspection results.
2. Implement resource hash checks and compression with independent test vectors.
3. Parse and preserve directory metadata, ACLs, hard links, alternate streams,
   reparse points, and image XML; validate lossless round trips.
4. Implement transactional WIM export/write operations with crash recovery.
5. Parse Dell INF packages and report dependencies and hardware matches.
6. Implement offline driver-store and registry servicing. Simply copying driver
   files is insufficient. Boot-critical storage support needs separate validation.
7. Test Windows Setup and installed Windows on the target Dell, including disk
   visibility and networking in the relevant boot and install images.

Full CBS servicing, Windows updates, feature management, online repair,
mount drivers, and complete DISM CLI compatibility are outside this milestone.

See [PROVENANCE.md](PROVENANCE.md) for implementation source boundaries.
