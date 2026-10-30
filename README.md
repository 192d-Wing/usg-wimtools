# Rust Image Tool

An independent, pure Rust foundation for portable Windows image tooling.
Targets macOS, Linux, and Windows. Requires Rust 1.99, edition 2024.
The tool uses Rust crates for XML and JSON parsing and SHA-256 hashing. It does
not use native libraries, Windows servicing APIs, or subprocesses. Unsafe Rust
is forbidden in this project's code.

## Current milestone

This is an **experimental, read-only WIM inspector and file extractor**, not a
complete DISM replacement. It cannot build the Dell image or inject drivers.

```sh
cargo run -- info /path/to/install.wim
cargo run -- xml /path/to/install.wim
cargo run -- check-structure /path/to/install.wim
cargo run -- verify-resource /path/to/install.wim 0
cargo run -- extract-file /path/to/install.wim 6 Windows/System32/notepad.exe ./notepad.exe
cargo run -- export-image /path/to/install.wim 6 ./windows11-pro.wim
cargo run -- replace-file /path/to/single-image.wim Windows/example.bin ./replacement.bin ./new.wim
cargo run -- inspect-inf /path/to/iaStorVD.inf
cargo run -- scan-drivers /path/to/extracted-drivers 'PCI\VEN_8086&DEV_7D0B'
cargo run -- match-inf /path/to/iaStorVD.inf 'PCI\VEN_8086&DEV_7D0B' 26300
cargo run -- audit-inf /path/to/iaStorVD.inf 'PCI\VEN_8086&DEV_7D0B' 26300
cargo run -- manifest-inf /path/to/iaStorVD.inf 'PCI\VEN_8086&DEV_7D0B' 26300 ./rst-manifest.json
cargo run -- verify-manifest /path/to/package-directory ./rst-manifest.json
cargo run -- hive-list /path/to/SYSTEM Select
cargo run -- hive-get /path/to/SYSTEM Select Current
cargo run -- hive-copy-set-dword /path/to/test.hive Example ValueName 42 ./test-copy.hive
```

Quote paths containing spaces. These commands also work in PowerShell with
Windows paths. `xml` emits decoded XML text; it does not parse XML or list
Windows editions separately. `info` exposes header fields and resource locations.
`verify-resource` takes a zero-based lookup-table ordinal. `extract-file` takes
a one-based image index and slash-separated image path; it verifies both image
metadata and file resources against their WIM SHA-1 values before creating the
output file. It will not overwrite an existing file. `extract-resource` can
write an individual verified lookup resource given its zero-based ordinal.
Resources larger than 128 MiB are currently unsupported. No ACLs, timestamps,
alternate streams, hard-link relationships, or other Windows metadata are
restored; reparse points cannot be extracted or traversed. Path matching is
ASCII case-insensitive and otherwise exact.

These SHA-1 checks detect mismatches with hashes stored in the WIM; they do not
authenticate the WIM or verify its provenance. A failed write can leave a partial
new output file. Extraction is experimental and is not an image deployment tool.

`check-structure` checks the classic WIM header, compression-field consistency,
resource bounds, lookup-record lengths and parts, metadata resource count,
boot-resource presence, and XML text encoding. It streams lookup records and
limits XML allocation to 16 MiB. Input files are opened read-only.

It does **not** check SHA-1 hashes, integrity-table contents, resource overlap,
directory/security metadata, compressed streams, XML semantics, or bootability.
A successful check only covers the stated structural checks.

Checking is limited to version `0x00010d00`, single-part ordinary WIM files,
uncompressed or classic 32-KiB XPRESS/LZX container layouts. No decompressor
is implemented for the structural check. File/resource reading supports LZX and
uncompressed resources; XPRESS decoding is not implemented. ESD/LZMS, solid
resources, split WIM, resource-only images,
unknown flags/versions, and nonclassic compression layouts are unsupported
for checking. Header inspection can still expose some unsupported variants.

`export-image` produces a single-image WIM, numbered 1, using an existing
classic, non-bootable, single-part WIM without an integrity table. It traverses
image metadata to collect referenced resources, preserves their stored bytes
and metadata, rebuilds lookup counts and XML, and verifies the metadata in the
result. The source is copied and compared byte-for-byte before editing the copy.
The output retains unused original resource bytes and is not size optimized.
It requires space for the complete source WIM and a filesystem that supports
hard links. The destination must not exist. A same-directory temporary file is
published using a non-overwriting hard link; normal errors clean it up, while
forced termination can leave a `.partial` file. The tool does not implement
power-loss recovery or protect against concurrent source changes after comparison.

The exporter is experimental. Its output passed an independent resource check
for one Windows 11 Pro WIM, but Windows Setup, booting and driver servicing have
not been tested. No authenticity check is performed.

`replace-file` experimentally replaces one existing, uniquely referenced regular
file in a single-image, non-bootable WIM without an integrity table. The input
file and replacement must have equal nonzero size (at most 128 MiB); files with
hard links, alternate streams, or shared content are rejected. The operation
verifies the original resource, copies and compares the source WIM, appends the
replacement and updated metadata, and checks the output before publishing it to a
new path. All other metadata is retained, including the original timestamps;
new resource bytes are uncompressed. Existing orphan data remains in the output.
The new destination is never overwritten, hard-link support is required, and a
forced termination can leave a `.partial` file. Neither power-loss recovery nor
concurrent source changes after the comparison are covered. A disposable Windows
image passed independent resource verification, but Windows deployment and boot
have not been tested. This operation does not add files, inject drivers, or stage
packages and is not yet suitable for deployment.

`inspect-inf` lists basic INF version fields, declared catalogs, raw Include
and Needs directives, and candidate hardware IDs. `scan-drivers` recursively
inventories INF files without following symbolic links; an optional hardware ID
filters for an exact ASCII case-insensitive textual candidate. The example ID is
illustrative, not evidence about the target machine. Both commands are read-only.
They do not evaluate Windows model sections, target architecture or OS-version
decorations, string substitutions, compatible-ID ranking, catalog signatures, or
the full dependency graph. IDs from any INF section are candidates only, so
results may include false positives and may miss substituted IDs. Non-ASCII
legacy text is decoded lossily and flagged. A skipped symlink is reported, and
an unreadable or malformed INF stops the scan. UTF-16 and UTF-8 BOMs are handled.

`match-inf` checks an exact supplied ID against model sections declared in
`[Manufacturer]`, for x64 Windows version 10.0 and the supplied build. It handles
`NTamd64`, basic major/minor decorations, optional minimum build with empty
product/suite fields, and substitutions from the undecorated `[Strings]` section.
It lists model candidates and related install-section names. It does not choose
the best model section, evaluate installation directives, resolve files, verify
signatures, or reproduce Windows ranking. Unsupported decorations, missing
tokens, undecorated manufacturers, and localized string sections produce warnings;
absence of a candidate is not proof of incompatibility when warnings are present.
Matching a test ID is not evidence that the target computer has that hardware.

`audit-inf` requires exactly one model candidate with no unresolved model
warnings. It checks generic and x64 SourceDisksFiles declarations against
SourceDisksNames paths, reports present or missing source files and catalogs,
and inspects CopyFiles, Include, and Needs in related candidate install sections.
It refuses path traversal, symbolic links, and ambiguous case-insensitive file
names. All related install sections are inspected without choosing the one Windows
would select. Cabinet fallback, CopyINF, external INF dependencies, catalog
selection and signatures, and complete dependency closure remain unimplemented.
Warnings and present files are not a certification that the package can be
installed or staged. This is a read-only audit.

`manifest-inf` snapshots the INF and the files identified by `audit-inf`, using
relative paths, sizes, and SHA-256 hashes. Missing files prevent creation.
`verify-manifest` checks those hashes and re-runs the audit to compare the file
set and candidate model. Manifest paths are restricted to the supplied package
directory, and a new manifest never overwrites an existing destination. Snapshot
publication requires hard-link support; forced termination can leave a temporary
file. Concurrent changes are not fully prevented.

The manifest is **not signed** and does not verify the catalog's contents,
signature, certificate chain, trust policy, dependency closure, or target
hardware. A match only shows consistency with the saved snapshot and this tool's
limited audit; an attacker who changes both package and manifest can create a
matching pair. Do not use it as authorization to stage a driver.

There is no driver staging or injection command. Completing that work requires
safe WIM file modifications, registry-hive servicing, driver-store behavior,
catalog trust handling, and Windows deployment testing. Do not use the scanner
as an installation or compatibility decision on its own.

`hive-list` and `hive-get` inspect a REGF hive read-only. Paths are relative to
the hive root, using `/` or `\`; pass an empty value name for the default value.
The reader validates the header checksum, sequence numbers, bin and allocated
cell bounds, and supports standard key lists and ordinary value data. Dirty hives
requiring log replay, symbolic-link keys, segmented or values over 16,344 bytes,
and hive files over 128 MiB are unsupported. Non-ASCII name matching is exact;
ASCII is case-insensitive. It loads the values for a whole key, so one unsupported
large value prevents reading that key. It does not validate every cell's semantic
content or recover logs. It has been checked against selected keys
in one Windows 11 SYSTEM hive; it is not a complete registry implementation.

`hive-copy-set-dword` experimentally changes one **existing inline** four-byte
REG_DWORD and creates a separate new hive. It checks that the value cell has
one reachable persistent reference, modifies only those four data bytes, reparses
the result, and checks the new value. It does not create keys or values, handle
external or non-DWORD values, update timestamps, or perform Windows staging.
It requires a filesystem with hard-link support, never overwrites an existing
destination, and may leave a `.partial` file after forced termination. Its output
has not been loaded by Windows. Do not use experimental hive copies for deployment.

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

1. Expand the Windows-generated fixture corpus, independent test vectors and
   cross-platform compatibility tests for LZX and resource decoding.
2. Implement streaming verification for resources larger than 128 MiB.
3. Parse and preserve directory metadata, ACLs, hard links, alternate streams,
   reparse points, and image XML; validate lossless round trips.
4. Extend WIM editing, optimize exports, and add crash recovery and validation
   against Windows deployment tools on Windows.
5. Parse Dell INF packages and report dependencies and hardware matches.
6. Implement offline driver-store and registry servicing. Simply copying driver
   files is insufficient. Boot-critical storage support needs separate validation.
7. Test Windows Setup and installed Windows on the target Dell, including disk
   visibility and networking in the relevant boot and install images.

Full CBS servicing, Windows updates, feature management, online repair,
mount drivers, and complete DISM CLI compatibility are outside this milestone.

See [PROVENANCE.md](PROVENANCE.md) for implementation source boundaries.

### Catalog envelope inspection

`rust-image-tool inspect-catalog <file.cat>` reports the PKCS#7 envelope content type, digest algorithm identifiers, and counts of outer certificate and signer records. It supports version 1 SignedData and limits input to 16 MiB. Nested records and catalog content are opaque: this does not validate signatures, certificates, trust, catalog membership, or driver suitability. Record counts do not imply valid signatures.

`rust-image-tool list-catalog-ids <file.cat>` lists subject identifiers from a limited Microsoft catalog CTL layout. The subject algorithm OID and identifiers are reported as encoded; attributes and file-specific hashing rules are not interpreted. A matching byte string alone does not establish verified file membership or catalog trust. Unsupported layouts are rejected.

`rust-image-tool pe-catalog-hash <file>` computes an experimental SHA-256 Authenticode PE digest for PE32 and PE32+ files with contiguous sections and either no overlay or a terminal certificate table. Other layouts are rejected. The digest excludes the PE checksum, certificate directory entry, and certificate table. Digest agreement is not signature, trust, or Windows driver-store verification; INF and other file-type hashing are not implemented.

`rust-image-tool compare-catalog-pe <file.cat> <file.exe-or-sys>` compares the experimental PE SHA-256 digest to subject identifiers in a supported V2 catalog. It exits unsuccessfully for mismatches and unsupported input. A match is unauthenticated and does not verify catalog signatures, trust, Windows catalog membership, or package completeness.
