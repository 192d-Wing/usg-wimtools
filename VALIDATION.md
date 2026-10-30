# Real-image inspection

Date: October 29, 2026. Platform: macOS ARM64. Rust: pinned 1.99.

Source: user-provided `Windows11_Client_x64_en-us_26300_9457.iso`, mounted
read-only with the macOS disk-image utility. The Rust implementation reads
the WIM files directly; it does not depend on that utility for WIM parsing.
The source ISO and WIMs were not modified or copied into this repository.

| Property | sources/install.wim | sources/boot.wim |
| --- | ---: | ---: |
| File bytes | 8,155,984,950 | 612,018,500 |
| WIM version | 0x00010d00 | 0x00010d00 |
| Header flags | 0x00040082 | 0x00040082 |
| Compression layout | LZX, 32 KiB | LZX, 32 KiB |
| Parts | 1 | 1 |
| Images | 11 | 2 |
| Boot index | 0 | 2 |
| Lookup records | 100,998 | 13,609 |
| Structural check | Passed | Passed |
| Integrity table | Absent | Absent |

Installation XML reports x64, en-US, Windows build 26300.9457.
Image index 6 is Windows 11 Pro. Other images include Home, Education,
Pro Education, Pro for Workstations, and their included variants.

The first run rejected metadata flag 0x02 on plain lookup/XML resources.
After accepting that flag without treating the resources as compressed,
both images passed. A synthetic test reproduces that resource-flag layout.

Verification: 11 automated tests passed, Clippy with warnings denied passed,
formatting passed, and the release build passed. Windows/Linux CI has not
been run from this local repository.

Subsequent LZX work verified 10 selected install WIM resources and 6 selected
boot WIM resources against their stored SHA-1 values, including several large
metadata resources. The tool decoded the metadata for install image 6 and
extracted `Windows/System32/notepad.exe` (360,448 bytes). Its SHA-1 matched
both the WIM lookup record and the macOS `shasum` result:
`76cd26b59923157e09d2bc927ba8fb059f3155dc`. The file was identified as an x64
Windows PE executable. Source WIMs were read only. This samples resources; it
does not validate all resources or establish authenticity. The automated suite
now covers hash test vectors, malformed inputs, basic LZX blocks, and metadata
path traversal; it does not include a real Windows WIM fixture.

The original structural check remains limited; the separate sampled resource
checks and extraction do not validate every resource, all metadata, XML
semantics, source authenticity, Windows Setup, bootability, or driver
installation. The ISO filename and XML
are observed metadata, not independent proof of source authenticity.


## Single-image export

The Rust exporter created a single-image export from the same source's index 6.
It copied and compared the full original WIM, rebuilt the lookup and XML, then
compared the decoded image metadata to the source. The result contains one
Windows 11 Pro image at index 1 and 97,635 lookup records. It retains unused
original resource bytes and is 8,160,869,314 bytes.

An independently downloaded wimlib 1.14.5 binary (used only for validation,
not linked or called by the Rust tool) recognized the image and successfully
verified its metadata and all referenced file data. It reported no WIM integrity
table, so that separate check was skipped. Its full directory listings of the
source and exported image matched byte for byte (187,635 lines); its extracted
`notepad.exe` also matched the source extraction.

These checks do not establish source authenticity or prove Windows Setup will
accept or boot the image. The export has no added Dell drivers. Automated tests
include synthetic export, metadata-cycle rejection, missing-index handling,
source preservation, and destination no-overwrite behavior.

## Dell INF scan

The Rust scanner inspected the user's extracted QxM1250 JHY83 A07 pack and
reported 255 INF files. A search for the illustrative hardware ID
`PCI\VEN_8086&DEV_7D0B` found the RST VMD controller and extension INFs.
The local Dell hardware ID and firmware configuration were not available;
this does not establish device applicability. The tool does not resolve all
INF directives or validate signatures, and no drivers were staged or injected.

The later `match-inf` prototype examined declared model sections in the same
Intel RST INF. For the illustrative `PCI\VEN_8086&DEV_7D0B` and Windows build
26300 it reported `INTEL.NTamd64.10.0...19041` and install base `VMD_inst`;
at build 18000 it reported no candidate. For illustrative ID
`PCI\VEN_8086&DEV_09AB` it reported `VMD_dummy_function_inst`. Synthetic tests
cover matching, architecture, minimum builds, substitutions, unsupported
decorations, and ignoring undeclared model sections. These are candidate results,
not Windows SetupAPI or target-device verification.

The `audit-inf` prototype examined the same illustrative model and build in
the Dell RST controller INF. It found the declared `iaStorVD.sys`,
`RstMwService.exe`, `RstMwEventLogMsg.dll`, and `iaStorVD.cat` alongside the
INF. The audit does not verify the catalog, reproduce Windows section selection,
or establish complete package dependency closure. Synthetic tests cover
case-insensitive resolution, missing files, undeclared CopyFiles entries,
external dependencies, and unsafe source paths.

The manifest prototype snapshotted the same RST INF, catalog, and three
declared source files for the illustrative hardware ID and build. It re-read
and matched all five records. The `iaStorVD.sys` SHA-256 also matched macOS
`shasum -a 256`. Synthetic tests cover altered or missing files, omitted and
duplicate records, path traversal, and refusing to overwrite a manifest.
The manifest itself is not signed and the catalog signature and membership
have not been verified. The hardware ID is an example, not a discovered device.

## Read-only registry inspection

The tool extracted the 10 MiB SYSTEM hive from exported Windows 11 Pro image 1,
verifying its WIM resource hash. Its REGF parser read `Select/Current = 1` and
`ControlSet001/Services/stornvme/Start = 0` and `disk/Start = 0`. A separately
installed python-registry 1.3.1 reader agreed on these values. Synthetic tests
exercise traversal, inline DWORD values, dirty sequence numbers, corrupted
checksums and cells, and truncated files. Neither the source WIM nor extracted
hive was modified. No registry write, driver staging, or boot validation has
been performed.

## Experimental hive copy

After the read-only inspection, the Rust tool created a separate test copy of
the extracted SYSTEM hive and changed `Select/Current` from 1 to 2. This is a
test value change, not a proposed system configuration. Python-registry 1.3.1
independently read 1 from the source and 2 from the copy. The files had equal
lengths and differed in one byte. The source hive and WIM remained unchanged;
the copy was not loaded by Windows or inserted into the WIM.

Tests cover inline DWORD replacement, wrong types, missing names, shared value
cells, failed publication, and refusing to overwrite an existing output. The
implementation does not allocate registry cells, create keys, preserve a normal
Windows last-write timestamp update, or stage drivers. Successful re-parsing is
not proof that Windows will accept or boot a modified hive.

## Experimental file replacement

The Rust replacement command created a disposable copy of the single-image WIM,
replacing its SYSTEM hive with the equal-sized test copy described above. The
original WIM remained unchanged. An independent wimlib 1.14.5 extractor
recovered bytes identical to the replacement hive. Its complete directory list
matched the source listing (187,635 lines). The test changes a boot-related
value only to exercise the format; the test WIM must not be deployed.
The independent verifier successfully checked the final test WIM's metadata and
all referenced file data; there was no WIM integrity table to check.

Synthetic tests exercise replacement, source preservation, no-overwrite,
wrong-sized inputs, missing paths, hard links, and shared-resource counts. The
tool does not change timestamps, add new paths, stage drivers, or support WIMs
with boot metadata or integrity tables. Windows loading has not been tested.

Catalog envelope inspection was exercised on the supplied Dell RST `iaStorVD.cat` and compared with the outer ASN.1 structure shown by OpenSSL. The reader reported Microsoft content type 1.3.6.1.4.1.311.10.1, SHA-256 digest OID 2.16.840.1.101.3.4.2.1, two certificate records, and one signer record. This comparison does not verify signatures, certificates, membership, or trust. Synthetic tests cover truncation and malformed lengths and OIDs.

The catalog subject identifier reader found eight identifiers in the supplied Dell RST catalog. Their bytes were compared against the OCTET STRING identifiers in the CTL entry sequence using OpenSSL ASN.1 inspection. This is structural evidence only; no file membership, signature, or trust verification was performed. Synthetic tests cover a supported CTL, truncation, wrong content type, and a malformed identifier.

The experimental PE SHA-256 digests for the supplied Dell RST `iaStorVD.sys`, `RstMwEventLogMsg.dll`, and `RstMwService.exe` matched three subject identifiers in the accompanying catalog. This is a consistency check against an unverified catalog, not independent Windows SIP validation, signature verification, catalog trust, or proof of driver-store compatibility. Synthetic tests exercise excluded and included bytes, truncation, and noncontiguous layouts.

The catalog-to-PE comparison was exercised with the supplied Dell `iaStorVD.cat` and `iaStorVD.sys`: one subject identifier matched. A temporary copy with a changed section byte produced no matches and a failure exit. Synthetic integration tests cover match, changed content, unsupported algorithm, non-PE input, and truncated catalog. These checks do not verify catalog trust or Windows behavior.

The catalog content digest check matched the SHA-256 message-digest attribute in the supplied Dell RST catalog. A modified copy of the catalog content failed the check. Synthetic tests cover a matching digest, changed content, duplicate digest, wrong content type, and truncation. The signer attribute and signature remain unauthenticated.

The Dell RST catalog content digest and RSA signature were verified against the matching embedded signer public key. An independent OpenSSL SHA-256 signature verification of the extracted signed attributes and signature also succeeded. Synthetic tests create a test key and exercise successful verification, a changed signature and changed content. These checks do not validate the certificate, its chain, timestamps, revocation, Windows policy, or trust.

For the supplied Dell RST catalog, the signer certificate signature was verified against the embedded issuer key. As a separate comparison, OpenSSL accepted that link with the embedded issuer explicitly supplied as a temporary trust anchor, time checks disabled, and generic purpose; this does not validate the issuer against a trusted root or establish Windows trust. Synthetic tests check that modifying the signer certificate signature fails issuer verification while the catalog signature check alone still succeeds.

The two-link certificate signature check was tested with synthetic certificate-shaped records and a generated RSA key. Tests exercise matching issuer name and key, a wrong or truncated caller-supplied certificate, and a changed embedded issuer signature. At that stage no independently obtained Microsoft root was available; the subsequent real-catalog check is recorded below. This is not a certificate trust or Windows policy check.

On 2026-10-30 UTC, the DER Microsoft Root Certificate Authority 2010 was downloaded from Microsoft’s [PKI repository](https://www.microsoft.com/pkiops/docs/repository.htm) via its [certificate link](https://www.microsoft.com/pki/certs/MicRooCerAut_2010-06-23.crt). Its SHA-1 thumbprint `3B1EFD3A66EA28B16697394703A72CA340A05BD5` matched the value in the repository, and its serial `28CC3A25BFBA44AC449A9B586B4339AA` matched [Microsoft’s root list](https://learn.microsoft.com/en-us/troubleshoot/windows-server/certificates-and-public-key-infrastructure-pki/trusted-root-certificates-are-required). Its SHA-256 is `df545bf919a2439c36983b54cdfc903dfa4f37d3996d8d84b4c31eec6f3c163e`.

`verify-catalog-root-link` successfully verified the Dell RST catalog’s signer and the two RSA certificate signatures with that explicit root. OpenSSL independently accepted the extracted leaf and embedded intermediate with the downloaded root, generic purpose, and the system time, with no revocation check. Neither check establishes Windows driver-signing policy, timestamp validity, revocation status, catalog membership, or deployment compatibility. The external certificate is not bundled in the repository or automatically trusted by the tool.

The raw SHA-256 of the supplied `iaStorVD.inf` was `716ed3b9070460740da6dde3028e17c09ebbc1b1147ab6c3b2ca15b12391da3e`, matching one identifier in `iaStorVD.cat`. Independent OpenSSL ASN.1 inspection showed the same entry contains a UTF-16LE `iaStorVD.inf` name attribute and SHA-256 indirect digest. This is a single observed example, not validation of general Windows INF SIP hashing or package membership. Synthetic tests cover exact matches, changes, unsupported catalog algorithms, truncation, and the input size limit.

The combined package audit ran against the example Dell RST snapshot, illustrative hardware ID `PCI\\VEN_8086&DEV_7D0B`, build 26300, its declared catalog, and the downloaded Microsoft 2010 root. The catalog signature links matched and all four non-catalog snapshot files matched catalog identifiers. Synthetic tests cover an unmatched PE, unsupported file type, wrong catalog name, failed certificate link and modified snapshot. This does not establish the machine hardware ID, Windows driver selection, package completeness or trust.

The read-only servicing image inspection ran on image 1 of the exported Windows 11 Pro WIM. It found Windows/INF, DriverStore, FileRepository, and the SYSTEM and SOFTWARE hive paths, and found no FileRepository directory name starting `iaStorVD.inf_`. This name search cannot prove that the driver package is absent or present. No image modification or Windows servicing validation was performed.

The combined image and package audit ran against image 1 of the exported Windows 11 Pro WIM and the Dell RST example snapshot. WIM XML reported x64 architecture code 9 and Windows build 26300, matching the snapshot build. The package comparisons and certificate links matched as documented above. The snapshot uses an illustrative hardware ID; target hardware and Windows driver selection have not been verified. Synthetic tests reject mismatched architecture and build, malformed and duplicate XML, and missing image index.
