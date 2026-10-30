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
