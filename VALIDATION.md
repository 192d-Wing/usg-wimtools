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
