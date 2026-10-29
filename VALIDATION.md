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

These are structural checks only. Resource hashes, decompression, metadata
contents, XML semantics, source authenticity, Windows Setup, bootability,
and driver installation have not been verified. The ISO filename and XML
are observed metadata, not independent proof of source authenticity.
