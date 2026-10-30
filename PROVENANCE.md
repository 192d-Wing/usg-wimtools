# Provenance and implementation boundaries

## Primary specification

Microsoft, *Windows Imaging File Format (WIM)*, version 1.1 download, document
last updated October 2007:

https://www.microsoft.com/en-us/download/details.aspx?id=13096

Implementation facts were taken from the WIM Header, WIM File Resource,
Lookup Table, and XML Data sections. The implementation uses independently
written Rust code and synthetic tests. The Microsoft document is not bundled.
Its age means modern Windows formats require additional specification work
and compatibility testing.

Driver-servicing behavior for future scope:

https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/add-and-remove-drivers-to-an-offline-windows-image?view=windows-11

## Clean-room status

This is an independent implementation from published format documentation,
not an audited, formally separated clean-room process. During initial research,
search results exposed snippets from Microsoft's Go WIM reader, wimlib-related
headers, and other WIM tools. Those sources were not used as code templates
or translated into this project. This exposure is recorded rather than claiming
the implementer had no access to other implementations.

No DISM, WIMGAPI, wimlib, or other WIM implementation is linked or executed by
the Rust tool. A separately downloaded wimlib binary was used only as an
independent verifier for the exported WIM; it is not a project dependency.
No external WIM implementation source is included. If strict personnel
separation is required, establish an independent specification/implementation
process before extending or adopting this prototype.

The LZX decoder uses Microsoft's published LZX Delta description for shared
Huffman, match, and E8 concepts, with WIM-specific differences informed by
publicly available format descriptions and observable WIM data:

https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-patch/
https://github.com/libyal/libfwnt/blob/main/documentation/Compression%20methods.asciidoc

Search results during this work also exposed code excerpts and comments from
other LZX implementations, including WIM-specific block sizes and offset-table
facts. No code was copied, but the developer saw those excerpts. This project
does not claim formal clean-room separation. SHA-1 is implemented for WIM format
interoperability, not as an authenticity mechanism.

## Compatibility evidence

Automated tests cover locally generated synthetic envelopes. Manual inspection,
resource verification, and a single file extraction also ran against the install
and boot WIMs inside the user's Windows 11 ISO;
see [VALIDATION.md](VALIDATION.md). This revealed that plain XML and lookup
resources can carry the metadata bit. The independently written flag check
was corrected and a synthetic regression test was added. No Windows boot,
driver package extraction, or driver-injection compatibility is claimed.

XML parsing uses the pure-Rust crates `roxmltree` and `memchr` under their
respective open-source licenses. The manifest implementation also uses Rust
crates `sha2`, `serde`, and `serde_json`; dependency versions are locked in
Cargo.lock.

INF inventory is an independently implemented, read-only approximation based on
observed INF text. It does not implement Windows selection or staging. Relevant
Microsoft references include:
https://learn.microsoft.com/en-us/windows-hardware/drivers/install/driver-store
https://learn.microsoft.com/en-us/windows-hardware/drivers/install/catalog-files
https://learn.microsoft.com/en-us/windows-hardware/drivers/install/inf-manufacturer-section
https://learn.microsoft.com/en-us/windows-hardware/drivers/install/inf-strings-section
https://learn.microsoft.com/en-us/windows-hardware/drivers/install/inf-sourcedisksfiles-section
https://learn.microsoft.com/en-us/windows-hardware/drivers/install/inf-sourcedisksnames-section
https://learn.microsoft.com/en-us/windows-hardware/drivers/install/inf-copyfiles-directive
https://learn.microsoft.com/en-us/windows-hardware/drivers/install/driver-store

The read-only REGF parser was independently implemented using the public format
description at https://github.com/libyal/libregf/blob/main/documentation/Windows%20NT%20Registry%20File%20%28REGF%29%20format.asciidoc
and synthetic inputs. This is a format document, not code copied into the project.
Python-registry 1.3.1 was used separately to compare selected values; it is not
linked to or executed by the Rust tool. No formal clean-room separation is claimed.
For volatile cell-index interpretation during write-safety checks, see the public
format analysis at https://projectzero.google/2024/12/the-windows-registry-adventure-5-regf.html

Catalog envelope inspection uses the published PKCS#7 structure in [RFC 2315](https://www.rfc-editor.org/rfc/rfc2315) and the context described in [Microsoft catalog files documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/catalog-files). It does not implement catalog trust or membership validation.

Catalog subject identifier inspection was informed by the published [CTL_INFO structure](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-ctl_info), [catalog documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/catalog-files), and the supplied catalog ASN.1 layout. Search results also exposed excerpts of Microsoft .NET catalog encoder source; those excerpts were not copied, but this is not a formally separated clean-room process. File-specific hashes are not implemented; [PE signatures documentation](https://learn.microsoft.com/en-us/windows/win32/secbp/understanding-pe-signatures) explains why ordinary file hashes are insufficient.

PE digest support was independently implemented for a restricted contiguous-section layout using the [Microsoft PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) and the supplied driver files. No Windows SIP or trust implementation is used, and this is not a formally separated clean-room process.

The catalog content digest check follows [RFC 2315 sections 9.2–9.3](https://www.rfc-editor.org/rfc/rfc2315) and observed catalog structure; it does not verify signatures or establish trust.

Embedded signer verification uses the pure Rust `rsa` crate and the SHA-256 implementation in `sha2`, with format processing informed by [RFC 2315](https://www.rfc-editor.org/rfc/rfc2315). Dependencies are recorded in Cargo.lock. The certificate is used only as a source of an issuer, serial and public key; its authenticity and validity are not checked.

The INF byte comparison is based on the observed Dell catalog and exact file bytes, not a claim to implement Windows INF SIP semantics. [Microsoft catalog documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/catalog-files) describes catalog hashes at a high level; no general INF hashing specification or independent Windows SIP result was established here.
