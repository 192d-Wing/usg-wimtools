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
the tool. No external implementation source is included. If strict personnel
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
