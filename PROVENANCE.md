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

## Compatibility evidence

Current tests cover only locally generated synthetic envelopes. No Windows ISO,
Dell driver package, or Windows-generated WIM has been tested. No Windows
boot or driver-injection compatibility is claimed.
