//! Narrow Authenticode PE hashing for images with contiguous file sections.
use sha2::{Digest, Sha256};
use std::io::{self, Read};
fn bad(s: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, s)
}
fn word(b: &[u8], i: usize) -> io::Result<u16> {
    Ok(u16::from_le_bytes(
        b.get(i..i + 2)
            .ok_or_else(|| bad("truncated PE"))?
            .try_into()
            .unwrap(),
    ))
}
fn dword(b: &[u8], i: usize) -> io::Result<usize> {
    Ok(u32::from_le_bytes(
        b.get(i..i + 4)
            .ok_or_else(|| bad("truncated PE"))?
            .try_into()
            .unwrap(),
    ) as usize)
}
/// SHA-256 PE image digest for the supported contiguous-section subset.
/// This is not a signature, trust, or Windows compatibility check.
pub fn authenticode_sha256(reader: impl Read) -> io::Result<[u8; 32]> {
    const LIMIT: u64 = 128 * 1024 * 1024;
    let mut b = Vec::new();
    reader.take(LIMIT + 1).read_to_end(&mut b)?;
    if b.len() as u64 > LIMIT {
        return Err(bad("PE exceeds 128 MiB limit"));
    }
    if b.get(..2) != Some(b"MZ") {
        return Err(bad("missing DOS signature"));
    }
    let pe = dword(&b, 0x3c)?;
    if b.get(pe..pe.checked_add(4).ok_or_else(|| bad("PE offset overflow"))?) != Some(b"PE\0\0") {
        return Err(bad("missing PE signature"));
    }
    if pe.checked_add(24).is_none_or(|end| end > b.len()) {
        return Err(bad("truncated PE header"));
    }
    let sections = usize::from(word(&b, pe + 6)?);
    if sections == 0 || sections > 96 {
        return Err(bad("unsupported section count"));
    }
    let opt_size = usize::from(word(&b, pe + 20)?);
    let opt = pe
        .checked_add(24)
        .ok_or_else(|| bad("PE offset overflow"))?;
    let opt_end = opt
        .checked_add(opt_size)
        .filter(|&n| n <= b.len())
        .ok_or_else(|| bad("truncated optional header"))?;
    let (directory, count_offset) = match word(&b, opt)? {
        0x10b => (96, 92),
        0x20b => (112, 108),
        _ => return Err(bad("unsupported optional header")),
    };
    if opt_size < directory + 40 || dword(&b, opt + count_offset)? < 5 {
        return Err(bad("missing certificate directory"));
    }
    let checksum = opt + 64;
    let cert_entry = opt + directory + 32;
    let cert_start = dword(&b, cert_entry)?;
    let cert_size = dword(&b, cert_entry + 4)?;
    let headers = dword(&b, opt + 60)?;
    let table_end = opt_end
        .checked_add(
            sections
                .checked_mul(40)
                .ok_or_else(|| bad("section table overflow"))?,
        )
        .ok_or_else(|| bad("section table overflow"))?;
    if table_end > headers || headers > b.len() || cert_entry + 8 > headers {
        return Err(bad("invalid PE headers"));
    }
    let mut ranges = Vec::new();
    for i in 0..sections {
        let at = opt_end + i * 40;
        let size = dword(&b, at + 16)?;
        let start = dword(&b, at + 20)?;
        if size != 0 {
            let end = start
                .checked_add(size)
                .filter(|&n| n <= b.len())
                .ok_or_else(|| bad("invalid section range"))?;
            ranges.push((start, end));
        }
    }
    ranges.sort_unstable();
    let mut end = headers;
    for &(start, next) in &ranges {
        if start != end {
            return Err(bad("unsupported overlapping or noncontiguous sections"));
        }
        end = next;
    }
    if cert_size == 0 {
        if cert_start != 0 || end != b.len() {
            return Err(bad("unsupported PE overlay"));
        }
    } else if cert_start != end || cert_start.checked_add(cert_size) != Some(b.len()) {
        return Err(bad("unsupported certificate or overlay layout"));
    }
    let mut hash = Sha256::new();
    hash.update(&b[..checksum]);
    hash.update(&b[checksum + 4..cert_entry]);
    hash.update(&b[cert_entry + 8..headers]);
    for (start, end) in ranges {
        hash.update(&b[start..end]);
    }
    Ok(hash.finalize().into())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn image() -> Vec<u8> {
        let mut b = vec![0u8; 0x230];
        b[..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        b[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        b[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
        let o = 0x98;
        b[o..o + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        b[o + 60..o + 64].copy_from_slice(&0x200u32.to_le_bytes());
        b[o + 108..o + 112].copy_from_slice(&16u32.to_le_bytes());
        b[o + 144..o + 148].copy_from_slice(&0x220u32.to_le_bytes());
        b[o + 148..o + 152].copy_from_slice(&0x10u32.to_le_bytes());
        let s = o + 0xf0;
        b[s + 16..s + 20].copy_from_slice(&0x20u32.to_le_bytes());
        b[s + 20..s + 24].copy_from_slice(&0x200u32.to_le_bytes());
        b
    }
    #[test]
    fn exclusions_and_covered_content() {
        let b = image();
        let h = authenticode_sha256(&b[..]).unwrap();
        let mut x = b.clone();
        x[0x98 + 64] = 7;
        x[0x220] = 3;
        assert_eq!(h, authenticode_sha256(&x[..]).unwrap());
        x[0x210] = 1;
        assert_ne!(h, authenticode_sha256(&x[..]).unwrap());
    }
    #[test]
    fn rejects_truncation_and_gaps() {
        let b = image();
        for n in 0..b.len() {
            assert!(authenticode_sha256(&b[..n]).is_err());
        }
        let mut x = b;
        x[0x98 + 0xf0 + 20..0x98 + 0xf0 + 24].copy_from_slice(&0x201u32.to_le_bytes());
        assert!(authenticode_sha256(&x[..]).is_err());
    }
}
