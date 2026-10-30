//! Limited, read-only inspection of a PKCS#7 catalog envelope.
use std::io::{self, Read};

const LIMIT: u64 = 16 * 1024 * 1024;
const SIGNED_DATA: &str = "1.2.840.113549.1.7.2";

fn bad(s: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, s)
}

#[derive(Debug, PartialEq, Eq)]
pub struct CatalogEnvelope {
    pub content_type: String,
    pub digest_algorithms: Vec<String>,
    pub certificate_records: usize,
    pub signer_records: usize,
}

fn element<'a>(input: &mut &'a [u8], tag: u8) -> io::Result<&'a [u8]> {
    let b = *input;
    if b.len() < 2 || b[0] != tag {
        return Err(bad("unexpected or truncated DER element"));
    }
    let first = b[1];
    let (header, length) = if first < 128 {
        (2, usize::from(first))
    } else {
        let n = usize::from(first & 127);
        if n == 0 || n > std::mem::size_of::<usize>() || b.len() < 2 + n || b[2] == 0 {
            return Err(bad("invalid DER length"));
        }
        let mut len = 0usize;
        for &v in &b[2..2 + n] {
            len = len
                .checked_mul(256)
                .and_then(|x| x.checked_add(usize::from(v)))
                .ok_or_else(|| bad("DER length overflow"))?;
        }
        if len < 128 {
            return Err(bad("nonminimal DER length"));
        }
        (2 + n, len)
    };
    let end = header
        .checked_add(length)
        .filter(|&n| n <= b.len())
        .ok_or_else(|| bad("truncated DER value"))?;
    *input = &b[end..];
    Ok(&b[header..end])
}
fn only(input: &[u8], tag: u8) -> io::Result<&[u8]> {
    let mut rest = input;
    let value = element(&mut rest, tag)?;
    if !rest.is_empty() {
        return Err(bad("unexpected trailing DER data"));
    }
    Ok(value)
}
fn oid(bytes: &[u8]) -> io::Result<String> {
    let mut arcs = Vec::new();
    let mut value = 0u64;
    let mut active = false;
    for &b in bytes {
        if !active && b == 0x80 {
            return Err(bad("nonminimal OID"));
        }
        active = true;
        value = value
            .checked_mul(128)
            .and_then(|x| x.checked_add(u64::from(b & 127)))
            .ok_or_else(|| bad("OID overflow"))?;
        if b & 128 == 0 {
            arcs.push(value);
            value = 0;
            active = false;
        }
    }
    if active || arcs.is_empty() {
        return Err(bad("invalid OID"));
    }
    let first = arcs[0];
    let a = (first / 40).min(2);
    let mut result = format!("{a}.{}", first - a * 40);
    for arc in &arcs[1..] {
        result.push_str(&format!(".{arc}"));
    }
    Ok(result)
}
fn records(mut input: &[u8]) -> io::Result<usize> {
    let mut count = 0usize;
    while !input.is_empty() {
        element(&mut input, 0x30)?;
        count += 1;
    }
    Ok(count)
}
/// Parse envelope boundaries and selected OIDs. Does not validate nested objects or signatures.
pub fn inspect(reader: impl Read) -> io::Result<CatalogEnvelope> {
    let mut data = Vec::new();
    reader.take(LIMIT + 1).read_to_end(&mut data)?;
    if data.len() as u64 > LIMIT {
        return Err(bad("catalog exceeds 16 MiB limit"));
    }
    let mut outer = only(&data, 0x30)?;
    if oid(element(&mut outer, 0x06)?)? != SIGNED_DATA {
        return Err(bad("not PKCS#7 SignedData"));
    }
    let wrapped = element(&mut outer, 0xa0)?;
    if !outer.is_empty() {
        return Err(bad("unexpected ContentInfo fields"));
    }
    let mut signed = only(wrapped, 0x30)?;
    let version = element(&mut signed, 0x02)?;
    if version != [1] {
        return Err(bad("unsupported SignedData version"));
    }
    let mut digest_set = element(&mut signed, 0x31)?;
    let mut digest_algorithms = Vec::new();
    while !digest_set.is_empty() {
        let mut algorithm = element(&mut digest_set, 0x30)?;
        digest_algorithms.push(oid(element(&mut algorithm, 0x06)?)?);
        // Algorithm parameters are opaque; validate their outer boundary when present.
        if !algorithm.is_empty() {
            let tag = algorithm[0];
            element(&mut algorithm, tag)?;
        }
        if !algorithm.is_empty() {
            return Err(bad("unexpected algorithm fields"));
        }
    }
    let mut content = element(&mut signed, 0x30)?;
    let content_type = oid(element(&mut content, 0x06)?)?;
    if !content.is_empty() {
        element(&mut content, 0xa0)?;
    }
    if !content.is_empty() {
        return Err(bad("unexpected content fields"));
    }
    let certificate_records = if signed.first() == Some(&0xa0) {
        records(element(&mut signed, 0xa0)?)?
    } else {
        0
    };
    if signed.first() == Some(&0xa1) {
        element(&mut signed, 0xa1)?;
    }
    let signer_records = records(element(&mut signed, 0x31)?)?;
    if !signed.is_empty() {
        return Err(bad("unexpected SignedData fields"));
    }
    Ok(CatalogEnvelope {
        content_type,
        digest_algorithms,
        certificate_records,
        signer_records,
    })
}

/// Extract subject identifiers from the supported catalog CTL layout. Attributes,
/// file hashing rules, and signatures are deliberately not interpreted.
pub fn subject_identifiers(reader: impl Read) -> io::Result<(String, Vec<Vec<u8>>)> {
    let mut data = Vec::new();
    reader.take(LIMIT + 1).read_to_end(&mut data)?;
    if data.len() as u64 > LIMIT {
        return Err(bad("catalog exceeds 16 MiB limit"));
    }
    let envelope = inspect(&data[..])?;
    if envelope.content_type != "1.3.6.1.4.1.311.10.1" {
        return Err(bad("not Microsoft CTL content"));
    }
    let mut outer = only(&data, 0x30)?;
    element(&mut outer, 6)?;
    let mut signed = only(element(&mut outer, 0xa0)?, 0x30)?;
    element(&mut signed, 2)?;
    element(&mut signed, 0x31)?;
    let mut content = element(&mut signed, 0x30)?;
    element(&mut content, 6)?;
    let mut ctl = only(element(&mut content, 0xa0)?, 0x30)?;
    // Support the common v1 CTL layout, with optional list ID, sequence and next-update.
    if ctl.first() == Some(&2) && element(&mut ctl, 2)? != [0] {
        return Err(bad("unsupported CTL version"));
    }
    let mut usage = element(&mut ctl, 0x30)?;
    let mut catalog_usage = false;
    while !usage.is_empty() {
        catalog_usage |= oid(element(&mut usage, 6)?)? == "1.3.6.1.4.1.311.12.1.1";
    }
    if !catalog_usage {
        return Err(bad("CTL is not a catalog list"));
    }
    if ctl.first() == Some(&4) {
        element(&mut ctl, 4)?;
    }
    if ctl.first() == Some(&2) {
        element(&mut ctl, 2)?;
    }
    let time = *ctl.first().ok_or_else(|| bad("missing CTL update time"))?;
    if !matches!(time, 0x17 | 0x18) {
        return Err(bad("invalid CTL update time"));
    }
    element(&mut ctl, time)?;
    if matches!(ctl.first(), Some(0x17 | 0x18)) {
        let time = ctl[0];
        element(&mut ctl, time)?;
    }
    let mut algorithm = element(&mut ctl, 0x30)?;
    let subject_algorithm = oid(element(&mut algorithm, 6)?)?;
    if !algorithm.is_empty() {
        let tag = algorithm[0];
        element(&mut algorithm, tag)?;
    }
    if !algorithm.is_empty() {
        return Err(bad("unexpected subject algorithm fields"));
    }
    let mut entries = element(&mut ctl, 0x30)?;
    let mut identifiers = Vec::new();
    while !entries.is_empty() {
        let mut entry = element(&mut entries, 0x30)?;
        let id = element(&mut entry, 4)?;
        if id.is_empty() || id.len() > 128 {
            return Err(bad("unsupported subject identifier length"));
        }
        element(&mut entry, 0x31)?;
        if !entry.is_empty() {
            return Err(bad("unexpected CTL entry fields"));
        }
        identifiers.push(id.to_vec());
        if identifiers.len() > 100_000 {
            return Err(bad("too many CTL entries"));
        }
    }
    if ctl.first() == Some(&0xa0) {
        element(&mut ctl, 0xa0)?;
    }
    if !ctl.is_empty() {
        return Err(bad("unexpected CTL fields"));
    }
    Ok((subject_algorithm, identifiers))
}

/// Compare an experimental PE SHA-256 digest with identifiers in a V2 catalog.
/// A match is unauthenticated and does not establish Windows membership or trust.
pub fn compare_pe(catalog: impl Read, image: impl Read) -> io::Result<PeComparison> {
    let (algorithm, identifiers) = subject_identifiers(catalog)?;
    if algorithm != "1.3.6.1.4.1.311.12.1.3" {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unsupported catalog subject algorithm",
        ));
    }
    let digest = crate::pe::authenticode_sha256(image)?;
    let matches = identifiers
        .iter()
        .filter(|id| id.as_slice() == digest)
        .count();
    Ok(PeComparison { digest, matches })
}

#[derive(Debug, PartialEq, Eq)]
pub struct PeComparison {
    pub digest: [u8; 32],
    pub matches: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        assert!(content.len() < 128);
        let mut out = vec![tag, content.len() as u8];
        out.extend(content);
        out
    }
    fn fixture() -> Vec<u8> {
        let mut signed = tlv(2, &[1]);
        signed.extend(tlv(0x31, &tlv(0x30, &tlv(6, &[42, 3]))));
        signed.extend(tlv(0x30, &tlv(6, &[42, 4])));
        signed.extend(tlv(0xa0, &tlv(0x30, &[])));
        signed.extend(tlv(0x31, &tlv(0x30, &[])));
        let mut outer = tlv(6, &[42, 134, 72, 134, 247, 13, 1, 7, 2]);
        outer.extend(tlv(0xa0, &tlv(0x30, &signed)));
        tlv(0x30, &outer)
    }
    fn catalog_fixture() -> Vec<u8> {
        let usage = tlv(0x30, &tlv(6, &[43, 6, 1, 4, 1, 130, 55, 12, 1, 1]));
        let mut ctl = usage;
        ctl.extend(tlv(0x17, b"260101000000Z"));
        ctl.extend(tlv(0x30, &tlv(6, &[42, 3])));
        let mut entry = tlv(4, &[1, 2, 3]);
        entry.extend(tlv(0x31, &[]));
        ctl.extend(tlv(0x30, &tlv(0x30, &entry)));
        let mut content = tlv(6, &[43, 6, 1, 4, 1, 130, 55, 10, 1]);
        content.extend(tlv(0xa0, &tlv(0x30, &ctl)));
        let mut signed = tlv(2, &[1]);
        signed.extend(tlv(0x31, &[]));
        signed.extend(tlv(0x30, &content));
        signed.extend(tlv(0x31, &[]));
        let mut outer = tlv(6, &[42, 134, 72, 134, 247, 13, 1, 7, 2]);
        outer.extend(tlv(0xa0, &tlv(0x30, &signed)));
        tlv(0x30, &outer)
    }
    #[test]
    fn reads_catalog_subjects_and_rejects_wrong_content() {
        let f = catalog_fixture();
        let (algorithm, entries) = subject_identifiers(&f[..]).unwrap();
        assert_eq!(algorithm, "1.2.3");
        assert_eq!(entries, [vec![1, 2, 3]]);
        assert!(subject_identifiers(&fixture()[..]).is_err());
        for n in 0..f.len() {
            assert!(subject_identifiers(&f[..n]).is_err());
        }
        let mut changed = f.clone();
        let index = changed.windows(3).position(|w| w == [1, 2, 3]).unwrap();
        changed[index - 1] = 0;
        assert!(subject_identifiers(&changed[..]).is_err());
    }
    #[test]
    fn reads_envelope() {
        let r = inspect(&fixture()[..]).unwrap();
        assert_eq!(r.content_type, "1.2.4");
        assert_eq!(r.digest_algorithms, ["1.2.3"]);
        assert_eq!((r.certificate_records, r.signer_records), (1, 1));
    }
    #[test]
    fn rejects_truncation_and_trailing() {
        let f = fixture();
        for n in 0..f.len() {
            assert!(inspect(&f[..n]).is_err());
        }
        let mut f = f;
        f.push(0);
        assert!(inspect(&f[..]).is_err());
    }
    #[test]
    fn rejects_bad_lengths_and_oid() {
        assert!(inspect(&[0x30, 0x80][..]).is_err());
        assert!(inspect(&[0x30, 0x81, 0x01, 0][..]).is_err());
        assert!(oid(&[0x80, 0]).is_err());
        assert!(oid(&[0x81]).is_err());
    }
}
