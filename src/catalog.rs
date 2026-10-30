//! Limited, read-only inspection of a PKCS#7 catalog envelope.
use sha2::{Digest, Sha256};
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

/// Check a single signer's SHA-256 authenticated content digest. This does not
/// verify the signature or certificate and therefore does not authenticate data.
pub fn check_content_digest(reader: impl Read) -> io::Result<bool> {
    let mut data = Vec::new();
    reader.take(LIMIT + 1).read_to_end(&mut data)?;
    if data.len() as u64 > LIMIT {
        return Err(bad("catalog exceeds 16 MiB limit"));
    }
    let envelope = inspect(&data[..])?;
    if envelope.content_type != "1.3.6.1.4.1.311.10.1" || envelope.signer_records != 1 {
        return Err(bad("expected a catalog with one signer"));
    }
    let mut outer = only(&data, 0x30)?;
    element(&mut outer, 6)?;
    let mut signed = only(element(&mut outer, 0xa0)?, 0x30)?;
    element(&mut signed, 2)?;
    element(&mut signed, 0x31)?;
    let mut content = element(&mut signed, 0x30)?;
    element(&mut content, 6)?;
    let ctl = only(element(&mut content, 0xa0)?, 0x30)?;
    if !content.is_empty() {
        return Err(bad("unexpected catalog content"));
    }
    if signed.first() == Some(&0xa0) {
        element(&mut signed, 0xa0)?;
    }
    if signed.first() == Some(&0xa1) {
        element(&mut signed, 0xa1)?;
    }
    let mut signer = only(element(&mut signed, 0x31)?, 0x30)?;
    if element(&mut signer, 2)? != [1] {
        return Err(bad("unsupported signer version"));
    }
    element(&mut signer, 0x30)?; // issuer and serial: opaque until signature verification
    let mut algorithm = element(&mut signer, 0x30)?;
    if oid(element(&mut algorithm, 6)?)? != "2.16.840.1.101.3.4.2.1" {
        return Err(bad("unsupported signer digest algorithm"));
    }
    if !algorithm.is_empty() && !element(&mut algorithm, 5)?.is_empty() {
        return Err(bad("invalid digest parameters"));
    }
    if !algorithm.is_empty() {
        return Err(bad("unexpected digest parameters"));
    }
    let mut attributes = element(&mut signer, 0xa0)?;
    let mut found_digest: Option<&[u8]> = None;
    let mut found_type = false;
    while !attributes.is_empty() {
        let mut attr = element(&mut attributes, 0x30)?;
        let id = oid(element(&mut attr, 6)?)?;
        let values = element(&mut attr, 0x31)?;
        if !attr.is_empty() {
            return Err(bad("unexpected attribute fields"));
        }
        match id.as_str() {
            "1.2.840.113549.1.9.3" => {
                if found_type || oid(only(values, 6)?)? != envelope.content_type {
                    return Err(bad("duplicate or incorrect content type attribute"));
                }
                found_type = true;
            }
            "1.2.840.113549.1.9.4" => {
                let value = only(values, 4)?;
                if found_digest.is_some() || value.len() != 32 {
                    return Err(bad("duplicate or invalid message digest attribute"));
                }
                found_digest = Some(value);
            }
            _ => {}
        }
    }
    if !found_type {
        return Err(bad("missing content type attribute"));
    }
    let expected = found_digest.ok_or_else(|| bad("missing message digest attribute"))?;
    element(&mut signer, 0x30)?; // signature algorithm
    if element(&mut signer, 4)?.is_empty() {
        return Err(bad("empty signature"));
    }
    if signer.first() == Some(&0xa1) {
        element(&mut signer, 0xa1)?;
    }
    if !signer.is_empty() {
        return Err(bad("unexpected signer fields"));
    }
    let actual = Sha256::digest(ctl);
    Ok(actual.as_slice() == expected)
}

fn raw_element<'a>(input: &mut &'a [u8], tag: u8) -> io::Result<&'a [u8]> {
    let before = *input;
    element(input, tag)?;
    Ok(&before[..before.len() - input.len()])
}

/// Verify a single SHA-256/RSA PKCS#1 v1.5 signer against its embedded
/// certificate. This validates the mathematical signature and the CTL digest,
/// but not the certificate's chain, identity, validity, revocation or policy.
pub fn verify_embedded_signer(reader: impl Read) -> io::Result<()> {
    use rsa::traits::PublicKeyParts;
    use rsa::{
        RsaPublicKey,
        pkcs1v15::{Signature, VerifyingKey},
        pkcs8::DecodePublicKey,
        signature::Verifier,
    };
    let mut data = Vec::new();
    reader.take(LIMIT + 1).read_to_end(&mut data)?;
    if data.len() as u64 > LIMIT {
        return Err(bad("catalog exceeds 16 MiB limit"));
    }
    if !check_content_digest(&data[..])? {
        return Err(bad("catalog content digest mismatch"));
    }
    let mut outer = only(&data, 0x30)?;
    element(&mut outer, 6)?;
    let mut signed = only(element(&mut outer, 0xa0)?, 0x30)?;
    element(&mut signed, 2)?;
    element(&mut signed, 0x31)?;
    element(&mut signed, 0x30)?;
    let mut certificates = element(&mut signed, 0xa0)?;
    if signed.first() == Some(&0xa1) {
        element(&mut signed, 0xa1)?;
    }
    let mut signer = only(element(&mut signed, 0x31)?, 0x30)?;
    element(&mut signer, 2)?;
    let mut issuer_serial = element(&mut signer, 0x30)?;
    let issuer = raw_element(&mut issuer_serial, 0x30)?;
    let serial = raw_element(&mut issuer_serial, 2)?;
    if !issuer_serial.is_empty() {
        return Err(bad("invalid signer identifier"));
    }
    element(&mut signer, 0x30)?;
    let attrs = raw_element(&mut signer, 0xa0)?;
    let mut attrs_der = attrs.to_vec();
    attrs_der[0] = 0x31;
    let mut algorithm = element(&mut signer, 0x30)?;
    if oid(element(&mut algorithm, 6)?)? != "1.2.840.113549.1.1.1" {
        return Err(bad("unsupported signature algorithm"));
    }
    if !algorithm.is_empty() && !element(&mut algorithm, 5)?.is_empty() {
        return Err(bad("invalid signature algorithm parameters"));
    }
    if !algorithm.is_empty() {
        return Err(bad("unexpected signature algorithm parameters"));
    }
    let signature =
        Signature::try_from(element(&mut signer, 4)?).map_err(|_| bad("invalid RSA signature"))?;
    let mut key_der = None;
    while !certificates.is_empty() {
        let mut cert = element(&mut certificates, 0x30)?;
        let mut tbs = element(&mut cert, 0x30)?;
        if tbs.first() == Some(&0xa0) {
            element(&mut tbs, 0xa0)?;
        }
        let cert_serial = raw_element(&mut tbs, 2)?;
        element(&mut tbs, 0x30)?;
        let cert_issuer = raw_element(&mut tbs, 0x30)?;
        element(&mut tbs, 0x30)?; // validity
        element(&mut tbs, 0x30)?; // subject
        let spki = raw_element(&mut tbs, 0x30)?;
        if cert_serial == serial && cert_issuer == issuer && key_der.replace(spki).is_some() {
            return Err(bad("ambiguous signer certificates"));
        }
    }
    let key_bytes = key_der.ok_or_else(|| bad("signer certificate not found"))?;
    if key_bytes.len() > 2048 {
        return Err(bad("signer key encoding exceeds limit"));
    }
    let key = RsaPublicKey::from_public_key_der(key_bytes)
        .map_err(|_| bad("unsupported signer public key"))?;
    if !(2048..=4096).contains(&key.n().bits()) {
        return Err(bad("unsupported signer RSA key size"));
    }
    VerifyingKey::<Sha256>::new(key)
        .verify(&attrs_der, &signature)
        .map_err(|_| bad("catalog signer signature mismatch"))
}

struct CertificateParts<'a> {
    tbs: &'a [u8],
    issuer: &'a [u8],
    subject: &'a [u8],
    serial: &'a [u8],
    spki: &'a [u8],
    algorithm: &'a [u8],
    signature: &'a [u8],
}
fn certificate_parts(raw: &[u8]) -> io::Result<CertificateParts<'_>> {
    let mut cert = only(raw, 0x30)?;
    let tbs = raw_element(&mut cert, 0x30)?;
    let algorithm = raw_element(&mut cert, 0x30)?;
    let bits = element(&mut cert, 3)?;
    if !cert.is_empty() || bits.len() < 2 || bits[0] != 0 {
        return Err(bad("invalid certificate signature"));
    }
    let mut fields = only(tbs, 0x30)?;
    if fields.first() == Some(&0xa0) {
        element(&mut fields, 0xa0)?;
    }
    let serial = raw_element(&mut fields, 2)?;
    let inner_algorithm = raw_element(&mut fields, 0x30)?;
    if inner_algorithm != algorithm {
        return Err(bad("certificate signature algorithms differ"));
    }
    let issuer = raw_element(&mut fields, 0x30)?;
    element(&mut fields, 0x30)?;
    let subject = raw_element(&mut fields, 0x30)?;
    let spki = raw_element(&mut fields, 0x30)?;
    Ok(CertificateParts {
        tbs,
        issuer,
        subject,
        serial,
        spki,
        algorithm,
        signature: &bits[1..],
    })
}
fn verify_certificate_link(
    child: &CertificateParts<'_>,
    issuer: &CertificateParts<'_>,
) -> io::Result<()> {
    use rsa::{
        RsaPublicKey,
        pkcs1v15::{Signature, VerifyingKey},
        pkcs8::DecodePublicKey,
        signature::Verifier,
        traits::PublicKeyParts,
    };
    if child.issuer != issuer.subject {
        return Err(bad(
            "certificate issuer name does not match supplied issuer subject",
        ));
    }
    let mut algorithm = only(child.algorithm, 0x30)?;
    if oid(element(&mut algorithm, 6)?)? != "1.2.840.113549.1.1.11" {
        return Err(bad("unsupported certificate signature algorithm"));
    }
    if !algorithm.is_empty() && !element(&mut algorithm, 5)?.is_empty() {
        return Err(bad("invalid certificate signature parameters"));
    }
    if !algorithm.is_empty() || issuer.spki.len() > 2048 {
        return Err(bad("unsupported certificate signature or key"));
    }
    let key = RsaPublicKey::from_public_key_der(issuer.spki)
        .map_err(|_| bad("unsupported issuer public key"))?;
    if !(2048..=4096).contains(&key.n().bits()) {
        return Err(bad("unsupported issuer RSA key size"));
    }
    let signature =
        Signature::try_from(child.signature).map_err(|_| bad("invalid certificate signature"))?;
    VerifyingKey::<Sha256>::new(key)
        .verify(child.tbs, &signature)
        .map_err(|_| bad("certificate signature mismatch"))
}

/// Verify the catalog signer and the signature of its certificate using an
/// embedded issuer certificate. No certificate or trust policy is evaluated.
pub fn verify_embedded_issuer(reader: impl Read) -> io::Result<()> {
    verify_issuer_links(reader, None)
}

/// Check a second certificate signature against the explicitly supplied DER
/// certificate. Its selection, validity, and suitability are not validated.
pub fn verify_issuer_against_certificate(reader: impl Read, anchor: impl Read) -> io::Result<()> {
    let mut anchor_bytes = Vec::new();
    anchor
        .take(1024 * 1024 + 1)
        .read_to_end(&mut anchor_bytes)?;
    if anchor_bytes.len() > 1024 * 1024 {
        return Err(bad("issuer certificate exceeds 1 MiB limit"));
    }
    verify_issuer_links(reader, Some(&anchor_bytes))
}
fn verify_issuer_links(reader: impl Read, anchor: Option<&[u8]>) -> io::Result<()> {
    let mut data = Vec::new();
    reader.take(LIMIT + 1).read_to_end(&mut data)?;
    if data.len() as u64 > LIMIT {
        return Err(bad("catalog exceeds 16 MiB limit"));
    }
    verify_embedded_signer(&data[..])?;
    let mut outer = only(&data, 0x30)?;
    element(&mut outer, 6)?;
    let mut signed = only(element(&mut outer, 0xa0)?, 0x30)?;
    element(&mut signed, 2)?;
    element(&mut signed, 0x31)?;
    element(&mut signed, 0x30)?;
    let mut certificates = element(&mut signed, 0xa0)?;
    let mut certs = Vec::new();
    while !certificates.is_empty() {
        let raw = raw_element(&mut certificates, 0x30)?;
        certs.push(certificate_parts(raw)?);
        if certs.len() > 64 {
            return Err(bad("too many certificates"));
        }
    }
    if signed.first() == Some(&0xa1) {
        element(&mut signed, 0xa1)?;
    }
    let mut signer = only(element(&mut signed, 0x31)?, 0x30)?;
    element(&mut signer, 2)?;
    let mut id = element(&mut signer, 0x30)?;
    let issuer = raw_element(&mut id, 0x30)?;
    let serial = raw_element(&mut id, 2)?;
    if !id.is_empty() {
        return Err(bad("invalid signer identifier"));
    }
    let mut leaves = certs
        .iter()
        .filter(|c| c.issuer == issuer && c.serial == serial);
    let leaf = leaves
        .next()
        .ok_or_else(|| bad("signer certificate not found"))?;
    if leaves.next().is_some() {
        return Err(bad("ambiguous signer certificates"));
    }
    let mut issuers = certs
        .iter()
        .filter(|c| c.subject == leaf.issuer && !std::ptr::eq(*c, leaf));
    let parent = issuers
        .next()
        .ok_or_else(|| bad("embedded issuer certificate not found"))?;
    if issuers.next().is_some() {
        return Err(bad("ambiguous embedded issuer certificates"));
    }
    verify_certificate_link(leaf, parent)?;
    if let Some(anchor) = anchor {
        let anchor = certificate_parts(anchor)?;
        verify_certificate_link(parent, &anchor)?;
    }
    Ok(())
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
