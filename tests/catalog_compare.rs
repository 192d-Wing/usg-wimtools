use rust_image_tool::{catalog, pe};
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    if content.len() < 128 {
        v.push(content.len() as u8);
    } else {
        assert!(content.len() < 256);
        v.extend([0x81, content.len() as u8]);
    }
    v.extend(content);
    v
}
fn image() -> Vec<u8> {
    let mut b = vec![0; 0x220];
    b[..2].copy_from_slice(b"MZ");
    b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    b[0x80..0x84].copy_from_slice(b"PE\0\0");
    b[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
    b[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
    let o = 0x98;
    b[o..o + 2].copy_from_slice(&0x20bu16.to_le_bytes());
    b[o + 60..o + 64].copy_from_slice(&0x200u32.to_le_bytes());
    b[o + 108..o + 112].copy_from_slice(&16u32.to_le_bytes());
    let s = o + 0xf0;
    b[s + 16..s + 20].copy_from_slice(&0x20u32.to_le_bytes());
    b[s + 20..s + 24].copy_from_slice(&0x200u32.to_le_bytes());
    b
}
fn fixture(hash: &[u8], algorithm: u8) -> Vec<u8> {
    let mut ctl = tlv(0x30, &tlv(6, &[43, 6, 1, 4, 1, 130, 55, 12, 1, 1]));
    ctl.extend(tlv(0x17, b"260101000000Z"));
    ctl.extend(tlv(
        0x30,
        &tlv(6, &[43, 6, 1, 4, 1, 130, 55, 12, 1, algorithm]),
    ));
    let mut entry = tlv(4, hash);
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
fn compares_digest_and_rejects_unsupported_inputs() {
    let original = image();
    let hash = pe::authenticode_sha256(&original[..]).unwrap();
    let cat = fixture(&hash, 3);
    assert_eq!(
        catalog::compare_pe(&cat[..], &original[..])
            .unwrap()
            .matches,
        1
    );
    let mut changed = original.clone();
    changed[0x210] = 1;
    assert_eq!(
        catalog::compare_pe(&cat[..], &changed[..]).unwrap().matches,
        0
    );
    assert!(catalog::compare_pe(&fixture(&hash, 4)[..], &original[..]).is_err());
    assert!(catalog::compare_pe(&cat[..], &b"not a PE"[..]).is_err());
    assert!(catalog::compare_pe(&cat[..cat.len() - 1], &original[..]).is_err());
}

fn signed_catalog(payload: &[u8], digest: &[u8], duplicate: bool, content_type: u8) -> Vec<u8> {
    let ctl_oid = [43, 6, 1, 4, 1, 130, 55, 10, 1];
    let mut content = tlv(6, &ctl_oid);
    content.extend(tlv(0xa0, &tlv(0x30, payload)));
    let mut attrs = tlv(6, &[42, 134, 72, 134, 247, 13, 1, 9, 3]);
    let mut type_oid = ctl_oid;
    type_oid[8] = content_type;
    attrs.extend(tlv(0x31, &tlv(6, &type_oid)));
    let mut attrs = tlv(0x30, &attrs);
    let mut md = tlv(6, &[42, 134, 72, 134, 247, 13, 1, 9, 4]);
    md.extend(tlv(0x31, &tlv(4, digest)));
    let md = tlv(0x30, &md);
    attrs.extend(&md);
    if duplicate {
        attrs.extend(&md);
    }
    let mut signer = tlv(2, &[1]);
    signer.extend(tlv(0x30, &[]));
    signer.extend(tlv(0x30, &tlv(6, &[96, 134, 72, 1, 101, 3, 4, 2, 1])));
    signer.extend(tlv(0xa0, &attrs));
    signer.extend(tlv(0x30, &[]));
    signer.extend(tlv(4, &[1]));
    let mut signed = tlv(2, &[1]);
    signed.extend(tlv(0x31, &[]));
    signed.extend(tlv(0x30, &content));
    signed.extend(tlv(0x31, &tlv(0x30, &signer)));
    let mut outer = tlv(6, &[42, 134, 72, 134, 247, 13, 1, 7, 2]);
    outer.extend(tlv(0xa0, &tlv(0x30, &signed)));
    tlv(0x30, &outer)
}
#[test]
fn checks_signer_content_digest_without_claiming_authenticity() {
    use sha2::{Digest, Sha256};
    let payload = [4, 2, 42, 43];
    let digest = Sha256::digest(payload);
    let cat = signed_catalog(&payload, &digest, false, 1);
    assert!(catalog::check_content_digest(&cat[..]).unwrap());
    let changed = signed_catalog(&[4, 2, 42, 44], &digest, false, 1);
    assert!(!catalog::check_content_digest(&changed[..]).unwrap());
    assert!(
        catalog::check_content_digest(&signed_catalog(&payload, &digest, true, 1)[..]).is_err()
    );
    assert!(
        catalog::check_content_digest(&signed_catalog(&payload, &digest, false, 2)[..]).is_err()
    );
    for n in 0..cat.len() {
        assert!(catalog::check_content_digest(&cat[..n]).is_err());
    }
}
