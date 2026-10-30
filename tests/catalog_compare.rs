use usg_wimtools::{catalog, pe};
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    if content.len() < 128 {
        v.push(content.len() as u8);
    } else if content.len() < 256 {
        v.extend([0x81, content.len() as u8]);
    } else {
        assert!(content.len() < 65536);
        v.push(0x82);
        v.extend((content.len() as u16).to_be_bytes());
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

#[test]
fn verifies_embedded_signer_and_rejects_tampering() {
    use rsa::{
        RsaPrivateKey, RsaPublicKey,
        pkcs1v15::SigningKey,
        pkcs8::EncodePublicKey,
        rand_core::OsRng,
        signature::{SignatureEncoding, Signer},
    };
    use sha2::{Digest, Sha256};
    let key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    let spki = RsaPublicKey::from(&key).to_public_key_der().unwrap();
    let issuer = tlv(0x30, &[]);
    let serial = tlv(2, &[5]);
    let cert_alg = tlv(0x30, &tlv(6, &[42, 134, 72, 134, 247, 13, 1, 1, 11]));
    let subject = tlv(0x30, &tlv(2, &[7]));
    let mut tbs = serial.clone();
    tbs.extend(&cert_alg);
    tbs.extend(&issuer);
    tbs.extend(tlv(0x30, &[]));
    tbs.extend(&subject);
    tbs.extend(spki.as_bytes());
    let tbs = tlv(0x30, &tbs);
    let cert_sig = SigningKey::<Sha256>::new(key.clone()).sign(&tbs).to_vec();
    let mut bits = vec![0];
    bits.extend(&cert_sig);
    let mut cert = tbs;
    cert.extend(&cert_alg);
    cert.extend(tlv(3, &bits));
    let cert = tlv(0x30, &cert);
    let mut parent_tbs = tlv(2, &[9]);
    parent_tbs.extend(&cert_alg);
    parent_tbs.extend(tlv(0x30, &tlv(2, &[8])));
    parent_tbs.extend(tlv(0x30, &[]));
    parent_tbs.extend(&issuer);
    parent_tbs.extend(spki.as_bytes());
    let parent_tbs = tlv(0x30, &parent_tbs);
    let parent_sig = SigningKey::<Sha256>::new(key.clone())
        .sign(&parent_tbs)
        .to_vec();
    let mut parent_bits = vec![0];
    parent_bits.extend(&parent_sig);
    let mut parent = parent_tbs;
    parent.extend(&cert_alg);
    parent.extend(tlv(3, &parent_bits));
    let parent = tlv(0x30, &parent);
    let mut root_tbs = tlv(2, &[10]);
    root_tbs.extend(&cert_alg);
    root_tbs.extend(tlv(0x30, &[]));
    root_tbs.extend(tlv(0x30, &[]));
    root_tbs.extend(tlv(0x30, &tlv(2, &[8])));
    root_tbs.extend(spki.as_bytes());
    let mut root = tlv(0x30, &root_tbs);
    root.extend(&cert_alg);
    root.extend(tlv(3, &[0, 1]));
    let root = tlv(0x30, &root);
    let ctl_oid = [43, 6, 1, 4, 1, 130, 55, 10, 1];
    let payload = [4, 2, 42, 43];
    let mut content = tlv(6, &ctl_oid);
    content.extend(tlv(0xa0, &tlv(0x30, &payload)));
    let mut ct = tlv(6, &[42, 134, 72, 134, 247, 13, 1, 9, 3]);
    ct.extend(tlv(0x31, &tlv(6, &ctl_oid)));
    let mut md = tlv(6, &[42, 134, 72, 134, 247, 13, 1, 9, 4]);
    md.extend(tlv(0x31, &tlv(4, &Sha256::digest(payload))));
    let mut attrs = tlv(0x30, &ct);
    attrs.extend(tlv(0x30, &md));
    let sig = SigningKey::<Sha256>::new(key)
        .sign(&tlv(0x31, &attrs))
        .to_vec();
    let mut issuer_serial = issuer;
    issuer_serial.extend(serial);
    let mut signer = tlv(2, &[1]);
    signer.extend(tlv(0x30, &issuer_serial));
    signer.extend(tlv(0x30, &tlv(6, &[96, 134, 72, 1, 101, 3, 4, 2, 1])));
    signer.extend(tlv(0xa0, &attrs));
    signer.extend(tlv(0x30, &tlv(6, &[42, 134, 72, 134, 247, 13, 1, 1, 1])));
    signer.extend(tlv(4, &sig));
    let mut signed = tlv(2, &[1]);
    signed.extend(tlv(0x31, &[]));
    signed.extend(tlv(0x30, &content));
    let mut certificates = cert.clone();
    certificates.extend(parent);
    signed.extend(tlv(0xa0, &certificates));
    signed.extend(tlv(0x31, &tlv(0x30, &signer)));
    let mut outer = tlv(6, &[42, 134, 72, 134, 247, 13, 1, 7, 2]);
    outer.extend(tlv(0xa0, &tlv(0x30, &signed)));
    let cat = tlv(0x30, &outer);
    assert!(catalog::verify_embedded_signer(&cat[..]).is_ok());
    assert!(catalog::verify_embedded_issuer(&cat[..]).is_ok());
    assert!(catalog::verify_issuer_against_certificate(&cat[..], &root[..]).is_ok());
    assert!(catalog::verify_issuer_against_certificate(&cat[..], &cert[..]).is_err());
    assert!(catalog::verify_issuer_against_certificate(&cat[..], &root[..root.len() - 1]).is_err());
    let mut changed_parent = cat.clone();
    let pos = changed_parent
        .windows(parent_sig.len())
        .position(|v| v == parent_sig)
        .unwrap();
    changed_parent[pos] ^= 1;
    assert!(catalog::verify_embedded_issuer(&changed_parent[..]).is_ok());
    assert!(catalog::verify_issuer_against_certificate(&changed_parent[..], &root[..]).is_err());
    let mut changed_cert = cat.clone();
    let pos = changed_cert
        .windows(cert_sig.len())
        .position(|v| v == cert_sig)
        .unwrap();
    changed_cert[pos] ^= 1;
    assert!(catalog::verify_embedded_signer(&changed_cert[..]).is_ok());
    assert!(catalog::verify_embedded_issuer(&changed_cert[..]).is_err());
    let mut changed = cat.clone();
    let pos = changed.windows(sig.len()).position(|v| v == sig).unwrap();
    changed[pos] ^= 1;
    assert!(catalog::verify_embedded_signer(&changed[..]).is_err());
    let mut changed = cat.clone();
    let pos = changed
        .windows(payload.len())
        .position(|v| v == payload)
        .unwrap();
    changed[pos + 3] ^= 1;
    assert!(catalog::verify_embedded_signer(&changed[..]).is_err());
}

#[test]
fn compares_exact_inf_bytes_without_claiming_windows_membership() {
    use sha2::{Digest, Sha256};
    let inf = b"[Version]\r\nSignature=\"$Windows NT$\"\r\n";
    let digest = Sha256::digest(inf);
    let cat = fixture(&digest, 3);
    assert_eq!(
        catalog::compare_inf_bytes(&cat[..], &inf[..])
            .unwrap()
            .matches,
        1
    );
    assert_eq!(
        catalog::compare_inf_bytes(&cat[..], &inf[..inf.len() - 1])
            .unwrap()
            .matches,
        0
    );
    assert!(catalog::compare_inf_bytes(&fixture(&digest, 4)[..], &inf[..]).is_err());
    assert!(catalog::compare_inf_bytes(&cat[..cat.len() - 1], &inf[..]).is_err());
    let huge = vec![0u8; 16 * 1024 * 1024 + 1];
    assert!(catalog::compare_inf_bytes(&cat[..], &huge[..]).is_err());
}

#[test]
fn package_audit_reports_unchecked_files_and_changed_snapshot() {
    use sha2::{Digest, Sha256};
    use std::fs;
    use usg_wimtools::{manifest, package_check};
    let root = std::env::temp_dir().join(format!("catalog-package-test-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let inf = b"[Version]\nCatalogFile=driver.cat\n[Manufacturer]\n%v%=Models,NTamd64.10.0...19041\n[Models.NTamd64.10.0...19041]\n%d%=Install,PCI\\VEN_1234&DEV_5678\n[Install.NTamd64]\nCopyFiles=@driver.sys\n[SourceDisksNames]\n1=Disk,,,\n[SourceDisksFiles.amd64]\ndriver.sys=1\nnotes.txt=1\n[Strings]\nv=Vendor\nd=Device\n";
    fs::write(root.join("driver.inf"), inf).unwrap();
    fs::write(root.join("driver.sys"), image()).unwrap();
    fs::write(root.join("notes.txt"), b"example").unwrap();
    fs::write(root.join("driver.cat"), fixture(&Sha256::digest(inf), 3)).unwrap();
    let snapshot =
        manifest::create(&root.join("driver.inf"), "PCI\\VEN_1234&DEV_5678", 26300).unwrap();
    let report =
        package_check::check(&root, &snapshot, "driver.cat", &b"invalid root"[..]).unwrap();
    assert!(!report.comparisons_match());
    assert!(!report.catalog_link_matches);
    assert!(
        report
            .files
            .iter()
            .any(|f| f.path == "driver.inf" && f.matched)
    );
    assert!(
        report
            .files
            .iter()
            .any(|f| f.path == "driver.sys" && !f.matched)
    );
    assert!(
        report
            .files
            .iter()
            .any(|f| f.path == "notes.txt" && !f.matched && f.result.contains("not implemented"))
    );
    assert!(package_check::check(&root, &snapshot, "other.cat", &b"x"[..]).is_err());
    fs::write(root.join("notes.txt"), b"changed").unwrap();
    assert!(package_check::check(&root, &snapshot, "driver.cat", &b"x"[..]).is_err());
    fs::remove_dir_all(root).unwrap();
}
