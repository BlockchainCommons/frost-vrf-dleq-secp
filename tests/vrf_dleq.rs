use std::collections::BTreeMap;

use frost::{rand_core::OsRng, round1};
use frost_secp256k1_tr as frost;
use frost_vrf_dleq_secp::{
    hash_to_curve, point_bytes, vrf_gamma_and_proof_for_x, vrf_verify_for_x,
};
use k256::{ProjectivePoint, Scalar};

#[test]
fn vrf_and_dleq_with_group_secret_x() {
    // ----- Keygen (trusted dealer) -----
    let mut rng = OsRng;
    let max = 5u16;
    let min = 3u16;

    let (shares, pubkey_pkg) = frost::keys::generate_with_dealer(
        max,
        min,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )
    .expect("keygen ok");

    // Materialize KeyPackages (what participants actually store)
    let mut key_packages: BTreeMap<frost::Identifier, frost::keys::KeyPackage> =
        BTreeMap::new();
    for (id, secret_share) in shares {
        let kp = frost::keys::KeyPackage::try_from(secret_share)
            .expect("share->KeyPackage");
        key_packages.insert(id, kp);
    }

    // Choose exactly `min` signers: 1,2,3 (not strictly needed for this test,
    // but we mirror a real signing roster).
    let chosen: Vec<frost::Identifier> =
        (1..=min).map(|i| i.try_into().unwrap()).collect();

    // ----- Round 1: each chosen signer commits (not used directly here, but
    // included to demonstrate realistic flow in a FROST-controlled system)
    // -----
    let mut _nonces: BTreeMap<frost::Identifier, round1::SigningNonces> =
        BTreeMap::new();
    let mut _comms: BTreeMap<frost::Identifier, round1::SigningCommitments> =
        BTreeMap::new();
    for id in &chosen {
        let kp = &key_packages[id];
        let (sn, sc) = frost::round1::commit(kp.signing_share(), &mut rng);
        _nonces.insert(*id, sn);
        _comms.insert(*id, sc);
    }

    // Group verifying key (X) as a point
    let group_vk = pubkey_pkg.verifying_key();
    let x_point = group_vk.to_element();

    // TEST-ONLY: reconstruct the group secret key x from exactly `min` shares
    let recon_input: Vec<frost::keys::KeyPackage> =
        chosen.iter().map(|i| key_packages[i].clone()).collect();
    let signing_key =
        frost::keys::reconstruct(&recon_input).expect("reconstruct x");
    // Extract scalar
    let mut x: Scalar = signing_key.to_scalar();

    // Normalize x so that x·G == X (if needed, flip sign)
    let x_raw_point = ProjectivePoint::GENERATOR * x;
    if x_raw_point != x_point {
        let x_neg = -x;
        let x_neg_point = ProjectivePoint::GENERATOR * x_neg;
        assert_eq!(
            x_neg_point, x_point,
            "reconstructed x does not match group key up to sign"
        );
        x = x_neg;
    }
    // Post-condition
    assert_eq!(ProjectivePoint::GENERATOR * x, x_point, "x*G must equal X");

    // ----- VRF over message m -----
    let m = b"PM: FROST-controlled chain, demo mark_j";
    let h_point = hash_to_curve(m);

    // Γ = x·H(m), plus DLEQ proof that log_G(X) = log_H(Γ)
    let (gamma, proof) = vrf_gamma_and_proof_for_x(&x, &x_point, &h_point);

    // Public verification
    vrf_verify_for_x(&x_point, &h_point, &gamma, &proof)
        .expect("DLEQ must verify");

    // Sanity assertions
    assert_ne!(x_point, ProjectivePoint::IDENTITY);
    assert_eq!(point_bytes(&x_point).unwrap().len(), 33);
    assert_ne!(gamma, ProjectivePoint::IDENTITY);
}
