use std::collections::BTreeMap;

use chrono::TimeZone;
use dcbor::Date;
use frost_secp256k1_tr as frost;
use frost_secp256k1_tr::Group;
use frost_vrf_dleq_secp::{
    hash_to_curve, key_from_gamma, normalize_secret_to_pubkey, pm_message,
    ratchet_state, vrf_gamma_and_proof_for_x, vrf_verify_for_x, DleqProof,
};
use k256::ProjectivePoint;
use provenance_mark as pm;
use sha2::{Digest, Sha256};

/// Wrapper that pairs a ProvenanceMark with the VRF output and proof for its
/// `next_key`.
#[derive(Clone, Debug)]
struct EnhancedMark {
    mark: pm::ProvenanceMark,
    gamma_next_bytes: [u8; 33], // SEC1 compressed Γ_{j+1}
    proof_next: DleqProof,      // DLEQ that log_G(X) = log_H(Γ_{j+1})
}

fn dealer_keygen(
    n: u16,
    t: u16,
) -> (
    BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    frost::keys::PublicKeyPackage,
) {
    let rng = rand::rngs::OsRng;
    let (shares, pubkeys) = frost::keys::generate_with_dealer(
        n,
        t,
        frost::keys::IdentifierList::Default,
        rng,
    )
    .expect("keygen");
    let mut kp = BTreeMap::new();
    for (id, secret_share) in shares {
        kp.insert(
            id,
            frost::keys::KeyPackage::try_from(secret_share).expect("share->kp"),
        );
    }
    (kp, pubkeys)
}

/// Deterministic, roster‑invariant chain id of the exact link length.
/// CHAIN_ID = H("PM-CHAIN-ID" || X || label)[0..link_length]
fn make_chain_id(
    res: pm::ProvenanceMarkResolution,
    x_point: &ProjectivePoint,
    label: &str,
) -> Vec<u8> {
    let x_bytes =
        <frost::Secp256K1Sha256TR as frost::Ciphersuite>::Group::serialize(
            x_point,
        )
        .expect("X encodable");
    let mut h = Sha256::new();
    h.update(b"PM-CHAIN-ID");
    h.update(x_bytes);
    h.update(label.as_bytes());
    let d = h.finalize();
    d[..res.link_length()].to_vec()
}

/// Expand a public (truncated) PM key into 32 bytes for the ratchet:
/// K32 = H("PM-KEY32" || key_trunc)
fn expand_key_to_32(key_trunc: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"PM-KEY32");
    h.update(key_trunc);
    let out = h.finalize();
    let mut a = [0u8; 32];
    a.copy_from_slice(&out);
    a
}

/// Build a chain of `steps` marks at a given resolution, producing
/// EnhancedMarks. Public ratchet:
///   S_0 = H("PM-Genesis")
///   For j >= 0:
///     msg_{j+1} = pm_message(X, chain_id, S_j, j+1)
///     Γ_{j+1} = x·H(msg_{j+1}), key_{j+1} = H(Γ_{j+1})[0..L]
///     S_{j+1} = Ratchet(S_j, Expand(key_{j+1}))
fn build_chain_with_proof(
    key_packages: &BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    pubkeys: &frost::keys::PublicKeyPackage,
    res: pm::ProvenanceMarkResolution,
    label: &str,
    steps: usize,
) -> (Vec<EnhancedMark>, Vec<u8>) {
    // Group key
    let x_point = pubkeys.verifying_key().to_element();

    // Reconstruct the signing secret x from any quorum of size t.
    let t = 3u16; // using 3-of-5 throughout here
    let quorum: Vec<_> = (1u16..=t)
        .map(|i| frost::Identifier::try_from(i).unwrap())
        .collect();
    let recon_input: Vec<_> =
        quorum.iter().map(|id| key_packages[id].clone()).collect();
    let signing_key =
        frost::keys::reconstruct(&recon_input).expect("reconstruct x");

    // Normalize x to the (Taproot even‑Y) X
    let x = normalize_secret_to_pubkey(signing_key.to_scalar(), &x_point);

    // Fixed date (monotone non-decreasing is sufficient for `precedes`)
    let date = Date::from_datetime(
        chrono::Utc
            .with_ymd_and_hms(2025, 1, 1, 0, 0, 0)
            .single()
            .expect("valid timestamp"),
    );

    // Public, deterministic chain id (length L depends on resolution)
    let chain_id = make_chain_id(res, &x_point, label);

    // Public genesis state S_0
    let mut s = {
        let mut h = Sha256::new();
        h.update(b"PM-Genesis");
        let out = h.finalize();
        let mut a = [0u8; 32];
        a.copy_from_slice(&out);
        a
    };

    // Prepare output
    let mut out: Vec<EnhancedMark> = Vec::with_capacity(steps);

    // Build marks j = 0 .. steps-1
    // ‣ mark_0 is genesis: key_0 == chain_id; next_key_0 == key_1 from
    // VRF(msg_1).
    let mut current_key_trunc = chain_id.clone(); // key_j, truncated to link length

    for j in 0..steps {
        // Compute next_key_{j} (i.e., key_{j+1}) from VRF over msg_{j+1}
        let msg_next = pm_message(&x_point, &chain_id, &s, (j as u64) + 1);
        let h_point = hash_to_curve(&msg_next);
        let (gamma_next, proof_next) =
            vrf_gamma_and_proof_for_x(&x, &x_point, &h_point);

        // key_{j+1}, truncated to the resolution link length
        let full_k_next = key_from_gamma(&gamma_next);
        let k_next_trunc = full_k_next[..res.link_length()].to_vec();

        // Create the mark_j with key_j and next_key_j
        let mark_j = pm::ProvenanceMark::new(
            res,
            current_key_trunc.clone(),
            k_next_trunc.clone(),
            chain_id.clone(),
            j as u32,
            date.clone(),
            Option::<dcbor::CBOR>::None, /* keep info application-defined
                                          * for now */
        )
        .expect("construct mark");

        // Stash EnhancedMark with Γ_{j+1} and its DLEQ proof
        let gamma_next_bytes = {
            let enc = <frost::Secp256K1Sha256TR as frost::Ciphersuite>::Group::serialize(&gamma_next)
                .expect("Γ encodable");
            let mut arr = [0u8; 33];
            arr.copy_from_slice(&enc);
            arr
        };

        out.push(EnhancedMark { mark: mark_j, gamma_next_bytes, proof_next });

        // Ratchet S_{j+1} publicly from truncated next_key
        let key32 = expand_key_to_32(&k_next_trunc);
        s = ratchet_state(&s, &key32);

        // Next loop: key_j <- key_{j+1} (public, truncated)
        current_key_trunc = k_next_trunc;
    }

    (out, chain_id)
}

/// End-to-end chain test at the given resolution (100 marks)
fn run_resolution(res: pm::ProvenanceMarkResolution, label: &str) {
    let n = 5u16;
    let t = 3u16;
    let (key_packages, pubkeys) = dealer_keygen(n, t);

    let steps = 100usize;
    let (enhanced, chain_id) =
        build_chain_with_proof(&key_packages, &pubkeys, res, label, steps);

    // 1) Basic PM invariants: genesis + sequence validity
    assert_eq!(enhanced.len(), steps);
    assert!(
        enhanced[0].mark.is_genesis(),
        "seq=0 must be genesis (key==chain_id)"
    );
    // check key bytes length equals link length for this resolution
    assert_eq!(enhanced[0].mark.chain_id().len(), res.link_length());
    assert_eq!(enhanced[0].mark.key().len(), res.link_length());
    assert_eq!(enhanced[0].mark.hash().len(), res.link_length());

    // `precedes` must hold pairwise, and the entire chain must be valid
    for w in enhanced.windows(2) {
        assert!(
            w[0].mark.precedes(&w[1].mark),
            "pairwise precedes must hold"
        );
    }
    let marks_only: Vec<_> = enhanced.iter().map(|e| e.mark.clone()).collect();
    assert!(pm::ProvenanceMark::is_sequence_valid(&marks_only));

    // 2) Verify every DLEQ proof for the nextKey And check that computed
    //    key_{j+1} matches mark_{j+1}.key()
    let x_point = pubkeys.verifying_key().to_element();
    let mut s = {
        let mut h = Sha256::new();
        h.update(b"PM-Genesis");
        let out = h.finalize();
        let mut a = [0u8; 32];
        a.copy_from_slice(&out);
        a
    };

    for (j, pair) in enhanced.iter().enumerate() {
        // msg_{j+1} and H for the public ratchet S_j
        let msg_next = pm_message(&x_point, &chain_id, &s, (j as u64) + 1);
        let h_point = hash_to_curve(&msg_next);

        // Decode Γ_{j+1} and verify DLEQ
        let gamma_next =
            frost_vrf_dleq_secp::point_from_bytes(&pair.gamma_next_bytes)
                .expect("decode Γ");
        vrf_verify_for_x(&x_point, &h_point, &gamma_next, &pair.proof_next)
            .expect("DLEQ verify");

        // key_{j+1} from Γ_{j+1}, truncated to resolution; check against next
        // mark's key if it exists
        if j + 1 < enhanced.len() {
            let k_next_full = key_from_gamma(&gamma_next);
            let k_next_trunc = &k_next_full[..res.link_length()];
            assert_eq!(
                enhanced[j + 1].mark.key(),
                k_next_trunc,
                "derived key_{} must equal mark_{}.key",
                j + 1,
                j + 1
            );
        }

        // S_{j+1}
        let k_next_full = key_from_gamma(&gamma_next);
        let k_next_trunc = &k_next_full[..res.link_length()];
        let k32 = expand_key_to_32(k_next_trunc);
        s = ratchet_state(&s, &k32);
    }
}

#[test]
fn pm_integration_all_resolutions_100_marks() {
    // Covers all four PM resolutions as defined by the crate. 100 marks each.
    // Low, Medium, Quartile, High ⇒ link lengths: 4, 8, 16, 32 bytes.
    // :contentReference[oaicite:3]{index=3}
    run_resolution(pm::ProvenanceMarkResolution::Low, "low");
    run_resolution(pm::ProvenanceMarkResolution::Medium, "medium");
    run_resolution(pm::ProvenanceMarkResolution::Quartile, "quartile");
    run_resolution(pm::ProvenanceMarkResolution::High, "high");
}
