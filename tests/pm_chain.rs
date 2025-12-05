use std::collections::BTreeMap;

use frost_secp256k1_tr as frost;
use frost::rand_core::OsRng;
use frost_vrf_dleq_secp::{
    hash_to_curve, key_from_gamma, normalize_secret_to_pubkey, pm_message,
    ratchet_state, vrf_gamma_and_proof_for_x, vrf_verify_for_x,
};
use k256::Scalar;
use nistrs::{prelude::*, BitsData, TEST_THRESHOLD};
use sha2::{Digest, Sha256};

fn dealer_keygen(
    n: u16,
    t: u16,
) -> (
    BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    frost::keys::PublicKeyPackage,
) {
    let rng = OsRng;
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

/// Build K steps of the PM chain using a chosen quorum to reconstruct x each
/// step. Returns the vector of keys and the final state.
fn build_chain_with_quorum(
    key_packages: &BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    pubkeys: &frost::keys::PublicKeyPackage,
    chain_id: &[u8],
    quorum: &[frost::Identifier],
    steps: usize,
) -> (Vec<[u8; 32]>, [u8; 32]) {
    let group_vk = pubkeys.verifying_key();
    let x_point = group_vk.to_element();
    // Define S_0 deterministically from a public constant; no PRNG/seed
    // involved.
    let mut state = {
        let mut h = Sha256::new();
        h.update(b"PM-Genesis");
        let out = h.finalize();
        let mut s = [0u8; 32];
        s.copy_from_slice(&out);
        s
    };

    let mut keys = Vec::with_capacity(steps);

    for j in 1..=steps {
        // TEST-ONLY: reconstruct x from THIS quorum (rostering can change per
        // step)
        let recon_input: Vec<_> =
            quorum.iter().map(|id| key_packages[id].clone()).collect();
        let signing_key =
            frost::keys::reconstruct(&recon_input).expect("reconstruct x");
        let x_raw: Scalar = signing_key.to_scalar();
        let x = normalize_secret_to_pubkey(x_raw, &x_point);

        // Build VRF message and compute Γ = x·H(m); also produce a DLEQ proof
        // and verify it.
        let msg = pm_message(&x_point, chain_id, &state, j as u64);
        let h_point = hash_to_curve(&msg);
        let (gamma, proof) = vrf_gamma_and_proof_for_x(&x, &x_point, &h_point);
        vrf_verify_for_x(&x_point, &h_point, &gamma, &proof)
            .expect("DLEQ must verify");

        // Derive key_j and ratchet state
        let key_j = key_from_gamma(&gamma);
        state = ratchet_state(&state, &key_j);

        keys.push(key_j);
    }

    (keys, state)
}

/// Generate `steps` full 32-byte keys using the FROST-controlled VRF ratchet.
fn generate_keys_for_randomness(
    key_packages: &BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    pubkeys: &frost::keys::PublicKeyPackage,
    steps: usize,
    chain_id: &[u8],
) -> Vec<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let x_point = pubkeys.verifying_key().to_element();
    // reconstruct x once from a valid quorum and normalize to Taproot-even-Y
    // public key
    let quorum: Vec<_> = vec![1u16, 3, 5]
        .into_iter()
        .map(|i| frost::Identifier::try_from(i).unwrap())
        .collect();
    let recon_input: Vec<_> =
        quorum.iter().map(|id| key_packages[id].clone()).collect();
    let signing_key =
        frost::keys::reconstruct(&recon_input).expect("reconstruct x");
    let x = frost_vrf_dleq_secp::normalize_secret_to_pubkey(
        signing_key.to_scalar(),
        &x_point,
    );

    // S0 := H("PM-Genesis")
    let mut s = {
        let mut h = Sha256::new();
        h.update(b"PM-Genesis");
        let out = h.finalize();
        let mut a = [0u8; 32];
        a.copy_from_slice(&out);
        a
    };

    let mut keys = Vec::with_capacity(steps);
    for j in 1..=steps {
        let msg =
            frost_vrf_dleq_secp::pm_message(&x_point, chain_id, &s, j as u64);
        let h_point = frost_vrf_dleq_secp::hash_to_curve(&msg);
        // Γ = x·H(m)
        let gamma = h_point * x;
        let key_j = frost_vrf_dleq_secp::key_from_gamma(&gamma);
        s = frost_vrf_dleq_secp::ratchet_state(&s, &key_j);
        keys.push(key_j);
    }
    keys
}

#[test]
fn pm_chain_deterministic_and_roster_invariant() {
    let n = 5;
    let t = 3;
    let (key_packages, pubkeys) = dealer_keygen(n, t);

    let chain_id = b"example-chain";

    // Two different 3-of-5 quorums: {1,2,3} and {1,3,5}
    let quorum_a: Vec<_> = vec![1u16, 2, 3]
        .into_iter()
        .map(|i| frost::Identifier::try_from(i).unwrap())
        .collect();
    let quorum_b: Vec<_> = vec![1u16, 3, 5]
        .into_iter()
        .map(|i| frost::Identifier::try_from(i).unwrap())
        .collect();

    // Build the same 64-step chain with two different quorums.
    let (keys_a, state_a) = build_chain_with_quorum(
        &key_packages,
        &pubkeys,
        chain_id,
        &quorum_a,
        64,
    );
    let (keys_b, state_b) = build_chain_with_quorum(
        &key_packages,
        &pubkeys,
        chain_id,
        &quorum_b,
        64,
    );

    // (2) Deterministic: building the chain twice with the same inputs yields
    // the same outputs. We assert that both runs (with different quorums)
    // match *each other* step-for-step:
    assert_eq!(
        keys_a, keys_b,
        "keys must be deterministic and roster-invariant"
    );
    assert_eq!(
        state_a, state_b,
        "final ratchet state must match across quorums"
    );

    // Also re-run A to confirm pure determinism (same quorum twice)
    let (keys_a2, state_a2) = build_chain_with_quorum(
        &key_packages,
        &pubkeys,
        chain_id,
        &quorum_a,
        64,
    );
    assert_eq!(
        keys_a, keys_a2,
        "re-running with same quorum must give identical keys"
    );
    assert_eq!(
        state_a, state_a2,
        "re-running with same quorum must give identical state"
    );
}

#[test]
fn pm_chain_nist_randomness_suite() {
    // Build a long sequence: 4,096 keys × 32 bytes = 1,048,576 bits.
    let (key_packages, pubkeys) = dealer_keygen(5, 3);
    let chain_id = b"nist-suite";
    let steps = 8192usize;
    let keys =
        generate_keys_for_randomness(&key_packages, &pubkeys, steps, chain_id);

    // Concatenate to bytes for NIST tests
    let mut bytes = Vec::with_capacity(steps * 32);
    for k in &keys {
        bytes.extend_from_slice(k);
    }
    let data = BitsData::from_binary(bytes);

    // Helper to assert pass + p-value threshold
    let chk = |name: &str, r: TestResultT| {
        assert!(r.0, "NIST {} failed (p = {})", name, r.1);
        assert!(
            r.1 >= TEST_THRESHOLD,
            "NIST {}: p-value {} < {}",
            name,
            r.1,
            TEST_THRESHOLD
        );
    };

    // Core tests (no extra parameters)
    chk("frequency", frequency_test(&data)); // SP 800‑22 §2.1 :contentReference[oaicite:1]{index=1}
    chk("runs", runs_test(&data)); // §2.3 :contentReference[oaicite:2]{index=2}
    chk("fft", fft_test(&data)); // §2.6 :contentReference[oaicite:3]{index=3}
    chk("universal", universal_test(&data)); // §2.8 Maurer :contentReference[oaicite:4]{index=4}

    // Parameterized tests (use standard, sane defaults for long streams)
    chk(
        "block_frequency(m=128)",
        block_frequency_test(&data, 128)
            .expect("block_frequency preconditions"),
    ); // §2.2 :contentReference[oaicite:5]{index=5}
    chk(
        "longest_run_of_ones",
        longest_run_of_ones_test(&data).expect("longest_run preconditions"),
    ); // §2.4 (len > 128) :contentReference[oaicite:6]{index=6}
    chk("rank", rank_test(&data).expect("rank preconditions")); // §2.5 (len > 38912) :contentReference[oaicite:7]{index=7}
    let cu = cumulative_sums_test(&data); // §2.7 (forward & reverse) :contentReference[oaicite:8]{index=8}
    chk("cumulative_sums-forward", cu[0]);
    chk("cumulative_sums-reverse", cu[1]);
    chk(
        "approximate_entropy(m=10)",
        approximate_entropy_test(&data, 10),
    ); // §2.12 :contentReference[oaicite:9]{index=9}
    let se = serial_test(&data, 16); // §2.13 (returns 2 p-values) :contentReference[oaicite:10]{index=10}
    chk("serial(m=16)[0]", se[0]);
    chk("serial(m=16)[1]", se[1]);
    chk(
        "overlapping_template(m=9)",
        overlapping_template_test(&data, 9),
    ); // §2.8 (overlapping) :contentReference[oaicite:11]{index=11}
       // §2.7 Non-overlapping templates return a vector of subtests (many
       // p-values). NIST methodology evaluates pass **rates** across
       // subtests. We allow up to 2% fails.
    let nonov = non_overlapping_template_test(&data, 9)
        .expect("non-overlapping preconditions");
    let mut fail_indices = Vec::new();
    for (i, tr) in nonov.iter().enumerate() {
        let pass = tr.0 && tr.1 >= TEST_THRESHOLD;
        if !pass {
            fail_indices.push((i, tr.1));
        }
    }
    let total = nonov.len();
    let allowed = ((total as f64) * 0.02).ceil() as usize; // <= 2% failures permitted
    assert!(
        fail_indices.len() <= allowed,
        "NIST non_overlapping_template(m=9): {} of {} subtests failed (allow ≤ {}); examples: {:?}",
        fail_indices.len(),
        total,
        allowed,
        &fail_indices[..fail_indices.len().min(5)]
    );

    // These two require enough zero-crossing cycles; if preconditions fail,
    // skip (informative).
    match random_excursions_test(&data) {
        // §2.14 :contentReference[oaicite:13]{index=13}
        Ok(arr) => {
            for (i, tr) in arr.into_iter().enumerate() {
                chk(&format!("random_excursions[{}]", i), tr);
            }
        }
        Err(e) => eprintln!("random_excursions skipped: {}", e),
    }
    match random_excursions_variant_test(&data) {
        // §2.15 :contentReference[oaicite:14]{index=14}
        Ok(arr) => {
            for (i, tr) in arr.into_iter().enumerate() {
                chk(&format!("random_excursions_variant[{}]", i), tr);
            }
        }
        Err(e) => eprintln!("random_excursions_variant skipped: {}", e),
    }
}
