use std::collections::{BTreeMap, HashSet};

use frost_secp256k1_tr as frost;
use k256::Scalar;
use sha2::{Digest, Sha256};

use frost_vrf_dleq_secp::{
    hash_to_curve, key_from_gamma, normalize_secret_to_pubkey, pm_message, ratchet_state,
    vrf_gamma_and_proof_for_x, vrf_verify_for_x,
};

fn dealer_keygen(n: u16, t: u16) -> (BTreeMap<frost::Identifier, frost::keys::KeyPackage>, frost::keys::PublicKeyPackage)
{
    let mut rng = rand::rngs::OsRng;
    let (shares, pubkeys) = frost::keys::generate_with_dealer(
        n,
        t,
        frost::keys::IdentifierList::Default,
        &mut rng,
    ).expect("keygen");
    let mut kp = BTreeMap::new();
    for (id, secret_share) in shares {
        kp.insert(id, frost::keys::KeyPackage::try_from(secret_share).expect("share->kp"));
    }
    (kp, pubkeys)
}

/// Build K steps of the PM chain using a chosen quorum to reconstruct x each step.
/// Returns the vector of keys and the final state.
fn build_chain_with_quorum(
    key_packages: &BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    pubkeys: &frost::keys::PublicKeyPackage,
    chain_id: &[u8],
    quorum: &[frost::Identifier],
    steps: usize,
) -> (Vec<[u8;32]>, [u8;32])
{
    let group_vk = pubkeys.verifying_key();
    let x_point = group_vk.to_element();
    // Define S_0 deterministically from a public constant; no PRNG/seed involved.
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
        // TEST-ONLY: reconstruct x from THIS quorum (rostering can change per step)
        let recon_input: Vec<_> = quorum.iter().map(|id| key_packages[id].clone()).collect();
        let signing_key = frost::keys::reconstruct(&recon_input).expect("reconstruct x");
        let x_raw: Scalar = signing_key.to_scalar();
        let x = normalize_secret_to_pubkey(x_raw, &x_point);

        // Build VRF message and compute Γ = x·H(m); also produce a DLEQ proof and verify it.
        let msg = pm_message(&x_point, chain_id, &state, j as u64);
        let h_point = hash_to_curve(&msg);
        let (gamma, proof) = vrf_gamma_and_proof_for_x(&x, &x_point, &h_point);
        vrf_verify_for_x(&x_point, &h_point, &gamma, &proof).expect("DLEQ must verify");

        // Derive key_j and ratchet state
        let key_j = key_from_gamma(&gamma);
        state = ratchet_state(&state, &key_j);

        keys.push(key_j);
    }

    (keys, state)
}

#[test]
fn pm_chain_deterministic_and_roster_invariant() {
    let n = 5;
    let t = 3;
    let (key_packages, pubkeys) = dealer_keygen(n, t);

    let chain_id = b"example-chain";

    // Two different 3-of-5 quorums: {1,2,3} and {1,3,5}
    let quorum_a: Vec<_> = vec![1u16,2,3].into_iter().map(|i| frost::Identifier::try_from(i).unwrap()).collect();
    let quorum_b: Vec<_> = vec![1u16,3,5].into_iter().map(|i| frost::Identifier::try_from(i).unwrap()).collect();

    // Build the same 64-step chain with two different quorums.
    let (keys_a, state_a) = build_chain_with_quorum(&key_packages, &pubkeys, chain_id, &quorum_a, 64);
    let (keys_b, state_b) = build_chain_with_quorum(&key_packages, &pubkeys, chain_id, &quorum_b, 64);

    // (2) Deterministic: building the chain twice with the same inputs yields the same outputs.
    // We assert that both runs (with different quorums) match *each other* step-for-step:
    assert_eq!(keys_a, keys_b, "keys must be deterministic and roster-invariant");
    assert_eq!(state_a, state_b, "final ratchet state must match across quorums");

    // Also re-run A to confirm pure determinism (same quorum twice)
    let (keys_a2, state_a2) = build_chain_with_quorum(&key_packages, &pubkeys, chain_id, &quorum_a, 64);
    assert_eq!(keys_a, keys_a2, "re-running with same quorum must give identical keys");
    assert_eq!(state_a, state_a2, "re-running with same quorum must give identical state");
}

#[test]
fn pm_chain_basic_randomness_checks() {
    let n = 5;
    let t = 3;
    let (key_packages, pubkeys) = dealer_keygen(n, t);
    let chain_id = b"randomness-check";

    // One quorum is enough to test distribution
    let quorum: Vec<_> = vec![1u16,3,5].into_iter().map(|i| frost::Identifier::try_from(i).unwrap()).collect();

    // Generate 512 keys (enough to get a half-million bits for monobit test)
    let steps = 512usize;
    let (keys, _state) = build_chain_with_quorum(&key_packages, &pubkeys, chain_id, &quorum, steps);

    // 1) Monobit test across all key bits (~512 * 256 = 131,072 bytes = 1,048,576 bits)
    let mut ones: u64 = 0;
    let mut total_bits: u64 = 0;
    for k in &keys {
        for b in k {
            ones += b.count_ones() as u64;
            total_bits += 8;
        }
    }
    let frac = (ones as f64) / (total_bits as f64);
    // Accept a very loose window around 50% (±1%); expected stdev is ~0.07% at this N.
    assert!(
        (0.49..=0.51).contains(&frac),
        "monobit frequency should be ~50% ones, got {:.4}%",
        100.0 * frac
    );

    // 2) Collision check: keys should all be unique at this small N
    let mut set = HashSet::with_capacity(steps);
    for k in &keys {
        set.insert(k);
    }
    assert_eq!(set.len(), steps, "no duplicate keys expected at this size");
}
