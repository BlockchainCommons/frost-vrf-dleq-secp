//! frost-vrf-dleq-secp
//!
//! Minimal, stand-alone helpers to:
//! 1) Hash-to-curve for a message `m` -> H(m) on secp256k1
//! 2) Compute a VRF output Γ = x·H(m)
//! 3) Prove a DLEQ:  log_G(X) = log_H(Γ)  using a Schnorr-style NIZK
//!
//! This is the construction you’ll use for PM: only the FROST group (who hold
//! x) can produce Γ and the proof; verifiers check the proof publicly against X
//! and H(m).

use core::ops::Add;

use frost::rand_core::OsRng;
use frost_secp256k1_tr as frost;
use frost_secp256k1_tr::Group; // for Group::serialize
use k256::{
    elliptic_curve::{
        hash2curve::{ExpandMsgXmd, GroupDigest},
        sec1::{FromEncodedPoint, ToEncodedPoint},
    },
    AffinePoint, EncodedPoint, ProjectivePoint, Scalar, Secp256k1,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Domain separator for hash-to-curve used here.
const H2C_DST: &[u8] = b"FROST-VRF-secp256k1-SHA256-RO";

/// Domain for our DLEQ transcript hashing (challenge computation).
const DLEQ_DST: &[u8] = b"FROST-VRF-DLEQ-2025";

#[derive(Debug, Error)]
pub enum VrfError {
    #[error("Malformed SEC1 encoding")]
    Sec1,
    #[error("Error: {0}")]
    Generic(String),
}

/// Compact DLEQ proof that log_G(X) = log_H(Gamma).
#[derive(Clone, Debug)]
pub struct DleqProof {
    /// A = k·G (compressed 33-byte SEC1)
    pub a_bytes: [u8; 33],
    /// B = k·H (compressed 33-byte SEC1)
    pub b_bytes: [u8; 33],
    /// e = H( X || Gamma || A || B || DLEQ_DST )
    pub e: Scalar,
    /// z = k + e·x
    pub z: Scalar,
}

/// Return compressed SEC1 (33 bytes) for any projective point (must not be
/// IDENTITY).
pub fn point_bytes(p: &ProjectivePoint) -> Result<[u8; 33], VrfError> {
    let ap: AffinePoint = (*p).to_affine();
    let enc = ap.to_encoded_point(true);
    let bytes = enc.as_bytes();
    if bytes.len() != 33 {
        return Err(VrfError::Sec1);
    }
    let mut out = [0u8; 33];
    out.copy_from_slice(bytes);
    Ok(out)
}

/// Deserialize a compressed 33-byte SEC1 point into `ProjectivePoint`.
pub fn point_from_bytes(bytes: &[u8; 33]) -> Result<ProjectivePoint, VrfError> {
    let enc = EncodedPoint::from_bytes(bytes).map_err(|_| VrfError::Sec1)?;
    let opt_aff = AffinePoint::from_encoded_point(&enc);
    let aff: AffinePoint = match Option::<AffinePoint>::from(opt_aff) {
        Some(p) => p,
        None => return Err(VrfError::Sec1),
    };
    Ok(ProjectivePoint::from(aff))
}

/// Hash-to-curve on secp256k1 (random oracle / SSWU via RustCrypto’s generic
/// impl).
pub fn hash_to_curve(msg: &[u8]) -> ProjectivePoint {
    <Secp256k1 as GroupDigest>::hash_from_bytes::<ExpandMsgXmd<Sha256>>(
        &[msg],
        &[H2C_DST],
    )
    .expect("ExpandMsgXmd never errors under documented bounds")
}

/// Build a DLEQ challenge scalar e = H2(X || Gamma || A || B || DLEQ_DST).
fn dleq_challenge_x(
    x_point: &ProjectivePoint,
    gamma: &ProjectivePoint,
    a: &ProjectivePoint,
    b: &ProjectivePoint,
) -> Scalar {
    let xb =
        <frost::Secp256K1Sha256TR as frost::Ciphersuite>::Group::serialize(
            x_point,
        )
        .unwrap();
    let gb =
        <frost::Secp256K1Sha256TR as frost::Ciphersuite>::Group::serialize(
            gamma,
        )
        .unwrap();
    let ab =
        <frost::Secp256K1Sha256TR as frost::Ciphersuite>::Group::serialize(a)
            .unwrap();
    let bb =
        <frost::Secp256K1Sha256TR as frost::Ciphersuite>::Group::serialize(b)
            .unwrap();

    let mut input = Vec::with_capacity(4 * 33 + DLEQ_DST.len());
    input.extend_from_slice(&xb);
    input.extend_from_slice(&gb);
    input.extend_from_slice(&ab);
    input.extend_from_slice(&bb);
    input.extend_from_slice(DLEQ_DST);

    <frost::Secp256K1Sha256TR as frost::Ciphersuite>::H2(&input)
}

/// Compute Γ = x·H and a DLEQ proof that log_G(X) = log_H(Γ).
pub fn vrf_gamma_and_proof_for_x(
    x: &Scalar,                // witness
    x_point: &ProjectivePoint, // X = x·G
    h_point: &ProjectivePoint, // H = hash_to_curve(m)
) -> (ProjectivePoint, DleqProof) {
    // VRF output Γ = x·H
    let gamma = (*h_point) * (*x);

    // Random nonce k (crypto RNG)
    let k = Scalar::generate_vartime(&mut OsRng);

    // A = k·G, B = k·H
    let a = ProjectivePoint::GENERATOR * k;
    let b = (*h_point) * k;

    // Fiat–Shamir over (X, Gamma, A, B, DST)
    let e = dleq_challenge_x(x_point, &gamma, &a, &b);

    // Response z = k + e·x
    let z = k + e * (*x);

    let a_bytes = point_bytes(&a).expect("A encodable");
    let b_bytes = point_bytes(&b).expect("B encodable");

    (gamma, DleqProof { a_bytes, b_bytes, e, z })
}

/// Verify a DLEQ proof that log_G(X) = log_H(Gamma).
pub fn vrf_verify_for_x(
    x_point: &ProjectivePoint, // X
    h_point: &ProjectivePoint, // H
    gamma: &ProjectivePoint,   // Γ
    proof: &DleqProof,
) -> Result<(), VrfError> {
    let a = point_from_bytes(&proof.a_bytes)?;
    let b = point_from_bytes(&proof.b_bytes)?;

    // Recompute challenge
    let e_chk = dleq_challenge_x(x_point, gamma, &a, &b);
    if e_chk != proof.e {
        return Err(VrfError::Generic("DLEQ challenge mismatch".to_owned()));
    }

    // Check z·G == A + e·X
    let lhs_g = ProjectivePoint::GENERATOR * proof.z;
    let rhs_g = a.add((*x_point) * proof.e);
    if lhs_g != rhs_g {
        return Err(VrfError::Generic("DLEQ G-relation failed".to_owned()));
    }

    // Check z·H == B + e·Γ
    let lhs_h = (*h_point) * proof.z;
    let rhs_h = b.add((*gamma) * proof.e);
    if lhs_h != rhs_h {
        return Err(VrfError::Generic("DLEQ H-relation failed".to_owned()));
    }

    Ok(())
}

/// Build the PM VRF message for step `j`: binds to the group pubkey X,
/// chain_id, the previous state hash `state_prev`, and the step index `j`.
pub fn pm_message(
    x_point: &ProjectivePoint,
    chain_id: &[u8],
    state_prev: &[u8; 32],
    j: u64,
) -> Vec<u8> {
    // Serialize X with the ciphersuite’s Group serializer (33 bytes,
    // compressed)
    let x_bytes =
        <frost::Secp256K1Sha256TR as frost::Ciphersuite>::Group::serialize(
            x_point,
        )
        .expect("X encodable");
    let mut msg = Vec::with_capacity(33 + 8 + 32 + chain_id.len() + 8);
    msg.extend_from_slice(b"PMVRF-secp256k1-v1");
    msg.extend_from_slice(&x_bytes);
    msg.extend_from_slice(chain_id);
    msg.extend_from_slice(state_prev);
    msg.extend_from_slice(&j.to_be_bytes());
    msg
}

/// Derive a 32-byte PM key from Γ by hashing its compressed SEC1 encoding.
pub fn key_from_gamma(gamma: &ProjectivePoint) -> [u8; 32] {
    let g_bytes =
        <frost::Secp256K1Sha256TR as frost::Ciphersuite>::Group::serialize(
            gamma,
        )
        .expect("Gamma encodable");
    let mut h = Sha256::new();
    h.update(b"PMKEY-v1");
    h.update(g_bytes);
    let out = h.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    key
}

/// Ratchet the public state deterministically: S_j = H("PMSTATE" || S_{j-1} ||
/// key_j).
pub fn ratchet_state(state_prev: &[u8; 32], key_j: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"PMSTATE-v1");
    h.update(state_prev);
    h.update(key_j);
    let out = h.finalize();
    let mut s = [0u8; 32];
    s.copy_from_slice(&out);
    s
}

/// Normalize a reconstructed secret scalar so that x*G == X (Taproot even‑Y
/// convention). If x*G == -X, returns -x. Panics if neither matches (should
/// never happen in these tests).
pub fn normalize_secret_to_pubkey(
    mut x: Scalar,
    x_point: &ProjectivePoint,
) -> Scalar {
    let x_raw_point = ProjectivePoint::GENERATOR * x;
    if x_raw_point == *x_point {
        return x;
    }
    let x_neg = -x;
    let x_neg_point = ProjectivePoint::GENERATOR * x_neg;
    assert_eq!(
        x_neg_point, *x_point,
        "reconstructed x does not match group key up to sign"
    );
    x = x_neg;
    x
}
