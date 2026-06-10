//! Default curve type aliases and shared crypto utilities.
//!
//! Change `DefaultCurve` to switch the entire project to a different curve.
//! All downstream modules reference types through these aliases.

use sha2::{Sha256, Digest};
use std::hash::{Hash, Hasher};

use crate::crypto::curve::{Curve, CurvePoint, Bls12381Curve, ElGamalCiphertextGeneric};

/// The default curve used by the project.
/// Change this single line to switch the entire project to a different curve.
pub type DefaultCurve = Bls12381Curve;

pub const N_CARDS: usize = 52;

// ============================================================
// Type aliases derived from DefaultCurve
// ============================================================

pub type EcPoint = <DefaultCurve as Curve>::Point;
pub type Scalar = <DefaultCurve as Curve>::Scalar;
pub type Plaintext = EcPoint;
pub type ElGamalCiphertext = ElGamalCiphertextGeneric<DefaultCurve>;

// ============================================================
// ECPoint wrapper for HashMap keys
// ============================================================

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ECPoint(pub EcPoint);

impl Hash for ECPoint {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.compress().as_ref().hash(state);
    }
}

impl std::ops::Deref for ECPoint {
    type Target = EcPoint;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<EcPoint> for ECPoint {
    fn from(point: EcPoint) -> Self {
        ECPoint(point)
    }
}

impl From<ECPoint> for EcPoint {
    fn from(point: ECPoint) -> Self {
        point.0
    }
}

impl ECPoint {
    pub fn to_affine(&self) -> <EcPoint as CurvePoint>::Compressed {
        self.0.compress()
    }
}

// ============================================================
// Utility functions
// ============================================================

pub fn hash_to_scalar(digest: &[u8]) -> Scalar {
    DefaultCurve::hash_to_scalar(digest)
}

pub fn derive_scalar_from_card_and_sk(user_card: &ElGamalCiphertext, user_sk: &Scalar) -> Scalar {
    let mut h = Sha256::new();
    h.update(b"derive_scalar_from_card_and_sk_v1:");
    h.update((user_card.c1 * user_sk).compress().as_ref());
    h.update((user_card.c2 * user_sk).compress().as_ref());
    let digest = h.finalize();
    hash_to_scalar(&digest)
}

pub fn derive_scalar_from_card_and_pk(user_card: &ElGamalCiphertext, user_pk: &EcPoint) -> Scalar {
    let mut h = Sha256::new();
    h.update(b"derive_scalar_from_card_and_pk_v1:");
    h.update(user_card.c1.compress().as_ref());
    h.update(user_card.c2.compress().as_ref());
    h.update(user_pk.compress().as_ref());
    let digest = h.finalize();
    hash_to_scalar(&digest)
}

lazy_static::lazy_static! {
    pub static ref BASE_G: EcPoint = DefaultCurve::base_g();
}
