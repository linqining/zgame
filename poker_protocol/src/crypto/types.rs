//! Default curve type aliases and shared crypto utilities.
//!
//! Change `DefaultCurve` to switch the entire project to a different curve.
//! All downstream modules reference types through these aliases.

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

/// 兼容 Move 合约 bls_scalar::derive_scalar_from_card_and_sk：
/// 输入 c1*sk 和 c2*sk 的压缩字节，直接拼接后 hash_to_scalar。
/// 无域名分隔符前缀，无 SHA-256 预哈希（Move 端只有一层 SHA3-256）。
pub fn derive_scalar_from_card_and_sk(user_card: &ElGamalCiphertext, user_sk: &Scalar) -> Scalar {
    let c1_sk = user_card.c1 * user_sk;
    let c2_sk = user_card.c2 * user_sk;
    let mut data = c1_sk.compress().as_ref().to_vec();
    data.extend_from_slice(c2_sk.compress().as_ref());
    hash_to_scalar(&data)
}

/// 兼容 Move 合约 bls_scalar::derive_scalar_from_card_and_pk：
/// 输入 c1、c2、pk 的压缩字节，直接拼接后 hash_to_scalar。
/// 无域名分隔符前缀，无 SHA-256 预哈希（Move 端只有一层 SHA3-256）。
pub fn derive_scalar_from_card_and_pk(user_card: &ElGamalCiphertext, user_pk: &EcPoint) -> Scalar {
    let mut data = user_card.c1.compress().as_ref().to_vec();
    data.extend_from_slice(user_card.c2.compress().as_ref());
    data.extend_from_slice(user_pk.compress().as_ref());
    hash_to_scalar(&data)
}

lazy_static::lazy_static! {
    pub static ref BASE_G: EcPoint = DefaultCurve::base_g();
}
