use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar as Sc,
    traits::{Identity, IsIdentity},
};
use sha2::{Sha256, Digest};
use std::hash::{Hash, Hasher};

pub const N_CARDS: usize = 52;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ECPoint(pub EcPoint);

pub type EcPoint = RistrettoPoint;
pub type Scalar = Sc;
pub type Plaintext = EcPoint;

impl Hash for ECPoint {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.compress().as_bytes().hash(state);
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
    pub fn to_affine(&self) -> CompressedRistretto {
        self.0.compress()
    }
}

pub fn hash_to_scalar(digest: &[u8]) -> Scalar {
    let mut bytes = [0u8; 64];
    let len = 64.min(digest.len());
    bytes[..len].copy_from_slice(&digest[..len]);
    let s = Scalar::from_bytes_mod_order_wide(&bytes);
    if s == Scalar::ZERO {
        let mut h = Sha256::new();
        h.update(b"hts_retry:");
        h.update(&bytes[..32]);
        let retry = h.finalize();
        let mut rb = [0u8; 64];
        rb[..32].copy_from_slice(&retry);
        let s2 = Scalar::from_bytes_mod_order_wide(&rb);
        if s2 == Scalar::ZERO { Scalar::ONE } else { s2 }
    } else {
        s
    }
}

pub fn derive_scalar_from_card_and_sk(user_card: &crate::crypto::ElGamalCiphertext, user_sk: &Scalar) -> Scalar {
    let mut h = Sha256::new();
    h.update(b"derive_scalar_from_card_and_sk_v1:");
    h.update((user_card.c1 * user_sk).compress().as_bytes());
    h.update((user_card.c2 * user_sk).compress().as_bytes());
    let digest = h.finalize();
    hash_to_scalar(&digest)
}

pub fn derive_scalar_from_card_and_pk(user_card: &crate::crypto::ElGamalCiphertext, user_pk: &EcPoint) -> Scalar {
    let mut h = Sha256::new();
    h.update(b"derive_scalar_from_card_and_pk_v1:");
    h.update(user_card.c1.compress().as_bytes());
    h.update(user_card.c2.compress().as_bytes());
    h.update(user_pk.compress().as_bytes());
    let digest = h.finalize();
    hash_to_scalar(&digest)
}

fn get_base_g() -> EcPoint { RISTRETTO_BASEPOINT_TABLE.basepoint() }

fn get_base_h() -> EcPoint {
    let mut h = Sha256::new();
    h.update(b"crypto_independent_base_H_2024");
    let digest = h.finalize();
    let hash_bytes: [u8; 32] = digest.into();
    // Use from_bytes_mod_order_wide with 64 bytes to ensure valid point
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&hash_bytes);
    wide[32..].copy_from_slice(&hash_bytes);
    let s = Scalar::from_bytes_mod_order_wide(&wide);
    RISTRETTO_BASEPOINT_TABLE.basepoint() * s
}

lazy_static::lazy_static! {
    pub static ref BASE_G: EcPoint = get_base_g();
}
