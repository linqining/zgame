use super::types::{EcPoint, Scalar, BASE_G};
use curve25519_dalek::traits::{Identity, IsIdentity};
use rand_core::{RngCore, CryptoRng};


#[derive(Debug, Clone, PartialEq,Copy)]
pub struct ElGamalCiphertext {
    pub c1: EcPoint,
    pub c2: EcPoint,
}

impl ElGamalCiphertext {
    pub fn encrypt(plaintext: &EcPoint, pk: &EcPoint, r: &Scalar) -> Self {
        ElGamalCiphertext { c1: *BASE_G * r, c2: plaintext.clone() + pk * r }
    }

    pub fn re_encrypt(&self, pk: &EcPoint, r_prime: &Scalar) -> Self {
        ElGamalCiphertext { c1: self.c1 + *BASE_G * r_prime, c2: self.c2 + pk * r_prime }
    }

    pub fn decrypt(&self, sk: &Scalar) -> EcPoint { self.c2 - self.c1 * sk }

    pub fn is_valid(&self) -> bool { !self.c1.is_identity() && !self.c2.is_identity() }

    pub fn new_placeholder_card() -> Self { ElGamalCiphertext { c1: EcPoint::identity(), c2: EcPoint::identity() } }

    pub fn gen_reveal_token(&self, sk: &Scalar) -> EcPoint {
        self.c1 * sk
    }
}

pub use super::types::Plaintext;

pub fn ec_encrypt_batch_v2(plaintexts: &[EcPoint], pk: &EcPoint, rng: &mut (impl CryptoRng + RngCore)) -> Vec<ElGamalCiphertext> {
    plaintexts.iter().map(|pt| ElGamalCiphertext::encrypt(pt, pk, &Scalar::random(&mut *rng))).collect()
}
