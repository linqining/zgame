use super::types::{EcPoint, Scalar, BASE_G, BASE_H};
use ff::Field;
use group::Group;
use rand_core::RngCore;

#[derive(Debug, Clone, PartialEq,Copy)]
pub struct ElGamalCiphertextV2 {
    pub c1: EcPoint,
    pub c2: EcPoint,
    pub c3: EcPoint,
}

impl ElGamalCiphertextV2 {
    pub fn encrypt(plaintext: &EcPoint, pk: &EcPoint, r: &Scalar) -> Self {
        ElGamalCiphertextV2 { c1: *BASE_G * r, c2: plaintext.clone() + pk * r, c3: *BASE_H * r }
    }

    pub fn re_encrypt(&self, pk: &EcPoint, r_prime: &Scalar) -> Self {
        ElGamalCiphertextV2 { c1: self.c1 + *BASE_G * r_prime, c2: self.c2 + pk * r_prime, c3: self.c3 + *BASE_H * r_prime }
    }

    pub fn decrypt(&self, sk: &Scalar) -> EcPoint { self.c2 - self.c1 * sk }

    pub fn is_valid(&self) -> bool { !bool::from(self.c1.is_identity()) || !bool::from(self.c2.is_identity()) }

    pub fn new_placehod_card() -> Self { ElGamalCiphertextV2 { c1: EcPoint::IDENTITY, c2: EcPoint::IDENTITY, c3: EcPoint::IDENTITY } }

    pub fn gen_reveal_token(&self, sk: &Scalar) -> EcPoint {
        self.c1 * sk
    }
}

pub use super::types::Plaintext;

pub fn ec_encrypt_batch_v2(plaintexts: &[EcPoint], pk: &EcPoint, rng: &mut (impl RngCore + ?Sized)) -> Vec<ElGamalCiphertextV2> {
    plaintexts.iter().map(|pt| ElGamalCiphertextV2::encrypt(pt, pk, &Scalar::random(&mut *rng))).collect()
}
