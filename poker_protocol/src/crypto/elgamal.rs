use super::types::{EcPoint, Scalar, DefaultCurve};
use crate::crypto::curve::{CurveScalar, ElGamalCiphertextGeneric};
use rand_core::{RngCore, CryptoRng};

/// Non-generic ElGamal ciphertext using the default curve.
/// This is a type alias for `ElGamalCiphertextGeneric<DefaultCurve>`.
pub type ElGamalCiphertext = ElGamalCiphertextGeneric<DefaultCurve>;

pub use super::types::Plaintext;

pub fn ec_encrypt_batch_v2(plaintexts: &[EcPoint], pk: &EcPoint, rng: &mut (impl CryptoRng + RngCore)) -> Vec<ElGamalCiphertext> {
    plaintexts.iter().map(|pt| ElGamalCiphertextGeneric::<DefaultCurve>::encrypt(pt, pk, &Scalar::random(&mut *rng))).collect()
}
