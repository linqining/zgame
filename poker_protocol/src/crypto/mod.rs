pub mod types;
pub mod elgamal;
pub mod curve;

pub use types::{DefaultCurve, EcPoint, Scalar, Plaintext, ElGamalCiphertext, ECPoint, BASE_G, N_CARDS, hash_to_scalar, derive_scalar_from_card_and_pk, derive_scalar_from_card_and_sk};
pub use elgamal::ec_encrypt_batch_v2;
pub use curve::{
    Curve, CurveScalar, CurvePoint,
    RistrettoCurve, Bls12381Curve,
    ElGamalCiphertextGeneric, RistrettoElGamalCiphertext, Bls12381ElGamalCiphertext,
    ec_encrypt_batch_generic,
};

pub type PublicKey = EcPoint;
pub fn encrypt_batch(plaintexts: &[EcPoint], pk: &EcPoint, rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore)) -> Vec<ElGamalCiphertext> {
    ec_encrypt_batch_v2(plaintexts, pk, rng)
}
