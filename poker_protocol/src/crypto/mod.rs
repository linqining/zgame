pub mod types;
pub mod elgamal;
pub mod zk_primitives;

pub use types::{EcPoint, Scalar, Plaintext, BASE_G, BASE_H, N_CARDS, hash_to_scalar};
pub use elgamal::{ElGamalCiphertextV2, ec_encrypt_batch_v2};
pub use zk_primitives::{TripleDLEqProof, ProductArgumentV2};

pub type ElGamalCiphertext = ElGamalCiphertextV2;
pub type PublicKey = EcPoint;
pub type TripleDleqProof = TripleDLEqProof;
pub type ProductArgument = ProductArgumentV2;
pub fn encrypt_batch(plaintexts: &[EcPoint], pk: &EcPoint, rng: &mut (impl rand_core::RngCore + ?Sized)) -> Vec<ElGamalCiphertext> {
    ec_encrypt_batch_v2(plaintexts, pk, rng)
}
