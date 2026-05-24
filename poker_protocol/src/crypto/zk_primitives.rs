use super::types::{EcPoint, Scalar, BASE_G, BASE_H, N_CARDS, hash_to_scalar};
use super::elgamal::ElGamalCiphertext;
use curve25519_dalek::traits::{Identity, IsIdentity};
use sha2::{Sha256, Digest};
use rand_core::{RngCore, CryptoRng};



