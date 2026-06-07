//! Curve abstraction trait for elliptic curve operations.
//!
//! This module defines the `Curve` trait and its associated types (`CurveScalar`, `CurvePoint`),
//! enabling the zk_shuffle module to be generic over different elliptic curves.
//! The `RistrettoCurve` implementation provides the default Ristretto255 curve.

use std::fmt::Debug;
use std::iter::Sum;
use std::ops::{Add, Mul, Neg, Sub};
use rand_core::{CryptoRng, RngCore};

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar as DalekScalar,
    traits::{Identity as DalekIdentity, IsIdentity as DalekIsIdentity, VartimeMultiscalarMul as DalekVartimeMultiscalarMul},
};
use sha2::{Digest, Sha256};

/// Wrapper around `CompressedRistretto` that implements `AsRef<[u8]>`.
#[derive(Clone, Debug)]
pub struct CompressedPoint(CompressedRistretto);

impl CompressedPoint {
    /// Access the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl AsRef<[u8]> for CompressedPoint {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl From<CompressedRistretto> for CompressedPoint {
    fn from(c: CompressedRistretto) -> Self {
        CompressedPoint(c)
    }
}

// ============================================================
// Trait definitions
// ============================================================

/// Trait for scalar operations on an elliptic curve.
///
/// Provides the arithmetic operations needed for zero-knowledge proofs:
/// addition, subtraction, multiplication, inversion, and serialization.
pub trait CurveScalar:
    Clone
    + Copy
    + Debug
    + PartialEq
    + Eq
    + Add<Output = Self>
    + Sub<Output = Self>
    + Mul<Output = Self>
    + Neg<Output = Self>
    + Sum
    + Send
    + Sync
    + 'static
{
    /// The additive identity (zero).
    fn zero() -> Self;
    /// The multiplicative identity (one).
    fn one() -> Self;
    /// Generate a cryptographically random scalar.
    fn random(rng: &mut (impl CryptoRng + RngCore)) -> Self;
    /// Create a scalar from a 64-byte wide reduction modulo the curve order.
    fn from_bytes_mod_order_wide(bytes: &[u8; 64]) -> Self;
    /// Create a scalar from a u64 value.
    fn from_u64(val: u64) -> Self;
    /// Serialize the scalar as 32 bytes.
    fn as_bytes(&self) -> [u8; 32];
    /// Compute the multiplicative inverse.
    fn invert(&self) -> Self;
}

/// Trait for point operations on an elliptic curve.
///
/// Provides the group operations needed for zero-knowledge proofs:
/// addition, subtraction, scalar multiplication, and serialization.
pub trait CurvePoint:
    Clone
    + Copy
    + Debug
    + PartialEq
    + Eq
    + Add<Output = Self>
    + Sub<Output = Self>
    + Sum
    + Mul<<Self as CurvePoint>::Scalar, Output = Self>
    + Send
    + Sync
    + 'static
{
    /// The scalar type for this curve.
    type Scalar: CurveScalar;
    /// The compressed (serialized) representation of a point.
    type Compressed: Clone + Debug + Send + Sync + AsRef<[u8]>;

    /// The identity element (neutral element of the group).
    fn identity() -> Self;
    /// Check if this point is the identity element.
    fn is_identity(&self) -> bool;
    /// Generate a random point.
    fn random(rng: &mut (impl CryptoRng + RngCore)) -> Self;
    /// Compress the point to its serialized form.
    fn compress(&self) -> Self::Compressed;
    /// Variable-time multi-scalar multiplication: `sum(scalars[i] * points[i])`.
    fn vartime_multiscalar_mul(scalars: &[Self::Scalar], points: &[Self]) -> Self;
}

/// Main curve trait that ties together point and scalar types.
///
/// Implement this trait for each elliptic curve you want to use with the
/// zk_shuffle module. The `RistrettoCurve` implementation is provided as
/// the default.
pub trait Curve: Clone + Debug + PartialEq + Eq + Send + Sync + 'static {
    /// The point type for this curve.
    type Point: CurvePoint<Scalar = Self::Scalar>;
    /// The scalar type for this curve.
    type Scalar: CurveScalar;

    /// The standard base point (generator G).
    fn base_g() -> Self::Point;
    /// A second independent base point H, derived deterministically from G.
    fn base_h() -> Self::Point;
    /// Hash arbitrary bytes to a scalar.
    fn hash_to_scalar(digest: &[u8]) -> Self::Scalar;
    /// Number of cards in a deck (default: 52).
    fn n_cards() -> usize {
        52
    }
}

// ============================================================
// Ristretto255 implementation
// ============================================================

/// Ristretto255 curve implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RistrettoCurve;

impl CurveScalar for DalekScalar {
    fn zero() -> Self {
        DalekScalar::ZERO
    }

    fn one() -> Self {
        DalekScalar::ONE
    }

    fn random(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        DalekScalar::random(rng)
    }

    fn from_bytes_mod_order_wide(bytes: &[u8; 64]) -> Self {
        DalekScalar::from_bytes_mod_order_wide(bytes)
    }

    fn from_u64(val: u64) -> Self {
        DalekScalar::from(val)
    }

    fn as_bytes(&self) -> [u8; 32] {
        *DalekScalar::as_bytes(self)
    }

    fn invert(&self) -> Self {
        DalekScalar::invert(self)
    }
}

impl CurvePoint for RistrettoPoint {
    type Scalar = DalekScalar;
    type Compressed = CompressedPoint;

    fn identity() -> Self {
        DalekIdentity::identity()
    }

    fn is_identity(&self) -> bool {
        DalekIsIdentity::is_identity(self)
    }

    fn random(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        RistrettoPoint::random(rng)
    }

    fn compress(&self) -> CompressedPoint {
        CompressedPoint(RistrettoPoint::compress(self))
    }

    fn vartime_multiscalar_mul(scalars: &[DalekScalar], points: &[Self]) -> Self {
        <RistrettoPoint as DalekVartimeMultiscalarMul>::vartime_multiscalar_mul(scalars, points)
    }
}

impl Curve for RistrettoCurve {
    type Point = RistrettoPoint;
    type Scalar = DalekScalar;

    fn base_g() -> RistrettoPoint {
        RISTRETTO_BASEPOINT_TABLE.basepoint()
    }

    fn base_h() -> RistrettoPoint {
        let mut h = Sha256::new();
        h.update(b"crypto_independent_base_H_2024");
        let digest = h.finalize();
        let hash_bytes: [u8; 32] = digest.into();
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&hash_bytes);
        wide[32..].copy_from_slice(&hash_bytes);
        let s = DalekScalar::from_bytes_mod_order_wide(&wide);
        RISTRETTO_BASEPOINT_TABLE.basepoint() * s
    }

    fn hash_to_scalar(digest: &[u8]) -> DalekScalar {
        let mut bytes = [0u8; 64];
        let len = 64.min(digest.len());
        bytes[..len].copy_from_slice(&digest[..len]);
        let s = DalekScalar::from_bytes_mod_order_wide(&bytes);
        if s == DalekScalar::ZERO {
            let mut h = Sha256::new();
            h.update(b"hts_retry:");
            h.update(&bytes[..32]);
            let retry = h.finalize();
            let mut rb = [0u8; 64];
            rb[..32].copy_from_slice(&retry);
            let s2 = DalekScalar::from_bytes_mod_order_wide(&rb);
            if s2 == DalekScalar::ZERO {
                DalekScalar::ONE
            } else {
                s2
            }
        } else {
            s
        }
    }

    fn n_cards() -> usize {
        52
    }
}

// ============================================================
// Generic ElGamal ciphertext
// ============================================================

/// ElGamal ciphertext, generic over the curve.
///
/// A ciphertext consists of two curve points:
/// - `c1 = G * r` (the ephemeral public key)
/// - `c2 = M + pk * r` (the encrypted message)
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub struct ElGamalCiphertextGeneric<C: Curve> {
    pub c1: C::Point,
    pub c2: C::Point,
}

impl<C: Curve> ElGamalCiphertextGeneric<C> {
    /// Encrypt a plaintext point under the given public key.
    pub fn encrypt(plaintext: &C::Point, pk: &C::Point, r: &C::Scalar) -> Self {
        ElGamalCiphertextGeneric {
            c1: C::base_g() * *r,
            c2: *plaintext + *pk * *r,
        }
    }

    /// Decrypt the ciphertext using the secret key.
    pub fn decrypt(&self, sk: &C::Scalar) -> C::Point {
        self.c2 - self.c1 * *sk
    }

    /// Re-encrypt the ciphertext with a new random value.
    pub fn re_encrypt(&self, pk: &C::Point, r_prime: &C::Scalar) -> Self {
        ElGamalCiphertextGeneric {
            c1: self.c1 + C::base_g() * *r_prime,
            c2: self.c2 + *pk * *r_prime,
        }
    }

    /// Check if this is a valid (non-identity) ciphertext.
    pub fn is_valid(&self) -> bool {
        !self.c1.is_identity() && !self.c2.is_identity()
    }

    /// Create a placeholder card (identity points).
    pub fn new_placeholder_card() -> Self {
        ElGamalCiphertextGeneric {
            c1: C::Point::identity(),
            c2: C::Point::identity(),
        }
    }

    /// Generate a reveal token: `c1 * sk`.
    pub fn gen_reveal_token(&self, sk: &C::Scalar) -> C::Point {
        self.c1 * *sk
    }
}

/// Type alias for Ristretto255 ElGamal ciphertext (backward compatibility).
pub type RistrettoElGamalCiphertext = ElGamalCiphertextGeneric<RistrettoCurve>;

impl From<ElGamalCiphertextGeneric<RistrettoCurve>> for crate::crypto::elgamal::ElGamalCiphertext {
    fn from(ct: ElGamalCiphertextGeneric<RistrettoCurve>) -> Self {
        Self { c1: ct.c1, c2: ct.c2 }
    }
}

impl From<crate::crypto::elgamal::ElGamalCiphertext> for ElGamalCiphertextGeneric<RistrettoCurve> {
    fn from(ct: crate::crypto::elgamal::ElGamalCiphertext) -> Self {
        Self { c1: ct.c1, c2: ct.c2 }
    }
}

/// Batch encrypt plaintexts under the given public key.
pub fn ec_encrypt_batch_generic<C: Curve>(
    plaintexts: &[C::Point],
    pk: &C::Point,
    rng: &mut (impl CryptoRng + RngCore),
) -> Vec<ElGamalCiphertextGeneric<C>> {
    plaintexts
        .iter()
        .map(|pt| ElGamalCiphertextGeneric::encrypt(pt, pk, &C::Scalar::random(rng)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_ristretto_curve_base_points() {
        let g = RistrettoCurve::base_g();
        let h = RistrettoCurve::base_h();
        assert!(!<RistrettoPoint as CurvePoint>::is_identity(&g));
        assert!(!<RistrettoPoint as CurvePoint>::is_identity(&h));
        assert_ne!(g, h);
    }

    #[test]
    fn test_ristretto_scalar_operations() {
        let a = DalekScalar::random(&mut OsRng);
        let b = DalekScalar::random(&mut OsRng);
        let _ = a + b;
        let _ = a - b;
        let _ = a * b;
        let _ = -a;
        assert_ne!(DalekScalar::zero(), DalekScalar::one());
        assert_eq!(DalekScalar::from_u64(0), DalekScalar::zero());
        assert_eq!(DalekScalar::from_u64(1), DalekScalar::one());
    }

    #[test]
    fn test_ristretto_point_operations() {
        let g = RistrettoCurve::base_g();
        let s = DalekScalar::from_u64(42);
        let p = g * s;
        assert!(!<RistrettoPoint as CurvePoint>::is_identity(&p));
        let _ = g + p;
        let _ = g - p;
    }

    #[test]
    fn test_elgamal_encrypt_decrypt() {
        let sk = DalekScalar::random(&mut OsRng);
        let pk = RistrettoCurve::base_g() * sk;
        let plaintext = RistrettoCurve::base_g() * DalekScalar::from_u64(123);
        let r = DalekScalar::random(&mut OsRng);

        let ct = ElGamalCiphertextGeneric::<RistrettoCurve>::encrypt(&plaintext, &pk, &r);
        let decrypted = ct.decrypt(&sk);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_elgamal_re_encrypt() {
        let sk = DalekScalar::random(&mut OsRng);
        let pk = RistrettoCurve::base_g() * sk;
        let plaintext = RistrettoCurve::base_g() * DalekScalar::from_u64(456);
        let r = DalekScalar::random(&mut OsRng);

        let ct = ElGamalCiphertextGeneric::<RistrettoCurve>::encrypt(&plaintext, &pk, &r);
        let r_prime = DalekScalar::random(&mut OsRng);
        let re_ct = ct.re_encrypt(&pk, &r_prime);
        let decrypted = re_ct.decrypt(&sk);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_hash_to_scalar() {
        let data = b"test data for hashing";
        let s = RistrettoCurve::hash_to_scalar(data);
        assert_ne!(s, DalekScalar::zero());
    }

    #[test]
    fn test_n_cards() {
        assert_eq!(RistrettoCurve::n_cards(), 52);
    }

    #[test]
    fn test_vartime_multiscalar_mul() {
        let g = RistrettoCurve::base_g();
        let h = RistrettoCurve::base_h();
        let s1 = DalekScalar::from_u64(3);
        let s2 = DalekScalar::from_u64(5);

        let result = <RistrettoPoint as CurvePoint>::vartime_multiscalar_mul(&[s1, s2], &[g, h]);
        let expected = g * s1 + h * s2;
        assert_eq!(result, expected);
    }

    #[test]
    fn test_placeholder_card() {
        let ct = ElGamalCiphertextGeneric::<RistrettoCurve>::new_placeholder_card();
        assert!(<RistrettoPoint as CurvePoint>::is_identity(&ct.c1));
        assert!(<RistrettoPoint as CurvePoint>::is_identity(&ct.c2));
    }

    #[test]
    fn test_reveal_token() {
        let sk = DalekScalar::random(&mut OsRng);
        let pk = RistrettoCurve::base_g() * sk;
        let plaintext = RistrettoCurve::base_g() * DalekScalar::from_u64(789);
        let r = DalekScalar::random(&mut OsRng);

        let ct = ElGamalCiphertextGeneric::<RistrettoCurve>::encrypt(&plaintext, &pk, &r);
        let token = ct.gen_reveal_token(&sk);
        let expected = ct.c1 * sk;
        assert_eq!(token, expected);

        // Verify decryption using reveal token
        let decrypted = ct.c2 - token;
        assert_eq!(decrypted, plaintext);
    }
}
