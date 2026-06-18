//! Curve abstraction trait for elliptic curve operations.
//!
//! This module defines the `Curve` trait and its associated types (`CurveScalar`, `CurvePoint`),
//! enabling the zk_shuffle module to be generic over different elliptic curves.
//! Two implementations are provided:
//! - `RistrettoCurve`: Ristretto255 curve (curve25519-dalek)
//! - `Bls12381Curve`: BLS12-381 G1 curve (blstrs, Sui-compatible)

use std::fmt::Debug;
use std::iter::Sum;
use std::ops::{Add, Mul, Neg, Sub};
use rand_core::{CryptoRng, RngCore};
use rayon::prelude::*;

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar as DalekScalar,
    traits::{Identity as DalekIdentity, IsIdentity as DalekIsIdentity, VartimeMultiscalarMul as DalekVartimeMultiscalarMul},
};
use sha2::{Digest, Sha256};
use sha3::Sha3_256;

use blstrs::{G1Projective, G1Compressed, Scalar as BlsScalar};
use ff::{Field, PrimeField};
use group::{Group, GroupEncoding};

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
    /// Create a scalar from arbitrary bytes, reducing modulo the curve order.
    fn from_bytes_mod_order(bytes: &[u8]) -> Self;
    /// Create a scalar from 64 arbitrary bytes, reducing modulo the curve order.
    fn from_bytes_mod_order_wide(bytes: &[u8; 64]) -> Self;
    /// Create a scalar from a u64 value.
    fn from_u64(val: u64) -> Self;
    /// Serialize the scalar as bytes.
    fn as_bytes(&self) -> Vec<u8>;
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
    + for<'a> Mul<&'a <Self as CurvePoint>::Scalar, Output = Self>
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
    /// Deserialize a point from compressed bytes. Returns None if invalid.
    fn from_compressed(bytes: &[u8]) -> Option<Self>;
}

/// Main curve trait that ties together point and scalar types.
///
/// Implement this trait for each elliptic curve you want to use with the
/// zk_shuffle module. The `RistrettoCurve` and `Bls12381Curve` implementations
/// are provided.
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

    fn from_bytes_mod_order(bytes: &[u8]) -> Self {
        let mut wide = [0u8; 64];
        let len = 64.min(bytes.len());
        wide[..len].copy_from_slice(&bytes[..len]);
        DalekScalar::from_bytes_mod_order_wide(&wide)
    }

    fn from_bytes_mod_order_wide(bytes: &[u8; 64]) -> Self {
        DalekScalar::from_bytes_mod_order_wide(bytes)
    }

    fn from_u64(val: u64) -> Self {
        DalekScalar::from(val)
    }

    fn as_bytes(&self) -> Vec<u8> {
        DalekScalar::as_bytes(self).to_vec()
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

    fn from_compressed(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 {
            return None;
        }
        CompressedRistretto::from_slice(bytes).ok().and_then(|c| c.decompress())
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
// BLS12-381 G1 implementation
// ============================================================

/// Wrapper around `G1Compressed` that implements `AsRef<[u8]>`.
#[derive(Clone, Debug)]
pub struct BlsCompressedPoint(G1Compressed);

impl BlsCompressedPoint {
    /// Access the underlying bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsRef<[u8]> for BlsCompressedPoint {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<G1Compressed> for BlsCompressedPoint {
    fn from(c: G1Compressed) -> Self {
        BlsCompressedPoint(c)
    }
}

/// BLS12-381 G1 curve implementation (Sui-compatible).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bls12381Curve;

impl CurveScalar for BlsScalar {
    fn zero() -> Self {
        <Self as Field>::ZERO
    }

    fn one() -> Self {
        <Self as Field>::ONE
    }

    fn random(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        <Self as Field>::random(rng)
    }

    fn from_bytes_mod_order(bytes: &[u8]) -> Self {
        let mut arr = [0u8; 32];
        let len = 32.min(bytes.len());
        arr[..len].copy_from_slice(&bytes[..len]);

        // Try normal deserialization first (works for values < modulus)
        if let Some(s) = BlsScalar::from_repr_vartime(arr) {
            return s;
        }

        // Value >= modulus. Since max 32-byte value < 3 * modulus,
        // subtract modulus until the value is in range.
        // Note: blstrs doesn't expose a native from_bytes_mod_order,
        // so we implement manual modular reduction.
        const MODULUS_LE: [u8; 32] = [
            0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
            0xfe, 0x5b, 0xfe, 0xff, 0x02, 0xa4, 0xbd, 0x53,
            0x05, 0xd8, 0xa1, 0x09, 0x08, 0xd8, 0x39, 0x33,
            0x48, 0x7d, 0x9d, 0x29, 0x53, 0xa7, 0xed, 0x73,
        ];

        for _ in 0..3 {
            let mut borrow = 0i64;
            for i in 0..32 {
                let diff = arr[i] as i64 - MODULUS_LE[i] as i64 - borrow;
                if diff < 0 {
                    arr[i] = (diff + 256) as u8;
                    borrow = 1;
                } else {
                    arr[i] = diff as u8;
                    borrow = 0;
                }
            }
            if let Some(s) = BlsScalar::from_repr_vartime(arr) {
                return s;
            }
        }

        <Self as Field>::ZERO
    }

    fn from_bytes_mod_order_wide(bytes: &[u8; 64]) -> Self {
        // Combine both halves: XOR low 32 bytes with high 32 bytes,
        // then reduce modulo the curve order.
        let mut arr = [0u8; 32];
        for i in 0..32 {
            arr[i] = bytes[i] ^ bytes[32 + i];
        }
        Self::from_bytes_mod_order(&arr)
    }

    fn from_u64(val: u64) -> Self {
        BlsScalar::from(val)
    }

    fn as_bytes(&self) -> Vec<u8> {
        <Self as PrimeField>::to_repr(self).as_ref().to_vec()
    }

    fn invert(&self) -> Self {
        <Self as Field>::invert(self).unwrap_or(<Self as Field>::ZERO)
    }
}

impl CurvePoint for G1Projective {
    type Scalar = BlsScalar;
    type Compressed = BlsCompressedPoint;

    fn identity() -> Self {
        <Self as Group>::identity()
    }

    fn is_identity(&self) -> bool {
        bool::from(<Self as Group>::is_identity(self))
    }

    fn random(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let s = <BlsScalar as Field>::random(rng);
        <Self as Group>::generator() * s
    }

    fn compress(&self) -> BlsCompressedPoint {
        BlsCompressedPoint(<Self as GroupEncoding>::to_bytes(self))
    }

    fn vartime_multiscalar_mul(scalars: &[BlsScalar], points: &[Self]) -> Self {
        G1Projective::multi_exp(points, scalars)
    }

    fn from_compressed(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 48 {
            return None;
        }
        let mut arr = [0u8; 48];
        arr.copy_from_slice(bytes);
        let ct = G1Projective::from_compressed(&arr);
        if bool::from(ct.is_some()) {
            Some(ct.unwrap())
        } else {
            None
        }
    }
}

impl Curve for Bls12381Curve {
    type Point = G1Projective;
    type Scalar = BlsScalar;

    fn base_g() -> G1Projective {
        <G1Projective as Group>::generator()
    }

    fn base_h() -> G1Projective {
        // 兼容 Move 合约 bls_scalar::base_h()：
        // 使用 hash_to_g1（RFC 9380 hash-to-curve）而非 G * hash(label)。
        // 两者产生不同的点，必须与链上实现保持一致。
        let label = b"texas_poker_independent_base_H";
        G1Projective::hash_to_curve(label, b"", b"")
    }

    fn hash_to_scalar(digest: &[u8]) -> BlsScalar {
        // 兼容 Move 合约 bls_scalar::hash_to_scalar：
        // SHA3-256(data) → 清除 h[0] 最高2位 → scalar_from_bytes
        //
        // Move 端 bls12381::scalar_from_bytes 对字节做模 r 约简（始终成功），
        // Rust 端使用 from_bytes_mod_order 做相同的模 r 约简。
        // 清位（& 0x3F）与 Move 保持一致，虽然模约简本身已能处理任意输入，
        // 但保留清位确保两端对同一输入产生相同标量。
        let mut hash = Sha3_256::digest(digest);
        hash[0] &= 0x3F;
        let arr: [u8; 32] = hash.into();
        BlsScalar::from_bytes_mod_order(&arr)
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElGamalCiphertextGeneric<C: Curve> {
    pub c1: C::Point,
    pub c2: C::Point,
}

impl<C: Curve> ElGamalCiphertextGeneric<C> {
    /// Encrypt a plaintext point under the given public key.
    pub fn encrypt(plaintext: &C::Point, pk: &C::Point, r: &C::Scalar) -> Self {
        ElGamalCiphertextGeneric {
            c1: C::base_g() * r,
            c2: *plaintext + *pk * r,
        }
    }

    /// Decrypt the ciphertext using the secret key.
    pub fn decrypt(&self, sk: &C::Scalar) -> C::Point {
        self.c2 - self.c1 * sk
    }

    /// Re-encrypt the ciphertext with a new random value.
    pub fn re_encrypt(&self, pk: &C::Point, r_prime: &C::Scalar) -> Self {
        ElGamalCiphertextGeneric {
            c1: self.c1.clone() + C::base_g() * r_prime,
            c2: self.c2.clone() + *pk * r_prime,
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
        self.c1.clone() * sk
    }

    /// Remask: c2 += c1 * sk (new player joins)
    pub fn remask(&self, sk: &C::Scalar) -> Self {
        ElGamalCiphertextGeneric {
            c1: self.c1.clone(),
            c2: self.c2.clone() + self.c1.clone() * sk,
        }
    }
}

/// Type alias for Ristretto255 ElGamal ciphertext (backward compatibility).
pub type RistrettoElGamalCiphertext = ElGamalCiphertextGeneric<RistrettoCurve>;

/// Type alias for BLS12-381 ElGamal ciphertext.
pub type Bls12381ElGamalCiphertext = ElGamalCiphertextGeneric<Bls12381Curve>;

/// Batch encrypt plaintexts under the given public key.
pub fn ec_encrypt_batch_generic<C: Curve>(
    plaintexts: &[C::Point],
    pk: &C::Point,
    rng: &mut (impl CryptoRng + RngCore),
) -> Vec<ElGamalCiphertextGeneric<C>> {
    let r_vec: Vec<C::Scalar> = (0..plaintexts.len())
        .map(|_| C::Scalar::random(rng))
        .collect();
    plaintexts
        .par_iter()
        .zip(r_vec.par_iter())
        .map(|(pt, r)| ElGamalCiphertextGeneric::encrypt(pt, pk, r))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    // ========== RistrettoCurve tests ==========

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
        let p = &g * &s;
        assert!(!<RistrettoPoint as CurvePoint>::is_identity(&p));
        let _ = g.clone() + p.clone();
        let _ = g.clone() - p;
    }

    #[test]
    fn test_ristretto_elgamal_encrypt_decrypt() {
        let sk = DalekScalar::random(&mut OsRng);
        let pk = RistrettoCurve::base_g() * &sk;
        let plaintext = RistrettoCurve::base_g() * &DalekScalar::from_u64(123);
        let r = DalekScalar::random(&mut OsRng);

        let ct = ElGamalCiphertextGeneric::<RistrettoCurve>::encrypt(&plaintext, &pk, &r);
        let decrypted = ct.decrypt(&sk);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ristretto_elgamal_re_encrypt() {
        let sk = DalekScalar::random(&mut OsRng);
        let pk = RistrettoCurve::base_g() * &sk;
        let plaintext = RistrettoCurve::base_g() * &DalekScalar::from_u64(456);
        let r = DalekScalar::random(&mut OsRng);

        let ct = ElGamalCiphertextGeneric::<RistrettoCurve>::encrypt(&plaintext, &pk, &r);
        let r_prime = DalekScalar::random(&mut OsRng);
        let re_ct = ct.re_encrypt(&pk, &r_prime);
        let decrypted = re_ct.decrypt(&sk);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ristretto_hash_to_scalar() {
        let data = b"test data for hashing";
        let s = RistrettoCurve::hash_to_scalar(data);
        assert_ne!(s, DalekScalar::zero());
    }

    #[test]
    fn test_ristretto_n_cards() {
        assert_eq!(RistrettoCurve::n_cards(), 52);
    }

    #[test]
    fn test_ristretto_vartime_multiscalar_mul() {
        let g = RistrettoCurve::base_g();
        let h = RistrettoCurve::base_h();
        let s1 = DalekScalar::from_u64(3);
        let s2 = DalekScalar::from_u64(5);

        let result = <RistrettoPoint as CurvePoint>::vartime_multiscalar_mul(&[s1, s2], &[g, h]);
        let expected = &g * &s1 + &h * &s2;
        assert_eq!(result, expected);
    }

    #[test]
    fn test_ristretto_placeholder_card() {
        let ct = ElGamalCiphertextGeneric::<RistrettoCurve>::new_placeholder_card();
        assert!(<RistrettoPoint as CurvePoint>::is_identity(&ct.c1));
        assert!(<RistrettoPoint as CurvePoint>::is_identity(&ct.c2));
    }

    #[test]
    fn test_ristretto_reveal_token() {
        let sk = DalekScalar::random(&mut OsRng);
        let pk = RistrettoCurve::base_g() * &sk;
        let plaintext = RistrettoCurve::base_g() * &DalekScalar::from_u64(789);
        let r = DalekScalar::random(&mut OsRng);

        let ct = ElGamalCiphertextGeneric::<RistrettoCurve>::encrypt(&plaintext, &pk, &r);
        let token = ct.gen_reveal_token(&sk);
        let expected = &ct.c1 * &sk;
        assert_eq!(token, expected);

        // Verify decryption using reveal token
        let decrypted = ct.c2.clone() - token;
        assert_eq!(decrypted, plaintext);
    }

    // ========== Bls12381Curve tests ==========

    #[test]
    fn test_bls12381_curve_base_points() {
        let g = Bls12381Curve::base_g();
        let h = Bls12381Curve::base_h();
        assert!(!<G1Projective as CurvePoint>::is_identity(&g));
        assert!(!<G1Projective as CurvePoint>::is_identity(&h));
        assert_ne!(g, h);
    }

    #[test]
    fn test_bls12381_scalar_operations() {
        let a = <BlsScalar as CurveScalar>::random(&mut OsRng);
        let b = <BlsScalar as CurveScalar>::random(&mut OsRng);
        let _ = a + b;
        let _ = a - b;
        let _ = a * b;
        let _ = -a;
        assert_ne!(BlsScalar::zero(), BlsScalar::one());
        assert_eq!(BlsScalar::from_u64(0), BlsScalar::zero());
        assert_eq!(BlsScalar::from_u64(1), BlsScalar::one());
    }

    #[test]
    fn test_bls12381_point_operations() {
        let g = Bls12381Curve::base_g();
        let s = BlsScalar::from_u64(42);
        let p = &g * &s;
        assert!(!<G1Projective as CurvePoint>::is_identity(&p));
        let _ = g.clone() + p.clone();
        let _ = g.clone() - p;
    }

    #[test]
    fn test_bls12381_elgamal_encrypt_decrypt() {
        let sk = <BlsScalar as CurveScalar>::random(&mut OsRng);
        let pk = Bls12381Curve::base_g() * &sk;
        let plaintext = Bls12381Curve::base_g() * &BlsScalar::from_u64(123);
        let r = <BlsScalar as CurveScalar>::random(&mut OsRng);

        let ct = ElGamalCiphertextGeneric::<Bls12381Curve>::encrypt(&plaintext, &pk, &r);
        let decrypted = ct.decrypt(&sk);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_bls12381_elgamal_re_encrypt() {
        let sk = <BlsScalar as CurveScalar>::random(&mut OsRng);
        let pk = Bls12381Curve::base_g() * &sk;
        let plaintext = Bls12381Curve::base_g() * &BlsScalar::from_u64(456);
        let r = <BlsScalar as CurveScalar>::random(&mut OsRng);

        let ct = ElGamalCiphertextGeneric::<Bls12381Curve>::encrypt(&plaintext, &pk, &r);
        let r_prime = <BlsScalar as CurveScalar>::random(&mut OsRng);
        let re_ct = ct.re_encrypt(&pk, &r_prime);
        let decrypted = re_ct.decrypt(&sk);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_bls12381_hash_to_scalar() {
        let data = b"test data for hashing";
        let s = Bls12381Curve::hash_to_scalar(data);
        assert_ne!(s, BlsScalar::zero());
    }

    #[test]
    fn test_bls12381_n_cards() {
        assert_eq!(Bls12381Curve::n_cards(), 52);
    }

    #[test]
    fn test_bls12381_vartime_multiscalar_mul() {
        let g = Bls12381Curve::base_g();
        let h = Bls12381Curve::base_h();
        let s1 = BlsScalar::from_u64(3);
        let s2 = BlsScalar::from_u64(5);

        let result = <G1Projective as CurvePoint>::vartime_multiscalar_mul(&[s1, s2], &[g, h]);
        let expected = &g * &s1 + &h * &s2;
        assert_eq!(result, expected);
    }

    #[test]
    fn test_bls12381_placeholder_card() {
        let ct = ElGamalCiphertextGeneric::<Bls12381Curve>::new_placeholder_card();
        assert!(<G1Projective as CurvePoint>::is_identity(&ct.c1));
        assert!(<G1Projective as CurvePoint>::is_identity(&ct.c2));
    }

    #[test]
    fn test_bls12381_reveal_token() {
        let sk = <BlsScalar as CurveScalar>::random(&mut OsRng);
        let pk = Bls12381Curve::base_g() * &sk;
        let plaintext = Bls12381Curve::base_g() * &BlsScalar::from_u64(789);
        let r = <BlsScalar as CurveScalar>::random(&mut OsRng);

        let ct = ElGamalCiphertextGeneric::<Bls12381Curve>::encrypt(&plaintext, &pk, &r);
        let token = ct.gen_reveal_token(&sk);
        let expected = &ct.c1 * &sk;
        assert_eq!(token, expected);

        // Verify decryption using reveal token
        let decrypted = ct.c2.clone() - token;
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_bls12381_remask() {
        let sk = <BlsScalar as CurveScalar>::random(&mut OsRng);
        let pk = Bls12381Curve::base_g() * &sk;
        let plaintext = Bls12381Curve::base_g() * &BlsScalar::from_u64(999);
        let r = <BlsScalar as CurveScalar>::random(&mut OsRng);

        let ct = ElGamalCiphertextGeneric::<Bls12381Curve>::encrypt(&plaintext, &pk, &r);
        let remask_sk = <BlsScalar as CurveScalar>::random(&mut OsRng);
        let remasked = ct.remask(&remask_sk);

        // c1 should be unchanged
        assert_eq!(remasked.c1, ct.c1);
        // c2 should be different
        assert_ne!(remasked.c2, ct.c2);
    }

    #[test]
    fn test_bls12381_point_serialization() {
        let g = Bls12381Curve::base_g();
        let compressed = g.compress();
        assert_eq!(compressed.as_ref().len(), 48);
        let decompressed = <G1Projective as CurvePoint>::from_compressed(compressed.as_ref());
        assert!(decompressed.is_some());
        assert_eq!(decompressed.unwrap(), g);
    }

    #[test]
    fn test_bls12381_scalar_serialization() {
        let s = BlsScalar::from_u64(42);
        let bytes = s.as_bytes();
        assert_eq!(bytes.len(), 32);
        let s2 = BlsScalar::from_bytes_mod_order(&bytes);
        assert_eq!(s, s2);
    }
}
