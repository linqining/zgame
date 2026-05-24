//! # RevealTokenProof - Chaum-Pedersen DLEq (双Base Pair)
//!
//! ## 参考 linqining/mental-poker 的 reveal_token 协议
//!
//! ```text
//! ElGamal加密: ct = (c1=G·r, c2=M+pk·r, c3=H·r)
//!
//! RevealToken (客户端生成):
//!   token = c1 · sk = G · r · sk = pk · r    (即 ElGamal 的 "mask" 部分)
//!
//! Chaum-Pedersen DLEq 证明 (Σ-Protocol + Fiat-Shamir):
//!   Statement: (G, c1) → (pk, token)   两组离散对数相等
//!   Witness:   sk                       (log_G(pk) == log_c1(token) == sk)
//!
//!   Commit:  T1 = G·ω,   T2 = c1·ω       ω ←$ random blind
//!   Challenge: c = H(domain ‖ pk ‖ c1 ‖ token ‖ T1 ‖ T2)
//!   Response:  s = ω + c·sk
//!
//!   Verify:
//!     G·s      == T1 + pk·c       ✓  → 第一组DLEq
//!     c1·s     == T2 + token·c    ✓  → 第二组DLEq (绑定token与c1的关系)
//!
//! 服务端额外校验:
//!   revealed_plaintext == c2 - token   ✓  → 确保解密结果正确
//! ```

use crate::crypto::curve::{Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric};
use rand_core::{CryptoRng, RngCore};

#[derive(Debug, Clone, Copy)]
pub struct RevealTokenProof<C: Curve> {
    pub user_public_key: C::Point,
    pub commitment_t1: C::Point,
    pub commitment_t2: C::Point,
    pub response_s: C::Scalar,
}

#[derive(Debug, Clone, Copy)]
pub struct RevealTokenAndProof<C: Curve> {
    pub reveal_token: C::Point,
    pub proof: RevealTokenProof<C>,
}

#[derive(Debug, Clone)]
pub struct ExpelHandState<C: Curve> {
    pub hand_encrypted: ElGamalCiphertextGeneric<C>,
    pub reveal_tokens: Vec<RevealTokenAndProof<C>>,
}

#[derive(Debug, Clone)]
pub enum RevealProofError {
    InvalidProof,
    InvalidElGamalStructure,
}

// statement: (G, c1) → (pk, token)   两组离散对数相等
// c1 =g^r
// witness: sk                       (log_G(pk) == log_c1(token) == sk)
impl<C: Curve> RevealTokenProof<C> {
    pub fn prove(
        sk: &C::Scalar,
        user_pk: &C::Point,
        encrypted_card: &ElGamalCiphertextGeneric<C>,
        reveal_token: &C::Point,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Self {
        let omega = C::Scalar::random(rng);
        let t1 = C::base_g() * omega;
        let t2 = encrypted_card.c1 * omega;

        let challenge = Self::compute_challenge(
            user_pk,
            &encrypted_card.c1,
            reveal_token,
            &t1,
            &t2,
        );

        let response_s = omega + challenge * *sk;

        RevealTokenProof {
            user_public_key: *user_pk,
            commitment_t1: t1,
            commitment_t2: t2,
            response_s,
        }
    }

    pub fn verify(
        &self,
        encrypted_card: &ElGamalCiphertextGeneric<C>,
        reveal_token: &C::Point,
    ) -> Result<(), RevealProofError> {
        if !encrypted_card.is_valid() {
            return Err(RevealProofError::InvalidElGamalStructure);
        }

        let expected_c = Self::compute_challenge(
            &self.user_public_key,
            &encrypted_card.c1,
            reveal_token,
            &self.commitment_t1,
            &self.commitment_t2,
        );

        let lhs_g = C::base_g() * self.response_s;
        let rhs_g = self.commitment_t1 + self.user_public_key * expected_c;
        if lhs_g != rhs_g {
            return Err(RevealProofError::InvalidProof);
        }

        let lhs_ct = encrypted_card.c1 * self.response_s;
        let rhs_ct = self.commitment_t2 + *reveal_token * expected_c;
        if lhs_ct != rhs_ct {
            return Err(RevealProofError::InvalidProof);
        }
        Ok(())
    }

    fn compute_challenge(
        pk: &C::Point,
        c1: &C::Point,
        reveal_token: &C::Point,
        t1: &C::Point,
        t2: &C::Point,
    ) -> C::Scalar {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(b"reveal_token_proof_v2");
        buffer.extend_from_slice(pk.compress().as_ref());
        buffer.extend_from_slice(c1.compress().as_ref());
        buffer.extend_from_slice(reveal_token.compress().as_ref());
        buffer.extend_from_slice(t1.compress().as_ref());
        buffer.extend_from_slice(t2.compress().as_ref());
        C::hash_to_scalar(&buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::curve::RistrettoCurve;

    type C = RistrettoCurve;
    type ElGamalCiphertext = ElGamalCiphertextGeneric<C>;

    fn setup() -> (<C as Curve>::Scalar, <C as Curve>::Point) {
        let sk = <C as Curve>::Scalar::random(&mut rand_core::OsRng);
        (sk, C::base_g() * sk)
    }

    #[test]
    fn test_reveal_token_and_proof_valid() {
        let (sk, pk) = setup();
        let pt = C::base_g() + C::base_h();
        let r = <C as Curve>::Scalar::random(&mut rand_core::OsRng);
        let ct = ElGamalCiphertext::encrypt(&pt, &pk, &r);

        let reveal_token = ct.gen_reveal_token(&sk);
        assert_eq!(ct.c2 - reveal_token, pt, "token should decrypt to plaintext");

        let proof = RevealTokenProof::<C>::prove(&sk, &pk, &ct, &reveal_token, &mut rand_core::OsRng);
        assert!(proof.verify(&ct, &reveal_token).is_ok(), "Valid proof should pass");
    }

    #[test]
    fn test_wrong_sk_fails() {
        let (_sk, pk) = setup();
        let wrong_sk = <C as Curve>::Scalar::random(&mut rand_core::OsRng);
        let pt = C::base_g() + C::base_h();
        let r = <C as Curve>::Scalar::random(&mut rand_core::OsRng);
        let ct = ElGamalCiphertext::encrypt(&pt, &pk, &r);

        let wrong_token = ct.gen_reveal_token(&wrong_sk);
        let _proof = RevealTokenProof::<C>::prove(&wrong_sk, &pk, &ct, &wrong_token, &mut rand_core::OsRng);

        let _wrong_pt = ct.c2 - wrong_token;
        assert!(RevealTokenProof::<C>::prove(&wrong_sk, &pk, &ct, &wrong_token, &mut rand_core::OsRng)
            .verify(&ct, &wrong_token).is_err(), "Wrong SK fails DLEq");
    }

    #[test]
    fn test_plaintext_binding_is_caller_responsibility() {
        let (sk, pk) = setup();
        let real_pt = C::base_g() + C::base_h();
        let r = <C as Curve>::Scalar::random(&mut rand_core::OsRng);
        let ct = ElGamalCiphertext::encrypt(&real_pt, &pk, &r);

        let reveal_token = ct.gen_reveal_token(&sk);
        let proof = RevealTokenProof::<C>::prove(&sk, &pk, &ct, &reveal_token, &mut rand_core::OsRng);

        assert!(proof.verify(&ct, &reveal_token).is_ok(), "DLEq proof valid regardless of plaintext");
        let computed_pt = ct.c2 - reveal_token;
        assert_eq!(computed_pt, real_pt, "Caller must verify c2 - token == expected plaintext");
    }

    #[test]
    fn test_token_cannot_transfer_to_different_ct() {
        let (sk, pk) = setup();
        let pt = C::base_g() + C::base_h();
        let r1 = <C as Curve>::Scalar::random(&mut rand_core::OsRng);
        let ct1 = ElGamalCiphertext::encrypt(&pt, &pk, &r1);
        let r2 = <C as Curve>::Scalar::random(&mut rand_core::OsRng);
        let ct2 = ElGamalCiphertext::encrypt(&pt, &pk, &r2);

        let token1 = ct1.gen_reveal_token(&sk);
        let proof = RevealTokenProof::<C>::prove(&sk, &pk, &ct1, &token1, &mut rand_core::OsRng);

        assert!(proof.verify(&ct2, &token1).is_err(), "Token for ct1 invalid on ct2");
    }

    #[test]
    fn test_reveal_token_equals_c1_times_sk() {
        let (sk, _pk) = setup();
        let pk = C::base_g() * sk;
        let pt = C::base_h();
        let r = <C as Curve>::Scalar::random(&mut rand_core::OsRng);
        let ct = ElGamalCiphertext::encrypt(&pt, &pk, &r);

        let token = ct.gen_reveal_token(&sk);
        let expected = ct.c1 * sk;
        assert_eq!(token, expected, "reveal_token must equal c1*sk");

        let decrypted = ct.c2 - token;
        assert_eq!(decrypted, pt, "c2 - token must equal plaintext");
    }
}
