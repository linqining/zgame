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

use crate::crypto::{BASE_G, EcPoint, ElGamalCiphertext, Scalar};
use ff::{Field, PrimeField};
use group::{Group, GroupEncoding};
use rand_core::RngCore;
use sha2::{Sha256, Digest};

#[derive(Debug, Clone,Copy)]
pub struct RevealTokenProof {
    pub user_public_key: EcPoint,
    pub commitment_t1: EcPoint,
    pub commitment_t2: EcPoint,
    pub response_s: Scalar,
}

#[derive(Debug, Clone)]
pub enum RevealProofError {
    InvalidProof,
    InvalidElGamalStructure,
}

// statement: (G, c1) → (pk, token)   两组离散对数相等
// c1 =g^r 
// witness: sk                       (log_G(pk) == log_c1(token) == sk)
impl RevealTokenProof {
    pub fn prove(
        sk: &Scalar,
        user_pk: &EcPoint,
        encrypted_card: &ElGamalCiphertext,
        reveal_token: &EcPoint,
        rng: &mut (impl RngCore + ?Sized),
    ) -> Self {
        let omega = Scalar::random(rng);
        let t1 = *BASE_G * omega;
        let t2 = encrypted_card.c1 * omega;


        let challenge = Self::compute_challenge(
            user_pk,
            &encrypted_card.c1,  // c1*sk = reveal token
            reveal_token,
            &t1,
            &t2,
        );

        let response_s = omega + challenge * sk;

        RevealTokenProof {
            user_public_key: *user_pk,
            commitment_t1: t1,
            commitment_t2: t2,
            response_s,
        }
    }

    pub fn verify(
        &self,
        encrypted_card: &ElGamalCiphertext,
        reveal_token: &EcPoint,
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

        let lhs_g = *BASE_G * self.response_s;
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
        pk: &EcPoint,
        c1: &EcPoint,
        reveal_token: &EcPoint,
        t1: &EcPoint,
        t2: &EcPoint,
    ) -> Scalar {
        let mut hasher = Sha256::new();
        hasher.update(b"reveal_token_proof_v2");
        hasher.update(&pk.to_bytes()[..]);
        hasher.update(&c1.to_bytes()[..]);
        hasher.update(&reveal_token.to_bytes()[..]);
        hasher.update(&t1.to_bytes()[..]);
        hasher.update(&t2.to_bytes()[..]);

        let digest = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&digest);
        match Option::<Scalar>::from(Scalar::from_repr(bytes.into())) {
            Some(s) if s != Scalar::ZERO => s,
            _ => {
                let mut h = Sha256::new();
                h.update(b"reveal_v2_retry:");
                h.update(&bytes[..]);
                let retry = h.finalize();
                let mut rb = [0u8; 32];
                rb.copy_from_slice(&retry);
                Option::<Scalar>::from(Scalar::from_repr(rb.into())).unwrap_or(Scalar::ONE)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{BASE_H, ElGamalCiphertext};

    fn setup() -> (Scalar, EcPoint) {
        let sk = Scalar::random(&mut rand_core::OsRng);
        (sk, *BASE_G * sk)
    }

    #[test]
    fn test_reveal_token_and_proof_valid() {
        let (sk, pk) = setup();
        let pt = *BASE_G + *BASE_H;
        let r = Scalar::random(&mut rand_core::OsRng);
        let ct = ElGamalCiphertext::encrypt(&pt, &pk, &r);

        let reveal_token = ct.gen_reveal_token(&sk);
        assert_eq!(ct.c2 - reveal_token, pt, "token should decrypt to plaintext");

        let proof = RevealTokenProof::prove(&sk, &pk, &ct, &reveal_token, &mut rand_core::OsRng);
        assert!(proof.verify(&ct, &reveal_token).is_ok(), "Valid proof should pass");
    }

    #[test]
    fn test_wrong_sk_fails() {
        let (_sk, pk) = setup();
        let wrong_sk = Scalar::random(&mut rand_core::OsRng);
        let pt = *BASE_G + *BASE_H;
        let r = Scalar::random(&mut rand_core::OsRng);
        let ct = ElGamalCiphertext::encrypt(&pt, &pk, &r);

        let wrong_token = ct.gen_reveal_token(&wrong_sk);
        let _proof = RevealTokenProof::prove(&wrong_sk, &pk, &ct, &wrong_token, &mut rand_core::OsRng);

        let wrong_pt = ct.c2 - wrong_token;
        assert!(RevealTokenProof::prove(&wrong_sk, &pk, &ct, &wrong_token, &mut rand_core::OsRng)
            .verify(&ct, &wrong_token).is_err(), "Wrong SK fails DLEq");
    }

    #[test]
    fn test_plaintext_binding_is_caller_responsibility() {
        let (sk, pk) = setup();
        let real_pt = *BASE_G + *BASE_H;
        let r = Scalar::random(&mut rand_core::OsRng);
        let ct = ElGamalCiphertext::encrypt(&real_pt, &pk, &r);

        let reveal_token = ct.gen_reveal_token(&sk);
        let proof = RevealTokenProof::prove(&sk, &pk, &ct, &reveal_token, &mut rand_core::OsRng);

        assert!(proof.verify(&ct, &reveal_token).is_ok(), "DLEq proof valid regardless of plaintext");
        let computed_pt = ct.c2 - reveal_token;
        assert_eq!(computed_pt, real_pt, "Caller must verify c2 - token == expected plaintext");
    }

    #[test]
    fn test_token_cannot_transfer_to_different_ct() {
        let (sk, pk) = setup();
        let pt = *BASE_G + *BASE_H;
        let r1 = Scalar::random(&mut rand_core::OsRng);
        let ct1 = ElGamalCiphertext::encrypt(&pt, &pk, &r1);
        let r2 = Scalar::random(&mut rand_core::OsRng);
        let ct2 = ElGamalCiphertext::encrypt(&pt, &pk, &r2);

        let token1 = ct1.gen_reveal_token(&sk);
        let proof = RevealTokenProof::prove(&sk, &pk, &ct1, &token1, &mut rand_core::OsRng);

        assert!(proof.verify(&ct2, &token1).is_err(), "Token for ct1 invalid on ct2");
    }

    #[test]
    fn test_reveal_token_equals_c1_times_sk() {
        let (sk, _pk) = setup();
        let pk = *BASE_G * sk;
        let pt = *BASE_H;
        let r = Scalar::random(&mut rand_core::OsRng);
        let ct = ElGamalCiphertext::encrypt(&pt, &pk, &r);

        let token = ct.gen_reveal_token(&sk);
        let expected = ct.c1 * sk;
        assert_eq!(token, expected, "reveal_token must equal c1*sk");

        let decrypted = ct.c2 - token;
        assert_eq!(decrypted, pt, "c2 - token must equal plaintext");
    }
}
