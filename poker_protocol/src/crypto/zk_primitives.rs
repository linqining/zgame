use super::types::{EcPoint, Scalar, BASE_G, BASE_H, N_CARDS, hash_to_scalar};
use super::elgamal::ElGamalCiphertextV2;
use ff::Field;
use group::{Group, GroupEncoding};
use sha2::{Sha256, Digest};
use rand_core::RngCore;

#[derive(Debug, Clone)]
pub struct TripleDLEqProof {
    pub A_g: EcPoint,
    pub A_pk: EcPoint,
    pub A_h: EcPoint,
    pub s: Scalar,
}

impl TripleDLEqProof {
    pub fn prove(sum_input_c1: &EcPoint, sum_input_c2: &EcPoint, sum_input_c3: &EcPoint,
        sum_output_c1: &EcPoint, sum_output_c2: &EcPoint, sum_output_c3: &EcPoint,
        total_r: &Scalar, pk: &EcPoint, rng: &mut impl RngCore) -> Self {
        let w = Scalar::random(rng);
        let (A_g, A_pk, A_h) = (*BASE_G * w, *pk * w, *BASE_H * w);
        let challenge = Self::hash_to_challenge(pk, &A_g, &A_pk, &A_h,
            &(sum_output_c1 - sum_input_c1), &(sum_output_c2 - sum_input_c2), &(sum_output_c3 - sum_input_c3));
        TripleDLEqProof { A_g, A_pk, A_h, s: w + challenge * total_r }
    }

    pub fn prove_commitments(sum_input_c1: &EcPoint, sum_input_c2: &EcPoint, sum_input_c3: &EcPoint,
        sum_output_c1: &EcPoint, sum_output_c2: &EcPoint, sum_output_c3: &EcPoint,
        total_r: &Scalar, pk: &EcPoint, rng: &mut impl RngCore)
        -> (EcPoint, EcPoint, EcPoint, EcPoint, EcPoint, EcPoint, Scalar, Scalar) {
        let w = Scalar::random(rng);
        let (A_g, A_pk, A_h) = (*BASE_G * w, *pk * w, *BASE_H * w);
        (A_g, A_pk, A_h, sum_output_c1 - sum_input_c1, sum_output_c2 - sum_input_c2, sum_output_c3 - sum_input_c3, w, *total_r)
    }

    pub fn respond(A_g: EcPoint, A_pk: EcPoint, A_h: EcPoint, challenge: &Scalar, w: &Scalar, total_r: &Scalar) -> Self {
        TripleDLEqProof { A_g, A_pk, A_h, s: w + challenge * total_r }
    }

    pub fn verify_with_challenge(&self, sum_input_c1: &EcPoint, sum_input_c2: &EcPoint, sum_input_c3: &EcPoint,
        sum_output_c1: &EcPoint, sum_output_c2: &EcPoint, sum_output_c3: &EcPoint,
        pk: &EcPoint, external_challenge: &Scalar) -> bool {
        let (d1, d2, d3) = (sum_output_c1 - sum_input_c1, sum_output_c2 - sum_input_c2, sum_output_c3 - sum_input_c3);
        *BASE_G * self.s == self.A_g + d1 * *external_challenge
            && *pk * self.s == self.A_pk + d2 * *external_challenge
            && *BASE_H * self.s == self.A_h + d3 * *external_challenge
    }

    pub fn verify(&self, sum_input_c1: &EcPoint, sum_input_c2: &EcPoint, sum_input_c3: &EcPoint,
        sum_output_c1: &EcPoint, sum_output_c2: &EcPoint, sum_output_c3: &EcPoint, pk: &EcPoint) -> bool {
        let (d1, d2, d3) = (sum_output_c1 - sum_input_c1, sum_output_c2 - sum_input_c2, sum_output_c3 - sum_input_c3);
        let c = Self::hash_to_challenge(pk, &self.A_g, &self.A_pk, &self.A_h, &d1, &d2, &d3);
        *BASE_G * self.s == self.A_g + d1 * c && *pk * self.s == self.A_pk + d2 * c && *BASE_H * self.s == self.A_h + d3 * c
    }

    fn hash_to_challenge(pk: &EcPoint, A_g: &EcPoint, A_pk: &EcPoint, A_h: &EcPoint, d1: &EcPoint, d2: &EcPoint, d3: &EcPoint) -> Scalar {
        let mut h = Sha256::new();
        h.update(b"triple_dleq_v2_secure");
        for pt in [pk, A_g, A_pk, A_h, d1, d2, d3] { h.update(pt.to_affine().to_bytes()); }
        hash_to_scalar(&h.finalize())
    }
}

#[derive(Debug, Clone)]
pub struct ProductArgumentV2 {
    pub A: EcPoint, pub B: EcPoint, pub C: EcPoint, pub D: EcPoint, pub s: Scalar, pub t: Scalar,
}

impl ProductArgumentV2 {
    pub fn prove(input_cts: &[ElGamalCiphertextV2], output_cts: &[ElGamalCiphertextV2],
        _permute: &[usize; N_CARDS], r_values: &[Scalar], _pk: &EcPoint, rng: &mut impl RngCore) -> Self {
        let (alpha, beta) = (Scalar::random(&mut *rng), Scalar::random(&mut *rng));
        let (mut pi, mut po) = (EcPoint::IDENTITY, EcPoint::IDENTITY);
        for ct in input_cts.iter().take(N_CARDS) { if !bool::from(ct.c1.is_identity()) { pi = pi + ct.c1; } }
        for ct in output_cts.iter().take(N_CARDS) { if !bool::from(ct.c1.is_identity()) { po = po + ct.c1; } }
        let total_r = r_values.iter().take(N_CARDS).fold(Scalar::ZERO, |a, r| a + r);
        let (A, B, C, D) = (*BASE_G * alpha, pi * beta, (po - pi) * alpha, *BASE_G * total_r * beta);
        let c = Self::hash_to_challenge(_pk, &A, &B, &C, &D, input_cts, output_cts);
        ProductArgumentV2 { A, B, C, D, s: alpha + c * total_r, t: beta + c * Scalar::ONE }
    }

    pub fn prove_commitments(input_cts: &[ElGamalCiphertextV2], output_cts: &[ElGamalCiphertextV2],
        r_values: &[Scalar], rng: &mut impl RngCore) -> (EcPoint, EcPoint, EcPoint, EcPoint, EcPoint, EcPoint, Scalar, Scalar, Scalar) {
        let (alpha, beta) = (Scalar::random(&mut *rng), Scalar::random(&mut *rng));
        let (mut pi, mut po) = (EcPoint::IDENTITY, EcPoint::IDENTITY);
        for ct in input_cts.iter().take(N_CARDS) { if !bool::from(ct.c1.is_identity()) { pi = pi + ct.c1; } }
        for ct in output_cts.iter().take(N_CARDS) { if !bool::from(ct.c1.is_identity()) { po = po + ct.c1; } }
        let tr = r_values.iter().take(N_CARDS).fold(Scalar::ZERO, |a, r| a + r);
        (*BASE_G * alpha, pi * beta, (po - pi) * alpha, *BASE_G * tr * beta, pi, po, alpha, beta, tr)
    }

    pub fn respond(A: EcPoint, B: EcPoint, C: EcPoint, D: EcPoint, c: &Scalar, a: &Scalar, b: &Scalar, tr: &Scalar) -> Self {
        ProductArgumentV2 { A, B, C, D, s: a + c * tr, t: b + *c * Scalar::ONE }
    }

    pub fn verify_with_challenge(&self, input_cts: &[ElGamalCiphertextV2], output_cts: &[ElGamalCiphertextV2],
        _pk: &EcPoint, ec: &Scalar) -> bool {
        let (mut pi, mut po) = (EcPoint::IDENTITY, EcPoint::IDENTITY);
        for ct in input_cts.iter().take(N_CARDS) { if !bool::from(ct.c1.is_identity()) { pi = pi + ct.c1; } }
        for ct in output_cts.iter().take(N_CARDS) { if !bool::from(ct.c1.is_identity()) { po = po + ct.c1; } }
        *BASE_G * self.s == self.A + (po - pi) * *ec && pi * self.t == self.B + pi * *ec
    }

    pub fn verify(&self, input_cts: &[ElGamalCiphertextV2], output_cts: &[ElGamalCiphertextV2], pk: &EcPoint) -> bool {
        let (mut pi, mut po) = (EcPoint::IDENTITY, EcPoint::IDENTITY);
        for ct in input_cts.iter().take(N_CARDS) { if !bool::from(ct.c1.is_identity()) { pi = pi + ct.c1; } }
        for ct in output_cts.iter().take(N_CARDS) { if !bool::from(ct.c1.is_identity()) { po = po + ct.c1; } }
        let c = Self::hash_to_challenge(pk, &self.A, &self.B, &self.C, &self.D, input_cts, output_cts);
        *BASE_G * self.s == self.A + (po - pi) * c && pi * self.t == self.B + pi * c
    }

    fn hash_to_challenge(pk: &EcPoint, A: &EcPoint, B: &EcPoint, C: &EcPoint, D: &EcPoint,
        input_cts: &[ElGamalCiphertextV2], output_cts: &[ElGamalCiphertextV2]) -> Scalar {
        let mut h = Sha256::new();
        for pt in [pk, A, B, C, D] { h.update(pt.to_affine().to_bytes()); }
        for ct in input_cts.iter().take(N_CARDS) { for p in [&ct.c1, &ct.c2, &ct.c3] { h.update(p.to_affine().to_bytes()); } }
        for ct in output_cts.iter().take(N_CARDS) { for p in [&ct.c1, &ct.c2, &ct.c3] { h.update(p.to_affine().to_bytes()); } }
        hash_to_scalar(&h.finalize())
    }
}
