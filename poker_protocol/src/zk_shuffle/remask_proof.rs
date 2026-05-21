use crate::crypto::{EcPoint, Scalar, ElGamalCiphertextV2, BASE_G, N_CARDS, hash_to_scalar};
use rand_core::OsRng;
use ff::Field;
use group::{Group, GroupEncoding};
use sha2::{Sha256, Digest};
use rand_core::RngCore;

#[derive(Debug, Clone)]
pub struct RemaskProof {
    pub A: EcPoint,
    pub B: EcPoint,
    pub sum_c1: EcPoint,
    pub sum_d2: EcPoint,
    pub s: Scalar,
    pub nonce: Scalar,
}

impl RemaskProof {
    pub fn prove(
        input_cts: &[ElGamalCiphertextV2],
        output_cts: &[ElGamalCiphertextV2],
        player_sk: &Scalar,
        player_pk: &EcPoint,
    ) -> Self {
        let n = input_cts.len().min(output_cts.len()).min(N_CARDS);
        let mut rng = OsRng;

        let omega = Scalar::random(&mut rng);
        let A = *BASE_G * omega;

        let rhos = Self::derive_rho(player_pk, &A, n);

        let mut sum_c1 = EcPoint::IDENTITY;
        let mut sum_d2 = EcPoint::IDENTITY;
        for i in 0..n {
            let d2 = output_cts[i].c2 - input_cts[i].c2;
            sum_c1 = sum_c1 + input_cts[i].c1 * rhos[i];
            sum_d2 = sum_d2 + d2 * rhos[i];
        }

        let B = sum_c1 * omega;
        let nonce = Scalar::random(&mut rng);

        let c = Self::hash_challenge(player_pk, &A, &B, &sum_c1, &sum_d2, &nonce);
        let s = omega + c * player_sk;

        RemaskProof { A, B, sum_c1, sum_d2, s, nonce }
    }

    pub fn verify(&self, input_cts: &[ElGamalCiphertextV2], output_cts: &[ElGamalCiphertextV2], player_pk: &EcPoint) -> bool {
        let n = input_cts.len().min(output_cts.len()).min(N_CARDS);

        let rhos = Self::derive_rho(player_pk, &self.A, n);

        let mut sum_c1 = EcPoint::IDENTITY;
        let mut sum_d2 = EcPoint::IDENTITY;
        for i in 0..n {
            let d2 = output_cts[i].c2 - input_cts[i].c2;
            sum_c1 = sum_c1 + input_cts[i].c1 * rhos[i];
            sum_d2 = sum_d2 + d2 * rhos[i];
        }

        let c = Self::hash_challenge(player_pk, &self.A, &self.B, &sum_c1, &sum_d2, &self.nonce);

        *BASE_G * self.s == self.A + *player_pk * c
            && sum_c1 * self.s == self.B + sum_d2 * c
    }

    fn derive_rho(pk: &EcPoint, A: &EcPoint, n: usize) -> Vec<Scalar> {
        (0..n).map(|i| {
            let mut h = Sha256::new();
            h.update(b"remask_rho");
            h.update(pk.to_affine().to_bytes());
            h.update(A.to_affine().to_bytes());
            h.update(&i.to_le_bytes());
            hash_to_scalar(&h.finalize())
        }).collect()
    }

    fn hash_challenge(pk: &EcPoint, A: &EcPoint, B: &EcPoint, sum_c1: &EcPoint, sum_d2: &EcPoint, nonce: &Scalar) -> Scalar {
        let mut h = Sha256::new();
        h.update(b"remask_batch_dleq");
        for pt in [pk, A, B, sum_c1, sum_d2] { h.update(pt.to_affine().to_bytes()); }
        h.update(nonce.to_bytes());
        hash_to_scalar(&h.finalize())
    }
}

pub fn remask_ciphertext(ct: &ElGamalCiphertextV2, sk: &Scalar, pk: &EcPoint, rng: &mut impl RngCore) -> ElGamalCiphertextV2 {
    let r_prime = Scalar::random(rng);
    if ct.c1 == EcPoint::IDENTITY {
         ct.re_encrypt(pk, &r_prime)
    }else{
        let mut mask_card = ct.clone();
        mask_card.c2 = mask_card.c2 + mask_card.c1*sk;
        mask_card
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::elgamal::ElGamalCiphertextV2;
    use crate::crypto::BASE_H;
    use crate::z_poker::convert::hex_to_ecpoint;
    use rand_core::RngCore;
    use sha2::digest::Output;

    fn gen_keypair(rng: &mut impl RngCore) -> (Scalar, EcPoint) {
        let sk = Scalar::random(rng);
        (sk.clone(), *BASE_G * sk)
    }

    fn make_remask_pair(input: &ElGamalCiphertextV2, sk: &Scalar, pk: &EcPoint, rng: &mut impl RngCore) -> ElGamalCiphertextV2 {
        let r_prime = Scalar::random(rng);
        ElGamalCiphertextV2 {
            c1: input.c1 + *BASE_G * r_prime,
            c2: input.c2 + input.c1 * sk,
            c3: input.c3 + *BASE_H * r_prime,
        }
    }

    #[test]
    fn test_honest_prover_passes() {
        let mut rng = OsRng;
        let (sk, pk) = gen_keypair(&mut rng);
        let plaintexts: Vec<EcPoint> = (0..N_CARDS).map(|i| *BASE_H * Scalar::from(i as u64)).collect();
        let r_values: Vec<Scalar> = (0..N_CARDS).map(|_| Scalar::random(&mut rng)).collect();

        let input_cts: Vec<ElGamalCiphertextV2> = (0..N_CARDS)
            .map(|i| ElGamalCiphertextV2::encrypt(&plaintexts[i], &pk, &r_values[i])).collect();
        let output_cts: Vec<ElGamalCiphertextV2> = (0..N_CARDS)
            .map(|i| remask_ciphertext(&input_cts[i], &sk, &pk, &mut rng)).collect();

        let proof = RemaskProof::prove(&input_cts, &output_cts, &sk, &pk);
        assert!(proof.verify(&input_cts, &output_cts, &pk), "honest prover should pass");
    }

    #[test]
    fn test_honest_prover_passes_2() {
        let mut rng = OsRng;
        let (sk, pk) = gen_keypair(&mut rng);
        
        let plaintexts: Vec<EcPoint> = (0..N_CARDS).map(|i| *BASE_G * Scalar::from(i as u64)).collect();
        let r_values: Vec<Scalar> = (0..N_CARDS).map(|_| Scalar::random(&mut rng)).collect();

        let input_cts: Vec<ElGamalCiphertextV2> = (0..N_CARDS)
            .map(|i| ElGamalCiphertextV2 {
                c1: EcPoint::IDENTITY,
                c2: plaintexts[i] ,
                c3: EcPoint::IDENTITY,
            }).collect();

        let mut output_cts = Vec::new();
        for i in 0..input_cts.len() {
            let mut mask_card = input_cts[i].clone();
            mask_card.c2 = mask_card.c2 + mask_card.c1*sk;
            output_cts.push(mask_card);
        }
        // let output_cts: Vec<ElGamalCiphertextV2> = (0..N_CARDS)
        //     .map(|i| make_remask_pair(&input_cts[i], &sk, &pk, &mut rng)).collect();

        let proof = RemaskProof::prove(&input_cts, &output_cts, &sk, &pk);
        assert!(proof.verify(&input_cts, &output_cts, &pk), "honest prover should pass");
    }

    #[test]
    fn test_honest_prover_passes_3() {
       let mut rng = OsRng;
        let (sk, pk) = gen_keypair(&mut rng);
        let plaintexts: Vec<EcPoint> = (0..N_CARDS).map(|i| *BASE_H * Scalar::from(i as u64)).collect();
        let r_values: Vec<Scalar> = (0..N_CARDS).map(|_| Scalar::random(&mut rng)).collect();

        let input_cts: Vec<ElGamalCiphertextV2> = (0..N_CARDS)
            .map(|i| ElGamalCiphertextV2::encrypt(&plaintexts[i], &pk, &r_values[i])).collect();

        let (sk2, pk2) = gen_keypair(&mut rng);
        let mut output_cts = Vec::new();
        for i in 0..input_cts.len() {
            let mut mask_card = input_cts[i].clone();
            mask_card.c2 = mask_card.c2 + mask_card.c1*sk2;
            output_cts.push(mask_card);
        }

        let proof = RemaskProof::prove(&input_cts, &output_cts, &sk2, &pk2);
        assert!(proof.verify(&input_cts, &output_cts, &pk2), "honest prover should pass");
    }

    #[test]
    fn test_gen_keys(){
        use crate::z_poker::convert::ecpoint_to_hex;
        let mut rng = OsRng;
        let origin = "000000000000000000000000000000000000000000000000000000000000000000";
        let c1 = hex_to_ecpoint(origin).unwrap();
        let ct = ElGamalCiphertextV2 {
            c1: c1,
            c2: EcPoint::random(rng),
            c3: EcPoint::IDENTITY,
        };

        let (sk2, pk2) = gen_keypair(&mut rng);

        let ct = remask_ciphertext(&ct, &sk2, &pk2, &mut rng);

        println!("is identity {}", EcPoint::identity().to_affine() == ct.c1.to_affine());
        let agg_pk_hex = ecpoint_to_hex(&ct.c1);
        println!("agg_pk {}", agg_pk_hex);
    }


    #[test]
    fn test_wrong_sk_fails() {
        let mut rng = OsRng;
        let (sk, pk) = gen_keypair(&mut rng);
        let (_, wrong_pk) = gen_keypair(&mut rng);
        let plaintexts: Vec<EcPoint> = (0..N_CARDS).map(|i| *BASE_H * Scalar::from(i as u64)).collect();
        let r_values: Vec<Scalar> = (0..N_CARDS).map(|_| Scalar::random(&mut rng)).collect();

        let input_cts: Vec<ElGamalCiphertextV2> = (0..N_CARDS)
            .map(|i| ElGamalCiphertextV2::encrypt(&plaintexts[i], &pk, &r_values[i])).collect();
        let output_cts: Vec<ElGamalCiphertextV2> = (0..N_CARDS)
            .map(|i| make_remask_pair(&input_cts[i], &sk, &pk, &mut rng)).collect();

        let proof = RemaskProof::prove(&input_cts, &output_cts, &sk, &pk);
        assert!(!proof.verify(&input_cts, &output_cts, &wrong_pk), "wrong pk should fail");
    }

    #[test]
    fn test_tampered_output_fails() {
        let mut rng = OsRng;
        let (sk, pk) = gen_keypair(&mut rng);
        let plaintexts: Vec<EcPoint> = (0..N_CARDS).map(|i| *BASE_H * Scalar::from(i as u64)).collect();
        let r_values: Vec<Scalar> = (0..N_CARDS).map(|_| Scalar::random(&mut rng)).collect();

        let input_cts: Vec<ElGamalCiphertextV2> = (0..N_CARDS)
            .map(|i| ElGamalCiphertextV2::encrypt(&plaintexts[i], &pk, &r_values[i])).collect();
        let output_cts: Vec<ElGamalCiphertextV2> = (0..N_CARDS)
            .map(|i| make_remask_pair(&input_cts[i], &sk, &pk, &mut rng)).collect();

        let proof = RemaskProof::prove(&input_cts, &output_cts, &sk, &pk);

        let mut tampered = output_cts.clone();
        tampered[0] = make_remask_pair(&tampered[0], &sk, &pk, &mut rng);
        assert!(!proof.verify(&input_cts, &tampered, &pk), "tampered output should fail");
    }

    #[test]
    fn test_tampered_input_fails() {
        let mut rng = OsRng;
        let (sk, pk) = gen_keypair(&mut rng);
        let plaintexts: Vec<EcPoint> = (0..N_CARDS).map(|i| *BASE_H * Scalar::from(i as u64)).collect();
        let r_values: Vec<Scalar> = (0..N_CARDS).map(|_| Scalar::random(&mut rng)).collect();

        let input_cts: Vec<ElGamalCiphertextV2> = (0..N_CARDS)
            .map(|i| ElGamalCiphertextV2::encrypt(&plaintexts[i], &pk, &r_values[i])).collect();
        let output_cts: Vec<ElGamalCiphertextV2> = (0..N_CARDS)
            .map(|i| make_remask_pair(&input_cts[i], &sk, &pk, &mut rng)).collect();

        let proof = RemaskProof::prove(&input_cts, &output_cts, &sk, &pk);

        let mut tampered = input_cts.clone();
        tampered[1] = ElGamalCiphertextV2::encrypt(&(*BASE_H * Scalar::from(99u64)), &pk, &Scalar::random(&mut rng));
        assert!(!proof.verify(&tampered, &output_cts, &pk), "tampered input should fail");
    }

    #[test]
    fn test_wrong_prover_sk_fails() {
        let mut rng = OsRng;
        let (sk, pk) = gen_keypair(&mut rng);
        let (wrong_sk, _) = gen_keypair(&mut rng);
        let plaintexts: Vec<EcPoint> = (0..N_CARDS).map(|i| *BASE_H * Scalar::from(i as u64)).collect();
        let r_values: Vec<Scalar> = (0..N_CARDS).map(|_| Scalar::random(&mut rng)).collect();

        let input_cts: Vec<ElGamalCiphertextV2> = (0..N_CARDS)
            .map(|i| ElGamalCiphertextV2::encrypt(&plaintexts[i], &pk, &r_values[i])).collect();
        let output_cts: Vec<ElGamalCiphertextV2> = (0..N_CARDS)
            .map(|i| make_remask_pair(&input_cts[i], &sk, &pk, &mut rng)).collect();

        let proof = RemaskProof::prove(&input_cts, &output_cts, &wrong_sk, &pk);
        assert!(!proof.verify(&input_cts, &output_cts, &pk), "prover with wrong sk should fail");
    }

    #[test]
    fn test_single_card() {
        let mut rng = OsRng;
        let (sk, pk) = gen_keypair(&mut rng);
        let pt = *BASE_H * Scalar::from(42u64);
        let r = Scalar::random(&mut rng);
        let input = ElGamalCiphertextV2::encrypt(&pt, &pk, &r);
        let output = make_remask_pair(&input, &sk, &pk, &mut rng);

        let proof = RemaskProof::prove(&[input.clone()], &[output.clone()], &sk, &pk);
        assert!(proof.verify(&[input], &[output], &pk), "single card should pass");
    }

    #[test]
    fn test_single_card_two_user() {
        let mut rng = OsRng;
        let (sk, pk) = gen_keypair(&mut rng);
        let pt = *BASE_G * Scalar::from(42u64);
        let input = ElGamalCiphertextV2 { c1: EcPoint::IDENTITY, c2: pt, c3: EcPoint::IDENTITY };
        let r_prime = Scalar::random(&mut rng);
        let enc_one  = input.re_encrypt(&pk, &r_prime);
        // let output = make_remask_pair(&input, &sk, &pk, &mut rng);
        let mut output = enc_one.clone();

        let (sk2, pk2) = gen_keypair(&mut rng);
        output.c2 += output.c1 * sk2; //user2 join 

        let proof = RemaskProof::prove(&[enc_one.clone()], &[output.clone()], &sk2, &pk2);
        assert!(proof.verify(&[enc_one.clone()], &[output.clone()], &pk2), "single card should pass");

        let reveal_token1 = output.gen_reveal_token(&sk);
        let reveal_token2 = output.gen_reveal_token(&sk2);

        let decrypted = output.c2 - reveal_token1-reveal_token2;
        assert_eq!(decrypted.to_affine(),pt.to_affine());
    }

    #[test]
    fn test_single_card_one_user() {
        let mut rng = OsRng;
        let (sk, pk) = gen_keypair(&mut rng);
        let pt = *BASE_G * Scalar::from(42u64);
        let input = ElGamalCiphertextV2 { c1: EcPoint::IDENTITY, c2: pt, c3: EcPoint::IDENTITY };
        let r_prime = Scalar::random(&mut rng);
        let mut output = input.clone();

        output.c2 += output.c1 * sk; //user2 join 

        let proof = RemaskProof::prove(&[input.clone()], &[output.clone()], &sk, &pk);
        assert!(proof.verify(&[input.clone()], &[output.clone()], &pk), "single card should pass");

        let reveal_token1 = output.clone().gen_reveal_token(&sk);


        let decrypted = output.c2 - reveal_token1;
        println!("{:?},{:?},{:?},{:?}",output.c2.to_affine(), reveal_token1.to_affine(),decrypted.to_affine(),pt.to_affine());

        assert_eq!(decrypted.to_affine(),pt.to_affine());
    }

}
