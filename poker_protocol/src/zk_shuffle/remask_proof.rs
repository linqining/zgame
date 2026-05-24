use crate::crypto::curve::{Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric};
use rand_core::{CryptoRng, RngCore, OsRng};

#[derive(Debug, Clone)]
pub struct RemaskProof<C: Curve> {
    pub commitment_a: C::Point,
    pub commitment_b: C::Point,
    pub response: C::Scalar,
    pub nonce: C::Scalar,
}

impl<C: Curve> RemaskProof<C> {
    pub fn prove(
        input_cts: &[ElGamalCiphertextGeneric<C>],
        output_cts: &[ElGamalCiphertextGeneric<C>],
        player_sk: &C::Scalar,
        player_pk: &C::Point,
    ) -> Self {
        let n = input_cts.len().min(output_cts.len()).min(C::n_cards());
        let mut rng = OsRng;

        let omega = C::Scalar::random(&mut rng);
        let commitment_a = C::base_g() * omega;

        let rhos = Self::derive_rho(player_pk, &commitment_a, n);

        let points_c1: Vec<C::Point> = input_cts[..n].iter().map(|ct| ct.c1).collect();
        let points_d2: Vec<C::Point> = (0..n).map(|i| output_cts[i].c2 - input_cts[i].c2).collect();

        let sum_c1 = C::Point::vartime_multiscalar_mul(&rhos, &points_c1);
        let sum_d2 = C::Point::vartime_multiscalar_mul(&rhos, &points_d2);

        let commitment_b = sum_c1 * omega;
        let nonce = C::Scalar::random(&mut rng);

        let c = Self::hash_challenge(player_pk, &commitment_a, &commitment_b, &sum_c1, &sum_d2, &nonce);
        let response = omega + c * *player_sk;

        RemaskProof { commitment_a, commitment_b, response, nonce }
    }

    pub fn verify(&self, input_cts: &[ElGamalCiphertextGeneric<C>], output_cts: &[ElGamalCiphertextGeneric<C>], player_pk: &C::Point) -> bool {
        let n = input_cts.len().min(output_cts.len()).min(C::n_cards());

        let rhos = Self::derive_rho(player_pk, &self.commitment_a, n);

        let points_c1: Vec<C::Point> = input_cts[..n].iter().map(|ct| ct.c1).collect();
        let points_d2: Vec<C::Point> = (0..n).map(|i| output_cts[i].c2 - input_cts[i].c2).collect();

        let sum_c1 = C::Point::vartime_multiscalar_mul(&rhos, &points_c1);
        let sum_d2 = C::Point::vartime_multiscalar_mul(&rhos, &points_d2);

        let c = Self::hash_challenge(player_pk, &self.commitment_a, &self.commitment_b, &sum_c1, &sum_d2, &self.nonce);

        C::base_g() * self.response == self.commitment_a + *player_pk * c
            && sum_c1 * self.response == self.commitment_b + sum_d2 * c
    }

    fn derive_rho(pk: &C::Point, commitment_a: &C::Point, n: usize) -> Vec<C::Scalar> {
        (0..n).map(|i| {
            let mut buffer = Vec::new();
            buffer.extend_from_slice(b"remask_rho");
            buffer.extend_from_slice(pk.compress().as_ref());
            buffer.extend_from_slice(commitment_a.compress().as_ref());
            buffer.extend_from_slice(&i.to_le_bytes());
            C::hash_to_scalar(&buffer)
        }).collect()
    }

    fn hash_challenge(pk: &C::Point, commitment_a: &C::Point, commitment_b: &C::Point, sum_c1: &C::Point, sum_d2: &C::Point, nonce: &C::Scalar) -> C::Scalar {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(b"remask_batch_dleq");
        for pt in [pk, commitment_a, commitment_b, sum_c1, sum_d2] {
            buffer.extend_from_slice(pt.compress().as_ref());
        }
        buffer.extend_from_slice(&nonce.as_bytes());
        C::hash_to_scalar(&buffer)
    }
}

pub fn remask_ciphertext<C: Curve>(ct: &ElGamalCiphertextGeneric<C>, sk: &C::Scalar, pk: &C::Point, rng: &mut (impl CryptoRng + RngCore)) -> ElGamalCiphertextGeneric<C> {
    let r_prime = C::Scalar::random(rng);
    if ct.c1 == C::Point::identity() {
         ct.re_encrypt(pk, &r_prime)
    } else {
        let mut mask_card = ct.clone();
        mask_card.c2 = mask_card.c2 + mask_card.c1 * *sk;
        mask_card
    }
}

/// Type alias for Ristretto255 RemaskProof (backward compatibility).
pub type RistrettoRemaskProof = RemaskProof<crate::crypto::curve::RistrettoCurve>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::curve::RistrettoCurve;
    use crate::z_poker::convert::{hex_to_ecpoint, ecpoint_to_hex};

    type RistrettoElGamalCiphertext = ElGamalCiphertextGeneric<RistrettoCurve>;

    fn gen_keypair<C: Curve>(rng: &mut (impl CryptoRng + RngCore)) -> (C::Scalar, C::Point) {
        let sk = C::Scalar::random(rng);
        (sk, C::base_g() * sk)
    }

    fn make_remask_pair<C: Curve>(input: &ElGamalCiphertextGeneric<C>, sk: &C::Scalar, pk: &C::Point, rng: &mut (impl CryptoRng + RngCore)) -> ElGamalCiphertextGeneric<C> {
        let r_prime = C::Scalar::random(rng);
        ElGamalCiphertextGeneric {
            c1: input.c1 + C::base_g() * r_prime,
            c2: input.c2 + input.c1 * *sk,
        }
    }

    #[test]
    fn test_honest_prover_passes() {
        let mut rng = OsRng;
        let (sk, pk) = gen_keypair::<RistrettoCurve>(&mut rng);
        let plaintexts: Vec<_> = (0..RistrettoCurve::n_cards()).map(|i| RistrettoCurve::base_h() * <RistrettoCurve as Curve>::Scalar::from_u64(i as u64)).collect();
        let r_values: Vec<_> = (0..RistrettoCurve::n_cards()).map(|_| <RistrettoCurve as Curve>::Scalar::random(&mut rng)).collect();

        let input_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| RistrettoElGamalCiphertext::encrypt(&plaintexts[i], &pk, &r_values[i])).collect();
        let output_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| remask_ciphertext(&input_cts[i], &sk, &pk, &mut rng)).collect();

        let proof = RemaskProof::prove(&input_cts, &output_cts, &sk, &pk);
        assert!(proof.verify(&input_cts, &output_cts, &pk), "honest prover should pass");
    }

    #[test]
    fn test_honest_prover_passes_2() {
        let mut rng = OsRng;
        let (sk, pk) = gen_keypair::<RistrettoCurve>(&mut rng);

        let plaintexts: Vec<_> = (0..RistrettoCurve::n_cards()).map(|i| RistrettoCurve::base_g() * <RistrettoCurve as Curve>::Scalar::from_u64(i as u64)).collect();
        let r_values: Vec<_> = (0..RistrettoCurve::n_cards()).map(|_| <RistrettoCurve as Curve>::Scalar::random(&mut rng)).collect();

        let input_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| RistrettoElGamalCiphertext {
                c1: <RistrettoCurve as Curve>::Point::identity(),
                c2: plaintexts[i],
            }).collect();

        let mut output_cts = Vec::new();
        for i in 0..input_cts.len() {
            let mut mask_card = input_cts[i].clone();
            mask_card.c2 = mask_card.c2 + mask_card.c1 * sk;
            output_cts.push(mask_card);
        }

        let proof = RemaskProof::prove(&input_cts, &output_cts, &sk, &pk);
        assert!(proof.verify(&input_cts, &output_cts, &pk), "honest prover should pass");
    }

    #[test]
    fn test_honest_prover_passes_3() {
       let mut rng = OsRng;
        let (sk, pk) = gen_keypair::<RistrettoCurve>(&mut rng);
        let plaintexts: Vec<_> = (0..RistrettoCurve::n_cards()).map(|i| RistrettoCurve::base_h() * <RistrettoCurve as Curve>::Scalar::from_u64(i as u64)).collect();
        let r_values: Vec<_> = (0..RistrettoCurve::n_cards()).map(|_| <RistrettoCurve as Curve>::Scalar::random(&mut rng)).collect();

        let input_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| RistrettoElGamalCiphertext::encrypt(&plaintexts[i], &pk, &r_values[i])).collect();

        let (sk2, pk2) = gen_keypair::<RistrettoCurve>(&mut rng);
        let mut output_cts = Vec::new();
        for i in 0..input_cts.len() {
            let mut mask_card = input_cts[i].clone();
            mask_card.c2 = mask_card.c2 + mask_card.c1 * sk2;
            output_cts.push(mask_card);
        }

        let proof = RemaskProof::prove(&input_cts, &output_cts, &sk2, &pk2);
        assert!(proof.verify(&input_cts, &output_cts, &pk2), "honest prover should pass");
    }

    #[test]
    fn test_gen_keys(){
        let mut rng = OsRng;
        let origin = "0000000000000000000000000000000000000000000000000000000000000000";
        let c1 = hex_to_ecpoint(origin).unwrap();
        let ct = RistrettoElGamalCiphertext {
            c1: c1,
            c2: <RistrettoCurve as Curve>::Point::random(&mut rng),
        };

        let (sk2, pk2) = gen_keypair::<RistrettoCurve>(&mut rng);

        let ct = remask_ciphertext(&ct, &sk2, &pk2, &mut rng);

        println!("is identity {}", <RistrettoCurve as Curve>::Point::identity() == ct.c1);
        let agg_pk_hex = ecpoint_to_hex(&ct.c1);
        println!("agg_pk {}", agg_pk_hex);
    }


    #[test]
    fn test_wrong_sk_fails() {
        let mut rng = OsRng;
        let (sk, pk) = gen_keypair::<RistrettoCurve>(&mut rng);
        let (_, wrong_pk) = gen_keypair::<RistrettoCurve>(&mut rng);
        let plaintexts: Vec<_> = (0..RistrettoCurve::n_cards()).map(|i| RistrettoCurve::base_h() * <RistrettoCurve as Curve>::Scalar::from_u64(i as u64)).collect();
        let r_values: Vec<_> = (0..RistrettoCurve::n_cards()).map(|_| <RistrettoCurve as Curve>::Scalar::random(&mut rng)).collect();

        let input_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| RistrettoElGamalCiphertext::encrypt(&plaintexts[i], &pk, &r_values[i])).collect();
        let output_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| make_remask_pair(&input_cts[i], &sk, &pk, &mut rng)).collect();

        let proof = RemaskProof::prove(&input_cts, &output_cts, &sk, &pk);
        assert!(!proof.verify(&input_cts, &output_cts, &wrong_pk), "wrong pk should fail");
    }

    #[test]
    fn test_tampered_output_fails() {
        let mut rng = OsRng;
        let (sk, pk) = gen_keypair::<RistrettoCurve>(&mut rng);
        let plaintexts: Vec<_> = (0..RistrettoCurve::n_cards()).map(|i| RistrettoCurve::base_h() * <RistrettoCurve as Curve>::Scalar::from_u64(i as u64)).collect();
        let r_values: Vec<_> = (0..RistrettoCurve::n_cards()).map(|_| <RistrettoCurve as Curve>::Scalar::random(&mut rng)).collect();

        let input_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| RistrettoElGamalCiphertext::encrypt(&plaintexts[i], &pk, &r_values[i])).collect();
        let output_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| make_remask_pair(&input_cts[i], &sk, &pk, &mut rng)).collect();

        let proof = RemaskProof::prove(&input_cts, &output_cts, &sk, &pk);

        let mut tampered = output_cts.clone();
        tampered[0] = make_remask_pair(&tampered[0], &sk, &pk, &mut rng);
        assert!(!proof.verify(&input_cts, &tampered, &pk), "tampered output should fail");
    }

    #[test]
    fn test_tampered_input_fails() {
        let mut rng = OsRng;
        let (sk, pk) = gen_keypair::<RistrettoCurve>(&mut rng);
        let plaintexts: Vec<_> = (0..RistrettoCurve::n_cards()).map(|i| RistrettoCurve::base_h() * <RistrettoCurve as Curve>::Scalar::from_u64(i as u64)).collect();
        let r_values: Vec<_> = (0..RistrettoCurve::n_cards()).map(|_| <RistrettoCurve as Curve>::Scalar::random(&mut rng)).collect();

        let input_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| RistrettoElGamalCiphertext::encrypt(&plaintexts[i], &pk, &r_values[i])).collect();
        let output_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| make_remask_pair(&input_cts[i], &sk, &pk, &mut rng)).collect();

        let proof = RemaskProof::prove(&input_cts, &output_cts, &sk, &pk);

        let mut tampered = input_cts.clone();
        tampered[1] = RistrettoElGamalCiphertext::encrypt(&(RistrettoCurve::base_h() * <RistrettoCurve as Curve>::Scalar::from_u64(99u64)), &pk, &<RistrettoCurve as Curve>::Scalar::random(&mut rng));
        assert!(!proof.verify(&tampered, &output_cts, &pk), "tampered input should fail");
    }

    #[test]
    fn test_wrong_prover_sk_fails() {
        let mut rng = OsRng;
        let (sk, pk) = gen_keypair::<RistrettoCurve>(&mut rng);
        let (wrong_sk, _) = gen_keypair::<RistrettoCurve>(&mut rng);
        let plaintexts: Vec<_> = (0..RistrettoCurve::n_cards()).map(|i| RistrettoCurve::base_h() * <RistrettoCurve as Curve>::Scalar::from_u64(i as u64)).collect();
        let r_values: Vec<_> = (0..RistrettoCurve::n_cards()).map(|_| <RistrettoCurve as Curve>::Scalar::random(&mut rng)).collect();

        let input_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| RistrettoElGamalCiphertext::encrypt(&plaintexts[i], &pk, &r_values[i])).collect();
        let output_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| make_remask_pair(&input_cts[i], &sk, &pk, &mut rng)).collect();

        let proof = RemaskProof::prove(&input_cts, &output_cts, &wrong_sk, &pk);
        assert!(!proof.verify(&input_cts, &output_cts, &pk), "prover with wrong sk should fail");
    }

    #[test]
    fn test_single_card() {
        let mut rng = OsRng;
        let (sk, pk) = gen_keypair::<RistrettoCurve>(&mut rng);
        let pt = RistrettoCurve::base_h() * <RistrettoCurve as Curve>::Scalar::from_u64(42u64);
        let r = <RistrettoCurve as Curve>::Scalar::random(&mut rng);
        let input = RistrettoElGamalCiphertext::encrypt(&pt, &pk, &r);
        let output = make_remask_pair(&input, &sk, &pk, &mut rng);

        let proof = RemaskProof::prove(&[input.clone()], &[output.clone()], &sk, &pk);
        assert!(proof.verify(&[input], &[output], &pk), "single card should pass");
    }

    #[test]
    fn test_single_card_two_user() {
        let mut rng = OsRng;
        let (sk, pk) = gen_keypair::<RistrettoCurve>(&mut rng);
        let pt = RistrettoCurve::base_g() * <RistrettoCurve as Curve>::Scalar::from_u64(42u64);
        let input = RistrettoElGamalCiphertext { c1: <RistrettoCurve as Curve>::Point::identity(), c2: pt };
        let r_prime = <RistrettoCurve as Curve>::Scalar::random(&mut rng);
        let enc_one  = input.re_encrypt(&pk, &r_prime);
        let mut output = enc_one.clone();

        let (sk2, pk2) = gen_keypair::<RistrettoCurve>(&mut rng);
        output.c2 = output.c2 + output.c1 * sk2; //user2 join

        let proof = RemaskProof::prove(&[enc_one.clone()], &[output.clone()], &sk2, &pk2);
        assert!(proof.verify(&[enc_one.clone()], &[output.clone()], &pk2), "single card should pass");

        let reveal_token1 = output.gen_reveal_token(&sk);
        let reveal_token2 = output.gen_reveal_token(&sk2);

        let decrypted = output.c2 - reveal_token1 - reveal_token2;
        assert_eq!(decrypted, pt);
    }

    #[test]
    fn test_benchmark_remask_proof_52_cards() {
        use std::time::{Duration, Instant};

        println!("\n{}", "=".repeat(72));
        println!("  RemaskProof Benchmark: prove() & verify() (52 cards)");
        println!("{}", "=".repeat(72));

        const N: usize = 52;
        const WARMUP: usize = 3;
        const ITERATIONS: usize = 20;

        let mut rng = OsRng;
        let (sk, pk) = gen_keypair::<RistrettoCurve>(&mut rng);
        let plaintexts: Vec<_> = (0..N).map(|i| RistrettoCurve::base_h() * <RistrettoCurve as Curve>::Scalar::from_u64(i as u64)).collect();
        let r_values: Vec<_> = (0..N).map(|_| <RistrettoCurve as Curve>::Scalar::random(&mut rng)).collect();

        let input_cts: Vec<RistrettoElGamalCiphertext> = (0..N)
            .map(|i| RistrettoElGamalCiphertext::encrypt(&plaintexts[i], &pk, &r_values[i])).collect();
        let output_cts: Vec<RistrettoElGamalCiphertext> = (0..N)
            .map(|i| remask_ciphertext(&input_cts[i], &sk, &pk, &mut rng)).collect();

        let mut prove_times: Vec<Duration> = Vec::with_capacity(ITERATIONS);
        let mut verify_times: Vec<Duration> = Vec::with_capacity(ITERATIONS);
        let mut proof_size_bytes = 0usize;

        for i in 0..(WARMUP + ITERATIONS) {
            let start = Instant::now();
            let proof = RemaskProof::prove(&input_cts, &output_cts, &sk, &pk);
            let prove_dur = start.elapsed();

            if i < WARMUP {
                println!("\n  [Warmup {}/{}] prove: {:?}", i + 1, WARMUP, prove_dur);
                continue;
            }

            if proof_size_bytes == 0 {
                proof_size_bytes = std::mem::size_of_val(&proof);
            }

            let start = Instant::now();
            let valid = proof.verify(&input_cts, &output_cts, &pk);
            let verify_dur = start.elapsed();

            assert!(valid, "Benchmark iteration {} must verify", i);

            prove_times.push(prove_dur);
            verify_times.push(verify_dur);
        }

        prove_times.sort();
        verify_times.sort();

        let avg_prove: Duration = prove_times.iter().sum::<Duration>() / ITERATIONS as u32;
        let avg_verify: Duration = verify_times.iter().sum::<Duration>() / ITERATIONS as u32;
        let p50_prove = prove_times[ITERATIONS / 2];
        let p50_verify = verify_times[ITERATIONS / 2];
        let p99_prove = prove_times[(ITERATIONS * 99 / 100).min(ITERATIONS - 1)];
        let p99_verify = verify_times[(ITERATIONS * 99 / 100).min(ITERATIONS - 1)];
        let min_prove = prove_times[0];
        let min_verify = verify_times[0];
        let max_prove = prove_times[ITERATIONS - 1];
        let max_verify = verify_times[ITERATIONS - 1];

        let prove_per_sec = 1.0f64 / avg_prove.as_secs_f64();
        let verify_per_sec = 1.0f64 / avg_verify.as_secs_f64();

        println!("\n  ┌─────────────────────────────────────────────────────────────┐");
        println!("  │  RemaskProof Performance (N={}, {} iters)                │", N, ITERATIONS);
        println!("  ├──────────────┬──────────┬──────────┬──────────┬──────────┤");
        println!("  │ Operation    │   Avg    │   P50    │   Min    │   Max    │");
        println!("  ├──────────────┼──────────┼──────────┼──────────┼──────────┤");
        println!("  │ prove()      │ {:>8.2?}ms│ {:>8.2?}ms│ {:>8.2?}ms│ {:>8.2?}ms│",
            avg_prove.as_millis(), p50_prove.as_millis(),
            min_prove.as_millis(), max_prove.as_millis());
        println!("  │ verify()     │ {:>8.2?}ms│ {:>8.2?}ms│ {:>8.2?}ms│ {:>8.2?}ms│",
            avg_verify.as_millis(), p50_verify.as_millis(),
            min_verify.as_millis(), max_verify.as_millis());
        println!("  ├──────────────┼──────────┼──────────┼──────────┼──────────┤");
        println!("  │ Throughput   │ {:>8.1}/s│          │ P99={:>6.2?}ms│ P99={:>6.2?}ms│",
            prove_per_sec, p99_prove.as_millis(), p99_verify.as_millis());
        println!("  │ Verify rate  │ {:>8.1}/s│          │          │          │",
            verify_per_sec);
        println!("  ├──────────────┴──────────┴──────────┴──────────┴──────────┤");
        println!("  │ Proof size: ~{} bytes (4 fields)                           │", proof_size_bytes);
        println!("  │ Total (prove+verify): {:>8.2?}ms                           │",
            (avg_prove + avg_verify).as_millis());
        println!("  └─────────────────────────────────────────────────────────────┘");

        assert!(avg_prove.as_millis() < 500, "prove() should complete within 500ms");
        assert!(avg_verify.as_millis() < 100, "verify() should complete within 100ms");

        println!("\n  ✅ Benchmark completed: all performance within acceptable bounds");
    }

    #[test]
    fn test_single_card_one_user() {
        let mut rng = OsRng;
        let (sk, pk) = gen_keypair::<RistrettoCurve>(&mut rng);
        let pt = RistrettoCurve::base_g() * <RistrettoCurve as Curve>::Scalar::from_u64(42u64);
        let input = RistrettoElGamalCiphertext { c1: <RistrettoCurve as Curve>::Point::identity(), c2: pt };
        let mut output = input.clone();

        output.c2 = output.c2 + output.c1 * sk; //user2 join

        let proof = RemaskProof::prove(&[input.clone()], &[output.clone()], &sk, &pk);
        assert!(proof.verify(&[input.clone()], &[output.clone()], &pk), "single card should pass");

        let reveal_token1 = output.clone().gen_reveal_token(&sk);

        let decrypted = output.c2 - reveal_token1;
        println!("{:?},{:?},{:?},{:?}",output.c2.compress(), reveal_token1.compress(),decrypted.compress(),pt.compress());

        assert_eq!(decrypted, pt);
    }

}
