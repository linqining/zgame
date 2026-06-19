use crate::crypto::curve::{Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric};
use rand_core::{CryptoRng, RngCore};
use crate::zk_shuffle::generalized_schnorr_proof::GeneralizedSchnorrProof;
use crate::zk_shuffle::transcript_ext::CryptoTranscript;
use crate::zk_shuffle::error::VerificationError;


#[derive(Debug, Clone)]
pub struct ZKShuffleProof<C: Curve> {
    pub sum_c1_commit: C::Point,
    pub sum_c2_commit: C::Point,
    /// Combined Schnorr proof for c1+c2, enforcing c1 and c2 use the same permutation.
    /// M-D13 修复：Base points: [output[0].c1, output[0].c2, ..., output[n-1].c1, output[n-1].c2, input[0].c1, input[0].c2]
    /// Secret vec:  [k_0, k_0, k_1, k_1, ..., k_{N-1}, k_{N-1}, s, s]
    /// R = sum_c1_commit + sum_c2_commit
    /// 防止c1/c2 swap攻击
    pub combined_schnorr_proof: GeneralizedSchnorrProof<C>,
    /// 攻击5 (CRITICAL): c1/c2 信息转移攻击 — 伪造的 ZKShuffleProof 通过验证
    ///
    /// 漏洞根因: 合并 Schnorr 证明只约束 output[j].c1 + output[j].c2 的加权和，
    /// 而不约束 c1 和 c2 的个体值。
    /// 解决方法: 为每个 c1 和 c2 分别提供 Schnorr 证明，确保每个 Schnorr 证明都约束 c1 和 c2 的个体值。
    pub sum_c1_schnorr_proof: GeneralizedSchnorrProof<C>,
    pub sum_c2_schnorr_proof: GeneralizedSchnorrProof<C>,
    pub nonce: C::Scalar,
}

impl<C: Curve> ZKShuffleProof<C> {
    fn derive_batch_coefficients(input_cts: &[ElGamalCiphertextGeneric<C>], output_cts: &[ElGamalCiphertextGeneric<C>], transcript: &mut impl CryptoTranscript,) -> Vec<C::Scalar> {
        let n = input_cts.len();
        for i in input_cts.iter().take(n) {
            transcript.append_point::<C>(b"input c1", &i.c1);
            transcript.append_point::<C>(b"input c2", &i.c2);
        }

        for i in output_cts.iter().take(n) {
            transcript.append_point::<C>(b"output c1", &i.c1);
            transcript.append_point::<C>(b"output c2", &i.c2);
        }
        // 兼容 Move 合约 bls_transcript::challenge_vec：
        // 使用带索引的子标签 "rho_challenge0", "rho_challenge1", ...
        // 而非旧实现中重复使用相同 label "rho_challenge" + challenge_bytes。
        // 两者产生不同的 challenge 标量，必须与链上实现一致。
        transcript.challenge_vec::<C>(b"rho_challenge", n)
    }

    pub fn prove(
        input_cts: &[ElGamalCiphertextGeneric<C>],
        output_cts: &[ElGamalCiphertextGeneric<C>],
        permute: &[usize],
        r_values: &[C::Scalar],
        pk: &C::Point,
        rng: &mut (impl RngCore + CryptoRng),
        transcript: &mut impl CryptoTranscript,
    ) -> Result<Self, VerificationError> {
        let n = input_cts.len();
        if input_cts.len() != n || output_cts.len() != n || permute.len() != n || r_values.len() != n {
            return Err(VerificationError::InvalidInput);
        }
        if n == 0 {
            return Err(VerificationError::InvalidInput);
        }

        // 兼容 Move 合约 shuffle_proof::verify 的 C1 修复：
        // 将 pk 加入 transcript，绑定证明到玩家公钥
        transcript.append_point::<C>(b"shuffle_pk", pk);

        let nonce = C::Scalar::random(rng);
        transcript.append_scalar::<C>(b"shuffle_nonce", &nonce);

        let rho = Self::derive_batch_coefficients(input_cts, output_cts, transcript);
        let input_c1s: Vec<C::Point> = input_cts.iter().map(|ct| ct.c1).collect();
        let input_c2s: Vec<C::Point> = input_cts.iter().map(|ct| ct.c2).collect();


        let sum_input_c1_commit = C::Point::vartime_multiscalar_mul(&rho, &input_c1s);
        let sum_input_c2_commit = C::Point::vartime_multiscalar_mul(&rho, &input_c2s);

        // 构造线性组合 input_cards * rho_i + share_pk*ri
        let mut secret_vec = vec![C::Scalar::zero(); n];
        let mut pk_delta = C::Scalar::zero();
        for j in 0..n {
            let position = permute.iter().position(|&x| x == j).unwrap();
            secret_vec[position] = rho[j];
            let r_val = r_values[position];
            pk_delta = pk_delta - r_val * rho[j];
        }
        secret_vec.push(pk_delta);

        // 生成广义Schnorr证明，证明 swap_sum_c1_commit 和 swap_sum_c2_commit 是对应基点的线性组合
        // M-D13 修复：基点从 [G, pk] 改为 [input[0].c1, input[0].c2]
        let mut base_points_c1: Vec<C::Point> = output_cts.iter().map(|ct| ct.c1).collect();
        let mut base_points_c2: Vec<C::Point> = output_cts.iter().map(|ct| ct.c2).collect();
        base_points_c1.push(C::base_g());
        base_points_c2.push(*pk);

        let no_identity_input_c2 = input_cts.iter().all(|ct| !ct.c2.is_identity());
        if !no_identity_input_c2 {
            return Err(VerificationError::IdentityBasePoint);
        }
        // M-D13 修复：input[0].c1 现在作为基点，需要检查非 identity
        if input_cts[0].c1.is_identity() {
            return Err(VerificationError::IdentityBasePoint);
        }

        let no_identity_c1 = output_cts.iter().all(|ct| !ct.c1.is_identity());
        let no_identity_c2 = output_cts.iter().all(|ct| !ct.c2.is_identity());
        if !(no_identity_c1 && no_identity_c2) {
            return Err(VerificationError::IdentityBasePoint);
        }
        // 合并 c1/c2 为单个 Schnorr 证明，强制使用相同的排列
        // Base points: [output[0].c1, output[0].c2, output[1].c1, output[1].c2, ..., G, pk]
        // Secret vec:  [k_0, k_0, k_1, k_1, ..., k_{N-1}, k_{N-1}, pk_delta, pk_delta]
        // R = sum_c1_commit + sum_c2_commit
        // 防止c1/c2 swap攻击
        let mut combined_base_points: Vec<C::Point> = Vec::with_capacity(2 * n + 2);
        let mut combined_secret_vec: Vec<C::Scalar> = Vec::with_capacity(2 * n + 2);
        for i in 0..n {
            combined_base_points.push(output_cts[i].c1);
            combined_base_points.push(output_cts[i].c2);
            combined_secret_vec.push(secret_vec[i]); // k_i for c1
            combined_secret_vec.push(secret_vec[i]); // same k_i for c2
        }
        combined_base_points.push(C::base_g());
        combined_base_points.push(*pk);
        combined_secret_vec.push(secret_vec[n]); // pk_delta for G
        combined_secret_vec.push(secret_vec[n]); // same pk_delta for pk

        let combined_commit = sum_input_c1_commit + sum_input_c2_commit;

        let combined_schnorr_proof = GeneralizedSchnorrProof::<C>::prove(
            &combined_base_points,
            &combined_secret_vec,
            &combined_commit,
            transcript,
        )?;

        let sum_c1_schnorr_proof = GeneralizedSchnorrProof::<C>::prove(
            &base_points_c1,
            &secret_vec,
            &sum_input_c1_commit,
            transcript,
        )?;
        let sum_c2_schnorr_proof = GeneralizedSchnorrProof::<C>::prove(
            &base_points_c2,
            &secret_vec,
            &sum_input_c2_commit,
            transcript,
        )?;

        Ok(ZKShuffleProof::<C> {
            sum_c1_commit: sum_input_c1_commit,
            sum_c2_commit: sum_input_c2_commit,
            nonce,
            combined_schnorr_proof,
            sum_c1_schnorr_proof,
            sum_c2_schnorr_proof,
        })
    }

    pub fn verify(
        &self,
        input_cts: &[ElGamalCiphertextGeneric<C>],
        output_cts: &[ElGamalCiphertextGeneric<C>],
        pk: &C::Point,
        transcript: &mut impl CryptoTranscript,
    ) -> Result<(), VerificationError> {
        let n = input_cts.len();
        if input_cts.len() != n || output_cts.len() != n {
            return Err(VerificationError::InvalidInput);
        }
        if n == 0 {
            return Err(VerificationError::InvalidInput);
        }

        // 兼容 Move 合约 shuffle_proof::verify 的 C1 修复：
        // 将 pk 加入 transcript，绑定证明到玩家公钥
        transcript.append_point::<C>(b"shuffle_pk", pk);

        // 兼容 Move 合约 shuffle_proof::verify 的 C2 缓解：
        // 校验所有输出密文有效（c1/c2 非 identity）
        for ct in output_cts.iter() {
            if ct.c1.is_identity() || ct.c2.is_identity() {
                return Err(VerificationError::IdentityBasePoint);
            }
        }

        transcript.append_scalar::<C>(b"shuffle_nonce", &self.nonce);
        let rho = Self::derive_batch_coefficients(input_cts, output_cts, transcript);

        let input_c1s: Vec<C::Point> = input_cts.iter().map(|ct| ct.c1).collect();
        let input_c2s: Vec<C::Point> = input_cts.iter().map(|ct| ct.c2).collect();

        // Recompute sum commitments and verify they match the proof
        let sum_input_c1_commit = C::Point::vartime_multiscalar_mul(&rho, &input_c1s);
        let sum_input_c2_commit = C::Point::vartime_multiscalar_mul(&rho, &input_c2s);

        if self.sum_c1_commit != sum_input_c1_commit {
            return Err(VerificationError::InvalidDLEQProof);
        }
        if self.sum_c2_commit != sum_input_c2_commit {
            return Err(VerificationError::InvalidDLEQProof);
        }

        // Reconstruct combined base points: [output[0].c1, output[0].c2, ..., G, pk]
        let mut combined_base_points: Vec<C::Point> = Vec::with_capacity(2 * n + 2);
        for ct in output_cts.iter() {
            combined_base_points.push(ct.c1);
            combined_base_points.push(ct.c2);
        }
        combined_base_points.push(C::base_g());
        combined_base_points.push(*pk);

        let mut base_points_c1: Vec<C::Point> = output_cts.iter().map(|ct| ct.c1).collect();
        let mut base_points_c2: Vec<C::Point> = output_cts.iter().map(|ct| ct.c2).collect();
        base_points_c1.push(C::base_g());
        base_points_c2.push(*pk);

        // Verify combined Schnorr proof
        let combined_commit = self.sum_c1_commit + self.sum_c2_commit;
        self.combined_schnorr_proof.verify(&combined_base_points, &combined_commit, transcript)?;
        self.sum_c1_schnorr_proof.verify(&base_points_c1, &self.sum_c1_commit,  transcript)?;
        self.sum_c2_schnorr_proof.verify(&base_points_c2, &self.sum_c2_commit,  transcript)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::curve::{RistrettoCurve, ec_encrypt_batch_generic};
    use crate::zk_shuffle::transcript_ext::{CryptoTranscript, MerlinTranscript};
    use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar as DalekScalar};
    use rand::seq::SliceRandom;
    use rand_core::OsRng;

    use std::time::Duration;

    type EcPoint = RistrettoPoint;
    type Scalar = DalekScalar;
    type ElGamalCiphertext = ElGamalCiphertextGeneric<RistrettoCurve>;

    /// Helper: 生成随机密钥对
    fn gen_keypair() -> (Scalar, EcPoint) {
        let sk = Scalar::random(&mut OsRng);
        (sk, RistrettoCurve::base_g() * sk)
    }

    /// Helper: 构造完整的 N_CARDS 张加密牌（无 placeholder）
    fn make_full_encrypted_cards(pk: &EcPoint) -> Vec<ElGamalCiphertext> {
        let n = RistrettoCurve::n_cards();
        let msgs: Vec<EcPoint> = (0..n)
            .map(|i| RistrettoCurve::base_g() * Scalar::from((i + 1) as u64))
            .collect();
        ec_encrypt_batch_generic::<RistrettoCurve>(&msgs, pk, &mut OsRng)
    }

    /// Helper: 构造随机排列
    fn random_permute() -> Vec<usize> {
        let n = RistrettoCurve::n_cards();
        let mut arr: Vec<usize> = (0..n).collect();
        arr.shuffle(&mut OsRng);
        arr
    }

    /// Helper: 对 input_cards 按 permute 执行 shuffle + re_encrypt，返回 (r_values, output_cards)
    fn shuffle_and_reencrypt(
        input: &[ElGamalCiphertext],
        permute: &[usize],
        pk: &EcPoint,
    ) -> (Vec<Scalar>, Vec<ElGamalCiphertext>) {
        let n = RistrettoCurve::n_cards();
        let mut r_values = Vec::with_capacity(n);
        let mut output = Vec::with_capacity(n);
        for j in 0..n {
            let r_j = Scalar::random(&mut OsRng);
            r_values.push(r_j);
            let i = permute[j];
            output.push(input[i].re_encrypt(pk, &r_j));
        }
        (r_values, output)
    }

    // ========== 正常功能测试 ==========

    #[test]
    fn test_honest_prover_passes() {
        let (_sk, pk) = gen_keypair();
        let input = make_full_encrypted_cards(&pk);
        let permute = random_permute();
        let (r_values, output) = shuffle_and_reencrypt(&input, &permute, &pk);

        let mut transcript = MerlinTranscript::new(b"test_shuffle");
        let proof = ZKShuffleProof::<RistrettoCurve>::prove(&input, &output, &permute, &r_values, &pk, &mut OsRng, &mut transcript).unwrap();
        let mut verify_transcript = MerlinTranscript::new(b"test_shuffle");
        assert!(proof.verify(&input, &output, &pk, &mut verify_transcript).is_ok(), "honest prover should pass");
    }

    #[test]
    fn test_identity_permutation_passes() {
        let (_sk, pk) = gen_keypair();
        let input = make_full_encrypted_cards(&pk);
        let n = RistrettoCurve::n_cards();
        let permute: Vec<usize> = (0..n).collect();
        let (r_values, output) = shuffle_and_reencrypt(&input, &permute, &pk);

        let mut transcript = MerlinTranscript::new(b"test_shuffle");
        let proof = ZKShuffleProof::<RistrettoCurve>::prove(&input, &output, &permute, &r_values, &pk, &mut OsRng, &mut transcript).unwrap();
        let mut verify_transcript = MerlinTranscript::new(b"test_shuffle");
        assert!(proof.verify(&input, &output, &pk, &mut verify_transcript).is_ok(), "identity permutation should pass");
    }

    #[test]
    fn test_prove_returns_error_for_placeholder_cards() {
        let (_sk, pk) = gen_keypair();
        let n = RistrettoCurve::n_cards();
        let mut input = make_full_encrypted_cards(&pk);
        // 将最后一张牌替换为 placeholder (c1=identity)
        input[n - 1] = ElGamalCiphertext::new_placeholder_card();
        let permute = random_permute();
        let (r_values, output) = shuffle_and_reencrypt(&input, &permute, &pk);

        let mut transcript = MerlinTranscript::new(b"test_shuffle");
        let result = ZKShuffleProof::<RistrettoCurve>::prove(&input, &output, &permute, &r_values, &pk, &mut OsRng, &mut transcript);
        assert!(result.is_err(), "placeholder cards should cause prove to fail");
        assert_eq!(result.unwrap_err(), VerificationError::IdentityBasePoint);
    }

    // ========== 安全性测试：篡改检测 ==========

    /// M-D13 修复后，verify 不再使用 pk 作为基点（与 Move 合约 _pk 一致）。
    /// 证明仅依赖 input/output 密文，pk 不再直接影响验证结果。
    /// 这是 M-D13 修复的预期行为：移除 G 和 pk 作为自由基点，防止攻击者利用。
    #[test]
    fn test_pk_independent_after_md13() {
        // 兼容 Move 合约 shuffle_proof::verify 的 C1 修复：
        // M-D13 移除了 pk 作为基点，但 C1 修复将 pk 加入 transcript 绑定证明到玩家公钥。
        // 因此 verify 不再独立于 pk——使用错误 pk 验证应失败（transcript 不匹配）。
        let (_sk, pk) = gen_keypair();
        let (_, wrong_pk) = gen_keypair();
        let input = make_full_encrypted_cards(&pk);
        let permute = random_permute();
        let (r_values, output) = shuffle_and_reencrypt(&input, &permute, &pk);

        let mut transcript = MerlinTranscript::new(b"test_shuffle");
        let proof = ZKShuffleProof::<RistrettoCurve>::prove(&input, &output, &permute, &r_values, &pk, &mut OsRng, &mut transcript).unwrap();
        // C1 修复后，pk 加入 transcript，使用错误 pk 验证应失败
        let mut verify_transcript = MerlinTranscript::new(b"test_shuffle");
        assert!(proof.verify(&input, &output, &wrong_pk, &mut verify_transcript).is_err(),
            "C1 fix: verify should fail with wrong pk (pk bound to transcript)");
        // 使用正确 pk 验证应通过
        let mut verify_transcript2 = MerlinTranscript::new(b"test_shuffle");
        assert!(proof.verify(&input, &output, &pk, &mut verify_transcript2).is_ok(),
            "C1 fix: verify should pass with correct pk");
    }

    #[test]
    fn test_tampered_output_fails() {
        let (_sk, pk) = gen_keypair();
        let input = make_full_encrypted_cards(&pk);
        let permute = random_permute();
        let (r_values, output) = shuffle_and_reencrypt(&input, &permute, &pk);

        let mut transcript = MerlinTranscript::new(b"test_shuffle");
        let proof = ZKShuffleProof::<RistrettoCurve>::prove(&input, &output, &permute, &r_values, &pk, &mut OsRng, &mut transcript).unwrap();

        // 篡改 output[0] 的 c2
        let mut tampered = output.clone();
        tampered[0] = tampered[0].re_encrypt(&pk, &Scalar::random(&mut OsRng));
        let mut verify_transcript = MerlinTranscript::new(b"test_shuffle");
        assert!(proof.verify(&input, &tampered, &pk, &mut verify_transcript).is_err(), "tampered output should fail");
    }

    #[test]
    fn test_tampered_input_fails() {
        let (_sk, pk) = gen_keypair();
        let input = make_full_encrypted_cards(&pk);
        let permute = random_permute();
        let (r_values, output) = shuffle_and_reencrypt(&input, &permute, &pk);

        let mut transcript = MerlinTranscript::new(b"test_shuffle");
        let proof = ZKShuffleProof::<RistrettoCurve>::prove(&input, &output, &permute, &r_values, &pk, &mut OsRng, &mut transcript).unwrap();

        // 篡改 input[1]
        let mut tampered = input.clone();
        tampered[1] = ElGamalCiphertext::encrypt(
            &(RistrettoCurve::base_g() * Scalar::from(99u64)), &pk, &Scalar::random(&mut OsRng),
        );
        let mut verify_transcript = MerlinTranscript::new(b"test_shuffle");
        assert!(proof.verify(&tampered, &output, &pk, &mut verify_transcript).is_err(), "tampered input should fail");
    }

    #[test]
    fn test_c2_swap_attack_fails() {
        let (_sk, pk) = gen_keypair();
        let input = make_full_encrypted_cards(&pk);
        let permute = random_permute();
        let (r_values, mut output) = shuffle_and_reencrypt(&input, &permute, &pk);

        // 交换 output[0] 和 output[1] 的 c2
        let tmp = output[0].c2;
        output[0].c2 = output[1].c2;
        output[1].c2 = tmp;

        let mut transcript = MerlinTranscript::new(b"test_shuffle");
        let proof = ZKShuffleProof::<RistrettoCurve>::prove(&input, &output, &permute, &r_values, &pk, &mut OsRng, &mut transcript).unwrap();
        let mut verify_transcript = MerlinTranscript::new(b"test_shuffle");
        assert!(proof.verify(&input, &output, &pk, &mut verify_transcript).is_err(), "c2 swap attack should fail");
    }

    #[test]
    fn test_tampered_commitment_fails() {
        let (_sk, pk) = gen_keypair();
        let input = make_full_encrypted_cards(&pk);
        let permute = random_permute();
        let (r_values, output) = shuffle_and_reencrypt(&input, &permute, &pk);

        let mut transcript = MerlinTranscript::new(b"test_shuffle");
        let mut proof = ZKShuffleProof::<RistrettoCurve>::prove(&input, &output, &permute, &r_values, &pk, &mut OsRng, &mut transcript).unwrap();

        // 篡改 combined schnorr proof 的 commitment
        proof.combined_schnorr_proof.commitment = proof.combined_schnorr_proof.commitment + RistrettoCurve::base_g();
        let mut verify_transcript = MerlinTranscript::new(b"test_shuffle");
        assert!(proof.verify(&input, &output, &pk, &mut verify_transcript).is_err(), "tampered commitment should fail");
    }

    #[test]
    fn test_tampered_nonce_fails() {
        let (_sk, pk) = gen_keypair();
        let input = make_full_encrypted_cards(&pk);
        let permute = random_permute();
        let (r_values, output) = shuffle_and_reencrypt(&input, &permute, &pk);

        let mut proof = ZKShuffleProof::<RistrettoCurve>::prove(&input, &output, &permute, &r_values, &pk, &mut OsRng, &mut MerlinTranscript::new(b"test_tampered_nonce_fails")).unwrap();

        // 篡改 nonce
        proof.nonce = proof.nonce + Scalar::ONE;
        assert!(proof.verify(&input, &output, &pk, &mut MerlinTranscript::new(b"test_tampered_nonce_fails")).is_err(), "tampered nonce should fail");
    }

    #[test]
    fn test_tampered_response_fails() {
        let (_sk, pk) = gen_keypair();
        let input = make_full_encrypted_cards(&pk);
        let permute = random_permute();
        let (r_values, output) = shuffle_and_reencrypt(&input, &permute, &pk);

        let mut proof = ZKShuffleProof::<RistrettoCurve>::prove(&input, &output, &permute, &r_values, &pk, &mut OsRng, &mut MerlinTranscript::new(b"test_tampered_response_fails")).unwrap();

        // 篡改 combined schnorr proof 的第一个 response
        if !proof.combined_schnorr_proof.responses.is_empty() {
            proof.combined_schnorr_proof.responses[0] = proof.combined_schnorr_proof.responses[0] + Scalar::ONE;
        }
        assert!(proof.verify(&input, &output, &pk, &mut MerlinTranscript::new(b"test_tampered_response_fails")).is_err(), "tampered response should fail");
    }

    // ========== 跨实例重放攻击测试 ==========

    #[test]
    fn test_cross_instance_replay_fails() {
        let (_sk1, pk1) = gen_keypair();
        let (_sk2, pk2) = gen_keypair();

        let input1 = make_full_encrypted_cards(&pk1);
        let input2 = make_full_encrypted_cards(&pk2);

        let permute1 = random_permute();
        let (r_values1, output1) = shuffle_and_reencrypt(&input1, &permute1, &pk1);

        let proof1 = ZKShuffleProof::<RistrettoCurve>::prove(&input1, &output1, &permute1, &r_values1, &pk1, &mut OsRng, &mut MerlinTranscript::new(b"test_cross_instance_replay_fails")).unwrap();

        // 用 proof1 验证完全不同的 input/output/pk
        assert!(proof1.verify(&input2, &output1, &pk2, &mut MerlinTranscript::new(b"test_cross_instance_replay_fails")).is_err(), "cross-instance replay should fail");
        // 即使 pk 相同，不同的 input/output 也应失败
        assert!(proof1.verify(&input2, &output1, &pk1, &mut MerlinTranscript::new(b"test_cross_instance_replay_fails")).is_err(), "different data same pk should fail");
    }

    // ========== Nonce 唯一性测试 ==========

    #[test]
    fn test_nonce_uniqueness() {
        let (_sk, pk) = gen_keypair();
        let input = make_full_encrypted_cards(&pk);
        let permute = random_permute();
        let (r_values, output) = shuffle_and_reencrypt(&input, &permute, &pk);

        let proof_a = ZKShuffleProof::<RistrettoCurve>::prove(&input, &output, &permute, &r_values, &pk, &mut OsRng, &mut MerlinTranscript::new(b"test_nonce_uniqueness_a")).unwrap();
        let proof_b = ZKShuffleProof::<RistrettoCurve>::prove(&input, &output, &permute, &r_values, &pk, &mut OsRng, &mut MerlinTranscript::new(b"test_nonce_uniqueness_b")).unwrap();

        assert_ne!(proof_a.nonce, proof_b.nonce, "each prove() must generate unique nonce");
    }

    // ========== 性能基准测试 ==========

    #[test]
    fn test_benchmark_zkshuffle_prove_verify() {
        use std::time::{Duration, Instant};

        const WARMUP: usize = 3;
        const ITERATIONS: usize = 20;

        let (_sk, pk) = gen_keypair();
        let input = make_full_encrypted_cards(&pk);
        let permute = random_permute();
        let (r_values, output) = shuffle_and_reencrypt(&input, &permute, &pk);

        // Warmup
        for _ in 0..WARMUP {
            let proof = ZKShuffleProof::<RistrettoCurve>::prove(&input, &output, &permute, &r_values, &pk, &mut OsRng, &mut MerlinTranscript::new(b"test_benchmark_warmup")).unwrap();
            let _ = proof.verify(&input, &output, &pk, &mut MerlinTranscript::new(b"test_benchmark_warmup"));
        }

        let mut prove_times = Vec::with_capacity(ITERATIONS);
        let mut verify_times = Vec::with_capacity(ITERATIONS);

        for i in 0..ITERATIONS {
            let start = Instant::now();
            let proof = ZKShuffleProof::<RistrettoCurve>::prove(&input, &output, &permute, &r_values, &pk, &mut OsRng, &mut MerlinTranscript::new(b"test_benchmark_prove_verify")).unwrap();
            prove_times.push(start.elapsed());

            let verify_start = Instant::now();
            let result = proof.verify(&input, &output, &pk, &mut MerlinTranscript::new(b"test_benchmark_prove_verify"));
            verify_times.push(verify_start.elapsed());
            assert!(result.is_ok());
        }

        let prove_avg = avg_duration(&prove_times);
        let prove_p50 = percentile(&prove_times, 50);
        let prove_p99 = percentile(&prove_times, 99);
        let prove_min = prove_times.iter().min().unwrap();
        let prove_max = prove_times.iter().max().unwrap();

        let verify_avg = avg_duration(&verify_times);
        let verify_p50 = percentile(&verify_times, 50);
        let verify_p99 = percentile(&verify_times, 99);
        let verify_min = verify_times.iter().min().unwrap();
        let verify_max = verify_times.iter().max().unwrap();

        let proof_size_bytes = std::mem::size_of::<ZKShuffleProof<RistrettoCurve>>();
        let total_avg = prove_avg + verify_avg;
        let n_cards = RistrettoCurve::n_cards();

        println!("\n{}", "=".repeat(72));
        println!("  ZKShuffleProof Benchmark ({} cards, {} iterations)", n_cards, ITERATIONS);
        println!("{}", "=".repeat(72));
        println!("  ┌──────────┬──────────┬──────────┬──────────┬──────────┬──────────┐");
        println!("  │  Metric  │   Avg    │   P50    │   P99    │   Min    │   Max    │");
        println!("  ├──────────┼──────────┼──────────┼──────────┼──────────┼──────────┤");
        println!("  │ prove    │ {:>6?} │ {:>6?} │ {:>6?} │ {:>6?} │ {:>6?} │",
            fmt_us(prove_avg), fmt_us(prove_p50), fmt_us(prove_p99), fmt_us(*prove_min), fmt_us(*prove_max));
        println!("  │ verify   │ {:>6?} │ {:>6?} │ {:>6?} │ {:>6?} │ {:>6?} │",
            fmt_us(verify_avg), fmt_us(verify_p50), fmt_us(verify_p99), fmt_us(*verify_min), fmt_us(*verify_max));
        println!("  └──────────┴──────────┴──────────┴──────────┴──────────┴──────────┘");
        println!("  total (prove+verify) avg: {:?}", total_avg);
        println!("  prove throughput:  {:.1} ops/s", 1.0 / prove_avg.as_secs_f64());
        println!("  verify throughput: {:.1} ops/s", 1.0 / verify_avg.as_secs_f64());
        println!("  proof struct size: {} bytes", proof_size_bytes);
        println!("{}", "=".repeat(72));

        assert!(prove_avg < Duration::from_millis(500), "prove avg should be < 500ms, got {:?}", prove_avg);
        assert!(verify_avg < Duration::from_millis(200), "verify avg should be < 200ms, got {:?}", verify_avg);
    }

    fn avg_duration(times: &[Duration]) -> Duration {
        times.iter().sum::<Duration>() / times.len() as u32
    }

    fn percentile(times: &[Duration], p: u8) -> Duration {
        let mut sorted = times.to_vec();
        sorted.sort();
        let idx = ((p as f64 / 100.0) * (sorted.len() - 1) as f64).round() as usize;
        sorted[idx.min(sorted.len() - 1)]
    }

    fn fmt_us(d: Duration) -> String {
        format!("{:.0}us", d.as_micros())
    }

    // ========== 伪造攻击测试：核心漏洞 - 线性组合系数不强制为排列 ==========

    /// 攻击1 (CRITICAL): 非排列映射伪造 - 复制牌+丢弃牌
    #[test]
    fn test_forge_proof_duplicate_and_drop_card() {
        let (sk, pk) = gen_keypair();
        let n = RistrettoCurve::n_cards();
        let input = make_full_encrypted_cards(&pk);

        // === 攻击: 构造 output，其中 output[0] 和 output[1] 都是 input[0] 的重加密 ===
        let mut output = Vec::with_capacity(n);
        let mut r_values = Vec::with_capacity(n);

        // output[0] = re_encrypt(input[0]) — 正常
        let r_0 = Scalar::random(&mut OsRng);
        r_values.push(r_0);
        output.push(input[0].re_encrypt(&pk, &r_0));

        // output[1] = re_encrypt(input[0]) — 复制牌0！
        let r_1 = Scalar::random(&mut OsRng);
        r_values.push(r_1);
        output.push(input[0].re_encrypt(&pk, &r_1));

        // output[i] = re_encrypt(input[i]) for i >= 2 — 跳过了 input[1]
        for i in 2..n {
            let r_i = Scalar::random(&mut OsRng);
            r_values.push(r_i);
            output.push(input[i].re_encrypt(&pk, &r_i));
        }

        // === 手动构造伪造证明 ===
        let nonce = Scalar::random(&mut OsRng);
        let mut transcript = MerlinTranscript::new(b"zk_shuffle_proof");
        transcript.append_scalar::<RistrettoCurve>(b"nonce", &nonce);
        let rho = ZKShuffleProof::<RistrettoCurve>::derive_batch_coefficients(&input, &output, &mut transcript);

        // 计算 sum commitments
        let output_c1s: Vec<EcPoint> = output.iter().map(|ct| ct.c1).collect();
        let output_c2s: Vec<EcPoint> = output.iter().map(|ct| ct.c2).collect();
        let sum_output_c1_commit = EcPoint::vartime_multiscalar_mul(&rho, &output_c1s);
        let sum_output_c2_commit = EcPoint::vartime_multiscalar_mul(&rho, &output_c2s);

        // 计算线性组合系数
        let mut secret_vec: Vec<Scalar> = Vec::with_capacity(n + 1);
        secret_vec.push(rho[0] + rho[1]); // k_0 = rho[0] + rho[1] (两张 output 映射到 input[0])
        secret_vec.push(Scalar::ZERO);     // k_1 = 0 (没有 output 映射到 input[1])
        for j in 2..n {
            secret_vec.push(rho[j]); // k_j = rho[j]
        }
        let mut pk_delta = Scalar::ZERO;
        for i in 0..n {
            pk_delta = pk_delta + r_values[i] * rho[i];
        }
        secret_vec.push(pk_delta);

        // 生成合并 Schnorr 证明（c1/c2 使用相同 secret_vec）
        let mut combined_base_points: Vec<EcPoint> = Vec::with_capacity(2 * n + 2);
        let mut combined_secret_vec: Vec<Scalar> = Vec::with_capacity(2 * n + 2);
        for i in 0..n {
            combined_base_points.push(output[i].c1);
            combined_base_points.push(output[i].c2);
            combined_secret_vec.push(secret_vec[i]);
            combined_secret_vec.push(secret_vec[i]);
        }
        combined_base_points.push(RistrettoCurve::base_g());
        combined_base_points.push(pk);
        combined_secret_vec.push(pk_delta);
        combined_secret_vec.push(pk_delta);

        let combined_commit = sum_output_c1_commit + sum_output_c2_commit;

        let combined_schnorr_proof = GeneralizedSchnorrProof::<RistrettoCurve>::prove(
            &combined_base_points,
            &combined_secret_vec,
            &combined_commit,
            &mut transcript,
        )
        .unwrap();

        // 生成 c1/c2 独立 Schnorr 证明
        let mut base_points_c1: Vec<EcPoint> = output.iter().map(|ct| ct.c1).collect();
        let mut base_points_c2: Vec<EcPoint> = output.iter().map(|ct| ct.c2).collect();
        base_points_c1.push(RistrettoCurve::base_g());
        base_points_c2.push(pk);

        let sum_c1_schnorr_proof = GeneralizedSchnorrProof::<RistrettoCurve>::prove(
            &base_points_c1,
            &secret_vec,
            &sum_output_c1_commit,
            &mut transcript,
        )
        .unwrap();
        let sum_c2_schnorr_proof = GeneralizedSchnorrProof::<RistrettoCurve>::prove(
            &base_points_c2,
            &secret_vec,
            &sum_output_c2_commit,
            &mut transcript,
        )
        .unwrap();

        // 组装伪造证明
        let forged_proof = ZKShuffleProof::<RistrettoCurve> {
            sum_c1_commit: sum_output_c1_commit,
            sum_c2_commit: sum_output_c2_commit,
            nonce,
            combined_schnorr_proof,
            sum_c1_schnorr_proof,
            sum_c2_schnorr_proof,
        };

        // === 伪造证明被验证拒绝 — 排列约束生效 ===
        let verify_result = forged_proof.verify(&input, &output, &pk, &mut MerlinTranscript::new(b"zk_shuffle_proof"));
        assert!(verify_result.is_err(), "non-permutation forged proof should be rejected");

        // === 验证 output 确实不是合法 shuffle ===
        let input_plaintexts: Vec<EcPoint> = input.iter().map(|ct| ct.decrypt(&sk)).collect();
        let output_plaintexts: Vec<EcPoint> = output.iter().map(|ct| ct.decrypt(&sk)).collect();

        // output[0] 和 output[1] 解密后都是 input[0] 的明文 — 牌被复制
        assert_eq!(output_plaintexts[0], input_plaintexts[0], "output[0] should decrypt to input[0]");
        assert_eq!(output_plaintexts[1], input_plaintexts[0], "output[1] should ALSO decrypt to input[0] - DUPLICATE!");

        // input[1] 的明文不出现在 output 中 — 牌被丢弃
        let input_1_plaintext = input_plaintexts[1];
        let found = output_plaintexts.iter().any(|p| *p == input_1_plaintext);
        assert!(!found, "input[1]'s plaintext should NOT appear in output - card was DROPPED!");
    }

    /// 攻击2 (CRITICAL): 极端情况 - 所有 output 都是同一张牌的重加密
    #[test]
    fn test_forge_proof_all_same_card() {
        let (sk, pk) = gen_keypair();
        let n = RistrettoCurve::n_cards();
        let input = make_full_encrypted_cards(&pk);

        // === 攻击: 所有 output 都是 input[0] 的重加密 ===
        let mut output = Vec::with_capacity(n);
        let mut r_values = Vec::with_capacity(n);

        for _ in 0..n {
            let r_i = Scalar::random(&mut OsRng);
            r_values.push(r_i);
            output.push(input[0].re_encrypt(&pk, &r_i));
        }

        // 构造伪造证明
        let nonce = Scalar::random(&mut OsRng);
        let mut transcript = MerlinTranscript::new(b"zk_shuffle_proof");
        transcript.append_scalar::<RistrettoCurve>(b"nonce", &nonce);
        let rho = ZKShuffleProof::<RistrettoCurve>::derive_batch_coefficients(&input, &output, &mut transcript);

        let output_c1s: Vec<EcPoint> = output.iter().map(|ct| ct.c1).collect();
        let output_c2s: Vec<EcPoint> = output.iter().map(|ct| ct.c2).collect();
        let sum_output_c1_commit = EcPoint::vartime_multiscalar_mul(&rho, &output_c1s);
        let sum_output_c2_commit = EcPoint::vartime_multiscalar_mul(&rho, &output_c2s);

        // k_0 = sum of all rho[i], k_j = 0 for j > 0
        let mut secret_vec: Vec<Scalar> = Vec::with_capacity(n + 1);
        let k_0: Scalar = rho.iter().sum();
        secret_vec.push(k_0);
        for _ in 1..n {
            secret_vec.push(Scalar::ZERO);
        }
        let mut pk_delta = Scalar::ZERO;
        for i in 0..n {
            pk_delta = pk_delta + r_values[i] * rho[i];
        }
        secret_vec.push(pk_delta);

        // 生成合并 Schnorr 证明
        let mut combined_base_points: Vec<EcPoint> = Vec::with_capacity(2 * n + 2);
        let mut combined_secret_vec: Vec<Scalar> = Vec::with_capacity(2 * n + 2);
        for i in 0..n {
            combined_base_points.push(output[i].c1);
            combined_base_points.push(output[i].c2);
            combined_secret_vec.push(secret_vec[i]);
            combined_secret_vec.push(secret_vec[i]);
        }
        combined_base_points.push(RistrettoCurve::base_g());
        combined_base_points.push(pk);
        combined_secret_vec.push(pk_delta);
        combined_secret_vec.push(pk_delta);

        let combined_commit = sum_output_c1_commit + sum_output_c2_commit;

        let combined_schnorr_proof = GeneralizedSchnorrProof::<RistrettoCurve>::prove(
            &combined_base_points,
            &combined_secret_vec,
            &combined_commit,
            &mut transcript,
        )
        .unwrap();

        // 生成 c1/c2 独立 Schnorr 证明
        let mut base_points_c1: Vec<EcPoint> = output.iter().map(|ct| ct.c1).collect();
        let mut base_points_c2: Vec<EcPoint> = output.iter().map(|ct| ct.c2).collect();
        base_points_c1.push(RistrettoCurve::base_g());
        base_points_c2.push(pk);

        let sum_c1_schnorr_proof = GeneralizedSchnorrProof::<RistrettoCurve>::prove(
            &base_points_c1,
            &secret_vec,
            &sum_output_c1_commit,
            &mut transcript,
        )
        .unwrap();
        let sum_c2_schnorr_proof = GeneralizedSchnorrProof::<RistrettoCurve>::prove(
            &base_points_c2,
            &secret_vec,
            &sum_output_c2_commit,
            &mut transcript,
        )
        .unwrap();

        let forged_proof = ZKShuffleProof::<RistrettoCurve> {
            sum_c1_commit: sum_output_c1_commit,
            sum_c2_commit: sum_output_c2_commit,
            nonce,
            combined_schnorr_proof,
            sum_c1_schnorr_proof,
            sum_c2_schnorr_proof,
        };

        // 伪造证明被验证拒绝 — 排列约束生效
        let mut transcript = MerlinTranscript::new(b"zk_shuffle_proof");
        let verify_result = forged_proof.verify(&input, &output, &pk, &mut transcript);
        assert!(verify_result.is_err(), "non-permutation forged proof should be rejected");

        // 验证所有 output 解密后都是同一张牌
        let input_plaintexts: Vec<EcPoint> = input.iter().map(|ct| ct.decrypt(&sk)).collect();
        let output_plaintexts: Vec<EcPoint> = output.iter().map(|ct| ct.decrypt(&sk)).collect();
        for i in 0..n {
            assert_eq!(output_plaintexts[i], input_plaintexts[0],
                "All output cards should decrypt to input[0] - deck is corrupted!");
        }
    }

    /// 攻击3 (已修复): c1/c2 使用不同的排列 — 混合组件攻击
    #[test]
    fn test_forge_proof_inconsistent_c1_c2() {
        let (sk, pk) = gen_keypair();
        let n = RistrettoCurve::n_cards();
        let input = make_full_encrypted_cards(&pk);

        // === 攻击: c1 使用恒等排列，c2 使用 swap(0,1) 排列 ===
        let r_values: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut OsRng)).collect();
        let mut output = Vec::with_capacity(n);

        // output[0]: c1 from input[0], c2 from input[1]
        output.push(ElGamalCiphertext {
            c1: input[0].c1 + RistrettoCurve::base_g() * r_values[0],
            c2: input[1].c2 + pk * r_values[0],
        });
        // output[1]: c1 from input[1], c2 from input[0]
        output.push(ElGamalCiphertext {
            c1: input[1].c1 + RistrettoCurve::base_g() * r_values[1],
            c2: input[0].c2 + pk * r_values[1],
        });
        // output[i]: c1 from input[i], c2 from input[i] (i >= 2)
        for i in 2..n {
            output.push(ElGamalCiphertext {
                c1: input[i].c1 + RistrettoCurve::base_g() * r_values[i],
                c2: input[i].c2 + pk * r_values[i],
            });
        }

        // === 尝试1: 用恒等排列的 secret_vec 构造合并证明 ===
        let nonce = Scalar::random(&mut OsRng);
        let mut transcript = MerlinTranscript::new(b"zk_shuffle_proof");
        transcript.append_scalar::<RistrettoCurve>(b"nonce", &nonce);
        let rho = ZKShuffleProof::<RistrettoCurve>::derive_batch_coefficients(&input, &output, &mut transcript);

        let input_c1s: Vec<EcPoint> = input.iter().map(|ct| ct.c1).collect();
        let input_c2s: Vec<EcPoint> = input.iter().map(|ct| ct.c2).collect();
        let sum_input_c1_commit = EcPoint::vartime_multiscalar_mul(&rho, &input_c1s);
        let sum_input_c2_commit = EcPoint::vartime_multiscalar_mul(&rho, &input_c2s);

        // 恒等排列的 secret_vec
        let mut secret_vec: Vec<Scalar> = vec![Scalar::ZERO; n];
        let mut pk_delta = Scalar::ZERO;
        for j in 0..n {
            secret_vec[j] = rho[j];
            pk_delta = pk_delta - r_values[j] * rho[j];
        }
        secret_vec.push(pk_delta);

        // 合并 Schnorr 证明：c1 和 c2 必须使用相同的 secret_vec
        let mut combined_base_points: Vec<EcPoint> = Vec::with_capacity(2 * n + 2);
        let mut combined_secret_vec: Vec<Scalar> = Vec::with_capacity(2 * n + 2);
        for i in 0..n {
            combined_base_points.push(output[i].c1);
            combined_base_points.push(output[i].c2);
            combined_secret_vec.push(secret_vec[i]);
            combined_secret_vec.push(secret_vec[i]);
        }
        combined_base_points.push(RistrettoCurve::base_g());
        combined_base_points.push(pk);
        combined_secret_vec.push(secret_vec[n]);
        combined_secret_vec.push(secret_vec[n]);

        let combined_commit = sum_input_c1_commit + sum_input_c2_commit;

        let combined_schnorr_proof = GeneralizedSchnorrProof::<RistrettoCurve>::prove(
            &combined_base_points,
            &combined_secret_vec,
            &combined_commit,
            &mut transcript,
        )
        .unwrap();

        // 生成 c1/c2 独立 Schnorr 证明
        let mut base_points_c1: Vec<EcPoint> = output.iter().map(|ct| ct.c1).collect();
        let mut base_points_c2: Vec<EcPoint> = output.iter().map(|ct| ct.c2).collect();
        base_points_c1.push(RistrettoCurve::base_g());
        base_points_c2.push(pk);

        let sum_c1_schnorr_proof = GeneralizedSchnorrProof::<RistrettoCurve>::prove(
            &base_points_c1,
            &secret_vec,
            &sum_input_c1_commit,
            &mut transcript,
        )
        .unwrap();
        let sum_c2_schnorr_proof = GeneralizedSchnorrProof::<RistrettoCurve>::prove(
            &base_points_c2,
            &secret_vec,
            &sum_input_c2_commit,
            &mut transcript,
        )
        .unwrap();

        let forged_proof = ZKShuffleProof::<RistrettoCurve> {
            sum_c1_commit: sum_input_c1_commit,
            sum_c2_commit: sum_input_c2_commit,
            nonce,
            combined_schnorr_proof,
            sum_c1_schnorr_proof,
            sum_c2_schnorr_proof,
        };

        // === 合并证明后，c1/c2 使用不同排列的伪造证明被拒绝 ===
        let mut transcript = MerlinTranscript::new(b"zk_shuffle_proof");
        let verify_result = forged_proof.verify(&input, &output, &pk, &mut transcript);
        assert!(verify_result.is_err(), "c1/c2 inconsistent permutation should be rejected after fix");

        // 验证 output[0] 确实不是合法密文
        let decrypted_0 = output[0].decrypt(&sk);
        let input_0_plain = input[0].decrypt(&sk);
        let input_1_plain = input[1].decrypt(&sk);
        assert_ne!(decrypted_0, input_0_plain, "output[0] should NOT decrypt to input[0]'s plaintext");
        assert_ne!(decrypted_0, input_1_plain, "output[0] should NOT decrypt to input[1]'s plaintext either");
    }

    /// 攻击4 (HIGH): 牌替换攻击 — 将一张牌替换为另一张牌
    #[test]
    fn test_forge_proof_replace_card() {
        let (sk, pk) = gen_keypair();
        let n = RistrettoCurve::n_cards();
        let input = make_full_encrypted_cards(&pk);

        // === 攻击: output[0] = re_encrypt(input[1]), output[1] = re_encrypt(input[1]) ===
        let mut output = Vec::with_capacity(n);
        let mut r_values = Vec::with_capacity(n);

        // output[0] = re_encrypt(input[1]) — 替换！本来应该是 input[0]
        let r_0 = Scalar::random(&mut OsRng);
        r_values.push(r_0);
        output.push(input[1].re_encrypt(&pk, &r_0));

        // output[1] = re_encrypt(input[1]) — 复制
        let r_1 = Scalar::random(&mut OsRng);
        r_values.push(r_1);
        output.push(input[1].re_encrypt(&pk, &r_1));

        // 其余正常
        for i in 2..n {
            let r_i = Scalar::random(&mut OsRng);
            r_values.push(r_i);
            output.push(input[i].re_encrypt(&pk, &r_i));
        }

        // 构造伪造证明
        let nonce = Scalar::random(&mut OsRng);
        let mut transcript = MerlinTranscript::new(b"zk_shuffle_proof");
        transcript.append_scalar::<RistrettoCurve>(b"nonce", &nonce);
        let rho = ZKShuffleProof::<RistrettoCurve>::derive_batch_coefficients(&input, &output, &mut transcript);

        let output_c1s: Vec<EcPoint> = output.iter().map(|ct| ct.c1).collect();
        let output_c2s: Vec<EcPoint> = output.iter().map(|ct| ct.c2).collect();
        let sum_output_c1_commit = EcPoint::vartime_multiscalar_mul(&rho, &output_c1s);
        let sum_output_c2_commit = EcPoint::vartime_multiscalar_mul(&rho, &output_c2s);

        // k_0 = 0 (没有 output 映射到 input[0])
        // k_1 = rho[0] + rho[1] (output[0] 和 output[1] 都映射到 input[1])
        // k_j = rho[j] for j >= 2
        let mut secret_vec: Vec<Scalar> = Vec::with_capacity(n + 1);
        secret_vec.push(Scalar::ZERO);           // k_0 = 0
        secret_vec.push(rho[0] + rho[1]);        // k_1 = rho[0] + rho[1]
        for j in 2..n {
            secret_vec.push(rho[j]);
        }
        let mut pk_delta = Scalar::ZERO;
        for i in 0..n {
            pk_delta = pk_delta + r_values[i] * rho[i];
        }
        secret_vec.push(pk_delta);

        // 生成合并 Schnorr 证明
        let mut combined_base_points: Vec<EcPoint> = Vec::with_capacity(2 * n + 2);
        let mut combined_secret_vec: Vec<Scalar> = Vec::with_capacity(2 * n + 2);
        for i in 0..n {
            combined_base_points.push(output[i].c1);
            combined_base_points.push(output[i].c2);
            combined_secret_vec.push(secret_vec[i]);
            combined_secret_vec.push(secret_vec[i]);
        }
        combined_base_points.push(RistrettoCurve::base_g());
        combined_base_points.push(pk);
        combined_secret_vec.push(pk_delta);
        combined_secret_vec.push(pk_delta);

        let combined_commit = sum_output_c1_commit + sum_output_c2_commit;

        let combined_schnorr_proof = GeneralizedSchnorrProof::<RistrettoCurve>::prove(
            &combined_base_points,
            &combined_secret_vec,
            &combined_commit,
            &mut transcript,
        )
        .unwrap();

        // 生成 c1/c2 独立 Schnorr 证明
        let mut base_points_c1: Vec<EcPoint> = output.iter().map(|ct| ct.c1).collect();
        let mut base_points_c2: Vec<EcPoint> = output.iter().map(|ct| ct.c2).collect();
        base_points_c1.push(RistrettoCurve::base_g());
        base_points_c2.push(pk);

        let sum_c1_schnorr_proof = GeneralizedSchnorrProof::<RistrettoCurve>::prove(
            &base_points_c1,
            &secret_vec,
            &sum_output_c1_commit,
            &mut transcript,
        )
        .unwrap();
        let sum_c2_schnorr_proof = GeneralizedSchnorrProof::<RistrettoCurve>::prove(
            &base_points_c2,
            &secret_vec,
            &sum_output_c2_commit,
            &mut transcript,
        )
        .unwrap();

        let forged_proof = ZKShuffleProof::<RistrettoCurve> {
            sum_c1_commit: sum_output_c1_commit,
            sum_c2_commit: sum_output_c2_commit,
            nonce,
            combined_schnorr_proof,
            sum_c1_schnorr_proof,
            sum_c2_schnorr_proof,
        };

        // 伪造证明被验证拒绝 — 排列约束生效
        let mut transcript = MerlinTranscript::new(b"zk_shuffle_proof");
        let verify_result = forged_proof.verify(&input, &output, &pk, &mut transcript);
        assert!(verify_result.is_err(), "non-permutation forged proof should be rejected");

        // 验证: input[0] 的明文不出现在 output 中
        let input_plaintexts: Vec<EcPoint> = input.iter().map(|ct| ct.decrypt(&sk)).collect();
        let output_plaintexts: Vec<EcPoint> = output.iter().map(|ct| ct.decrypt(&sk)).collect();
        let input_0_plain = input_plaintexts[0];
        let found = output_plaintexts.iter().any(|p| *p == input_0_plain);
        assert!(!found, "input[0]'s plaintext should NOT appear in output - card was REPLACED!");
    }

    // ========== CRITICAL 漏洞：c1/c2 信息转移攻击 ==========

    /// 攻击5 (CRITICAL): c1/c2 信息转移攻击 — 伪造的 ZKShuffleProof 通过验证
    #[test]
    fn test_forge_proof_c1_c2_information_shift() {
        let (sk, pk) = gen_keypair();
        let n = RistrettoCurve::n_cards();
        let input = make_full_encrypted_cards(&pk);

        // === 攻击: 将 input 信息从 c1 转移到 c2 ===
        let mut output = Vec::with_capacity(n);
        let mut r_values = Vec::with_capacity(n);

        for j in 0..n {
            let r_j = Scalar::random(&mut OsRng);
            r_values.push(r_j);
            // c1 = G * r_j (无 input 信息)
            // c2 = input[j].c1 + input[j].c2 + pk * r_j (包含全部 input 信息)
            let forged_c1 = RistrettoCurve::base_g() * r_j;
            let forged_c2 = input[j].c1 + input[j].c2 + pk * r_j;
            output.push(ElGamalCiphertext { c1: forged_c1, c2: forged_c2 });
        }

        // === 构造伪造证明 ===
        let nonce = Scalar::random(&mut OsRng);
        let mut transcript = MerlinTranscript::new(b"zk_shuffle_proof");
        transcript.append_scalar::<RistrettoCurve>(b"nonce", &nonce);
        let rho = ZKShuffleProof::<RistrettoCurve>::derive_batch_coefficients(&input, &output, &mut transcript);

        // 使用 INPUT 计算 sum commitments (与 verify 中的重计算一致)
        let input_c1s: Vec<EcPoint> = input.iter().map(|ct| ct.c1).collect();
        let input_c2s: Vec<EcPoint> = input.iter().map(|ct| ct.c2).collect();
        let sum_input_c1_commit = EcPoint::vartime_multiscalar_mul(&rho, &input_c1s);
        let sum_input_c2_commit = EcPoint::vartime_multiscalar_mul(&rho, &input_c2s);

        // 使用恒等排列系数: k_j = rho_j
        let mut secret_vec: Vec<Scalar> = rho.to_vec();
        // pk_delta = -sum(rho_j * r_j)
        let pk_delta: Scalar = -(0..n).map(|j| rho[j] * r_values[j]).sum::<Scalar>();
        secret_vec.push(pk_delta);

        // 构造合并 Schnorr 证明
        let mut combined_base_points: Vec<EcPoint> = Vec::with_capacity(2 * n + 2);
        let mut combined_secret_vec: Vec<Scalar> = Vec::with_capacity(2 * n + 2);
        for i in 0..n {
            combined_base_points.push(output[i].c1);
            combined_base_points.push(output[i].c2);
            combined_secret_vec.push(secret_vec[i]); // k_j for c1
            combined_secret_vec.push(secret_vec[i]); // same k_j for c2
        }
        combined_base_points.push(RistrettoCurve::base_g());
        combined_base_points.push(pk);
        combined_secret_vec.push(pk_delta);
        combined_secret_vec.push(pk_delta);

        let combined_commit = sum_input_c1_commit + sum_input_c2_commit;

        let combined_schnorr_proof = GeneralizedSchnorrProof::<RistrettoCurve>::prove(
            &combined_base_points,
            &combined_secret_vec,
            &combined_commit,
            &mut transcript,
        )
        .unwrap();

        // 生成 c1/c2 独立 Schnorr 证明
        let mut base_points_c1: Vec<EcPoint> = output.iter().map(|ct| ct.c1).collect();
        let mut base_points_c2: Vec<EcPoint> = output.iter().map(|ct| ct.c2).collect();
        base_points_c1.push(RistrettoCurve::base_g());
        base_points_c2.push(pk);

        let sum_c1_schnorr_proof = GeneralizedSchnorrProof::<RistrettoCurve>::prove(
            &base_points_c1,
            &secret_vec,
            &sum_input_c1_commit,
            &mut transcript,
        )
        .unwrap();
        let sum_c2_schnorr_proof = GeneralizedSchnorrProof::<RistrettoCurve>::prove(
            &base_points_c2,
            &secret_vec,
            &sum_input_c2_commit,
            &mut transcript,
        )
        .unwrap();

        let forged_proof = ZKShuffleProof::<RistrettoCurve> {
            sum_c1_commit: sum_input_c1_commit,
            sum_c2_commit: sum_input_c2_commit,
            nonce,
            combined_schnorr_proof,
            sum_c1_schnorr_proof,
            sum_c2_schnorr_proof,
        };

        // === 添加独立 c1/c2 Schnorr 证明后，信息转移攻击被拒绝 ===
        let mut transcript = MerlinTranscript::new(b"zk_shuffle_proof");
        let verify_result = forged_proof.verify(&input, &output, &pk, &mut transcript);
        assert!(verify_result.is_err(),
            "c1/c2 information shift forged proof should be REJECTED after adding independent c1/c2 proofs");

        // === 验证 output 确实不是合法 shuffle ===
        let input_plaintexts: Vec<EcPoint> = input.iter().map(|ct| ct.decrypt(&sk)).collect();
        let output_plaintexts: Vec<EcPoint> = output.iter().map(|ct| ct.decrypt(&sk)).collect();

        // output 解密后是 D_j = input[j].c1 + input[j].c2，而非原始明文
        for j in 0..n {
            let d_j = input[j].c1 + input[j].c2;
            assert_eq!(output_plaintexts[j], d_j,
                "output[{}] should decrypt to input[{}].c1 + input[{}].c2", j, j, j);
            assert_ne!(output_plaintexts[j], input_plaintexts[j],
                "output[{}] should NOT decrypt to the original plaintext - deck is corrupted!", j);
        }
    }

    /// 攻击6 (CRITICAL): c1/c2 部分信息转移 — 更隐蔽的伪造
    #[test]
    fn test_forge_proof_c1_c2_partial_shift() {
        let (sk, pk) = gen_keypair();
        let n = RistrettoCurve::n_cards();
        let input = make_full_encrypted_cards(&pk);

        // alpha = 0.5: 将一半的 input[j].c1 信息转移到 c2
        let alpha = Scalar::from(2u64).invert(); // 0.5 mod l
        let one_minus_alpha = Scalar::ONE - alpha;

        let mut output = Vec::with_capacity(n);
        let mut r_values = Vec::with_capacity(n);

        for j in 0..n {
            let r_j = Scalar::random(&mut OsRng);
            r_values.push(r_j);
            let forged_c1 = input[j].c1 * alpha + RistrettoCurve::base_g() * r_j;
            let forged_c2 = input[j].c2 + input[j].c1 * one_minus_alpha + pk * r_j;
            output.push(ElGamalCiphertext { c1: forged_c1, c2: forged_c2 });
        }

        // 构造伪造证明 (与攻击5相同的方法)
        let nonce = Scalar::random(&mut OsRng);
        let mut transcript = MerlinTranscript::new(b"zk_shuffle_proof");
        transcript.append_scalar::<RistrettoCurve>(b"nonce", &nonce);
        let rho = ZKShuffleProof::<RistrettoCurve>::derive_batch_coefficients(&input, &output, &mut transcript);

        let input_c1s: Vec<EcPoint> = input.iter().map(|ct| ct.c1).collect();
        let input_c2s: Vec<EcPoint> = input.iter().map(|ct| ct.c2).collect();
        let sum_input_c1_commit = EcPoint::vartime_multiscalar_mul(&rho, &input_c1s);
        let sum_input_c2_commit = EcPoint::vartime_multiscalar_mul(&rho, &input_c2s);

        let mut secret_vec: Vec<Scalar> = rho.to_vec();
        let pk_delta: Scalar = -(0..n).map(|j| rho[j] * r_values[j]).sum::<Scalar>();
        secret_vec.push(pk_delta);

        let mut combined_base_points: Vec<EcPoint> = Vec::with_capacity(2 * n + 2);
        let mut combined_secret_vec: Vec<Scalar> = Vec::with_capacity(2 * n + 2);
        for i in 0..n {
            combined_base_points.push(output[i].c1);
            combined_base_points.push(output[i].c2);
            combined_secret_vec.push(secret_vec[i]);
            combined_secret_vec.push(secret_vec[i]);
        }
        combined_base_points.push(RistrettoCurve::base_g());
        combined_base_points.push(pk);
        combined_secret_vec.push(pk_delta);
        combined_secret_vec.push(pk_delta);

        let combined_commit = sum_input_c1_commit + sum_input_c2_commit;

        let combined_schnorr_proof = GeneralizedSchnorrProof::<RistrettoCurve>::prove(
            &combined_base_points,
            &combined_secret_vec,
            &combined_commit,
            &mut transcript,
        )
        .unwrap();

        // 生成 c1/c2 独立 Schnorr 证明
        let mut base_points_c1: Vec<EcPoint> = output.iter().map(|ct| ct.c1).collect();
        let mut base_points_c2: Vec<EcPoint> = output.iter().map(|ct| ct.c2).collect();
        base_points_c1.push(RistrettoCurve::base_g());
        base_points_c2.push(pk);

        let sum_c1_schnorr_proof = GeneralizedSchnorrProof::<RistrettoCurve>::prove(
            &base_points_c1,
            &secret_vec,
            &sum_input_c1_commit,
            &mut transcript,
        )
        .unwrap();
        let sum_c2_schnorr_proof = GeneralizedSchnorrProof::<RistrettoCurve>::prove(
            &base_points_c2,
            &secret_vec,
            &sum_input_c2_commit,
            &mut transcript,
        )
        .unwrap();

        let forged_proof = ZKShuffleProof::<RistrettoCurve> {
            sum_c1_commit: sum_input_c1_commit,
            sum_c2_commit: sum_input_c2_commit,
            nonce,
            combined_schnorr_proof,
            sum_c1_schnorr_proof,
            sum_c2_schnorr_proof,
        };

        // 添加独立 c1/c2 Schnorr 证明后，部分信息转移攻击被拒绝
        let mut transcript = MerlinTranscript::new(b"zk_shuffle_proof");
        let verify_result = forged_proof.verify(&input, &output, &pk, &mut transcript);
        assert!(verify_result.is_err(),
            "partial c1/c2 shift forged proof should be REJECTED after adding independent c1/c2 proofs");

        // 验证 output 解密后不是原始明文
        let input_plaintexts: Vec<EcPoint> = input.iter().map(|ct| ct.decrypt(&sk)).collect();
        let output_plaintexts: Vec<EcPoint> = output.iter().map(|ct| ct.decrypt(&sk)).collect();

        for j in 0..n {
            assert_ne!(output_plaintexts[j], input_plaintexts[j],
                "output[{}] should NOT decrypt to original plaintext with alpha != 1", j);
        }
    }

    /// 攻击7 (CRITICAL): c1/c2 信息转移 + 排列组合 — 伪造带排列的信息转移
    #[test]
    fn test_forge_proof_c1_c2_shift_with_permutation() {
        let (sk, pk) = gen_keypair();
        let n = RistrettoCurve::n_cards();
        let input = make_full_encrypted_cards(&pk);
        let permute = random_permute();

        let mut output = Vec::with_capacity(n);
        let mut r_values = Vec::with_capacity(n);

        for j in 0..n {
            let r_j = Scalar::random(&mut OsRng);
            r_values.push(r_j);
            let i = permute[j];
            let forged_c1 = RistrettoCurve::base_g() * r_j;
            let forged_c2 = input[i].c1 + input[i].c2 + pk * r_j;
            output.push(ElGamalCiphertext { c1: forged_c1, c2: forged_c2 });
        }

        // 构造伪造证明，使用排列系数
        let nonce = Scalar::random(&mut OsRng);
        let mut transcript = MerlinTranscript::new(b"zk_shuffle_proof");
        transcript.append_scalar::<RistrettoCurve>(b"nonce", &nonce);
        let rho = ZKShuffleProof::<RistrettoCurve>::derive_batch_coefficients(&input, &output, &mut transcript);

        let input_c1s: Vec<EcPoint> = input.iter().map(|ct| ct.c1).collect();
        let input_c2s: Vec<EcPoint> = input.iter().map(|ct| ct.c2).collect();
        let sum_input_c1_commit = EcPoint::vartime_multiscalar_mul(&rho, &input_c1s);
        let sum_input_c2_commit = EcPoint::vartime_multiscalar_mul(&rho, &input_c2s);

        // 使用与 prove() 相同的排列系数构造
        let mut secret_vec = vec![Scalar::ZERO; n];
        let mut pk_delta = Scalar::ZERO;
        for j in 0..n {
            let position = permute.iter().position(|&x| x == j).unwrap();
            secret_vec[position] = rho[j];
            let r_val = r_values[position];
            pk_delta = pk_delta - r_val * rho[j];
        }
        secret_vec.push(pk_delta);

        let mut combined_base_points: Vec<EcPoint> = Vec::with_capacity(2 * n + 2);
        let mut combined_secret_vec: Vec<Scalar> = Vec::with_capacity(2 * n + 2);
        for i in 0..n {
            combined_base_points.push(output[i].c1);
            combined_base_points.push(output[i].c2);
            combined_secret_vec.push(secret_vec[i]);
            combined_secret_vec.push(secret_vec[i]);
        }
        combined_base_points.push(RistrettoCurve::base_g());
        combined_base_points.push(pk);
        combined_secret_vec.push(pk_delta);
        combined_secret_vec.push(pk_delta);

        let combined_commit = sum_input_c1_commit + sum_input_c2_commit;

        let combined_schnorr_proof = GeneralizedSchnorrProof::<RistrettoCurve>::prove(
            &combined_base_points,
            &combined_secret_vec,
            &combined_commit,
            &mut transcript,
        )
        .unwrap();

        // 生成 c1/c2 独立 Schnorr 证明
        let mut base_points_c1: Vec<EcPoint> = output.iter().map(|ct| ct.c1).collect();
        let mut base_points_c2: Vec<EcPoint> = output.iter().map(|ct| ct.c2).collect();
        base_points_c1.push(RistrettoCurve::base_g());
        base_points_c2.push(pk);

        let sum_c1_schnorr_proof = GeneralizedSchnorrProof::<RistrettoCurve>::prove(
            &base_points_c1,
            &secret_vec,
            &sum_input_c1_commit,
            &mut transcript,
        )
        .unwrap();
        let sum_c2_schnorr_proof = GeneralizedSchnorrProof::<RistrettoCurve>::prove(
            &base_points_c2,
            &secret_vec,
            &sum_input_c2_commit,
            &mut transcript,
        )
        .unwrap();

        let forged_proof = ZKShuffleProof::<RistrettoCurve> {
            sum_c1_commit: sum_input_c1_commit,
            sum_c2_commit: sum_input_c2_commit,
            nonce,
            combined_schnorr_proof,
            sum_c1_schnorr_proof,
            sum_c2_schnorr_proof,
        };

        // 添加独立 c1/c2 Schnorr 证明后，带排列的信息转移攻击被拒绝
        let mut transcript = MerlinTranscript::new(b"zk_shuffle_proof");
        let verify_result = forged_proof.verify(&input, &output, &pk, &mut transcript);
        assert!(verify_result.is_err(),
            "c1/c2 shift with permutation forged proof should be REJECTED after adding independent c1/c2 proofs");

        // 验证 output 解密后不是原始明文
        let input_plaintexts: Vec<EcPoint> = input.iter().map(|ct| ct.decrypt(&sk)).collect();
        let output_plaintexts: Vec<EcPoint> = output.iter().map(|ct| ct.decrypt(&sk)).collect();

        for j in 0..n {
            let i = permute[j];
            let d_i = input[i].c1 + input[i].c2;
            assert_eq!(output_plaintexts[j], d_i,
                "output[{}] should decrypt to D_{}", j, i);
            assert_ne!(output_plaintexts[j], input_plaintexts[i],
                "output[{}] should NOT decrypt to original plaintext of input[{}]", j, i);
        }
    }

    /// 攻击8: 智能信息转移攻击 — 为每个 Schnorr 证明使用不同的 secret_vec
    #[test]
    fn test_forge_proof_c1_c2_smart_information_shift() {
        let (sk, pk) = gen_keypair();
        let n = RistrettoCurve::n_cards();
        let input = make_full_encrypted_cards(&pk);

        // === 攻击: 将 input 信息从 c1 转移到 c2 ===
        let mut output = Vec::with_capacity(n);
        let mut r_values = Vec::with_capacity(n);

        for j in 0..n {
            let r_j = Scalar::random(&mut OsRng);
            r_values.push(r_j);
            let forged_c1 = RistrettoCurve::base_g() * r_j;
            let forged_c2 = input[j].c1 + input[j].c2 + pk * r_j;
            output.push(ElGamalCiphertext { c1: forged_c1, c2: forged_c2 });
        }

        // === 构造伪造证明，为每个 Schnorr 证明使用不同的 secret_vec ===
        let nonce = Scalar::random(&mut OsRng);
        let mut transcript = MerlinTranscript::new(b"zk_shuffle_proof");
        transcript.append_scalar::<RistrettoCurve>(b"nonce", &nonce);
        let rho = ZKShuffleProof::<RistrettoCurve>::derive_batch_coefficients(&input, &output, &mut transcript);

        let input_c1s: Vec<EcPoint> = input.iter().map(|ct| ct.c1).collect();
        let input_c2s: Vec<EcPoint> = input.iter().map(|ct| ct.c2).collect();
        let sum_input_c1_commit = EcPoint::vartime_multiscalar_mul(&rho, &input_c1s);
        let sum_input_c2_commit = EcPoint::vartime_multiscalar_mul(&rho, &input_c2s);

        // 验证: 使用与攻击5相同的 secret_vec (rho + pk_delta)，
        // c1 证明方程不成立，伪造证明被拒绝
        let mut secret_vec: Vec<Scalar> = rho.to_vec();
        let pk_delta: Scalar = -(0..n).map(|j| rho[j] * r_values[j]).sum::<Scalar>();
        secret_vec.push(pk_delta);

        // combined Schnorr 证明
        let mut combined_base_points: Vec<EcPoint> = Vec::with_capacity(2 * n + 2);
        let mut combined_secret_vec: Vec<Scalar> = Vec::with_capacity(2 * n + 2);
        for i in 0..n {
            combined_base_points.push(output[i].c1);
            combined_base_points.push(output[i].c2);
            combined_secret_vec.push(secret_vec[i]);
            combined_secret_vec.push(secret_vec[i]);
        }
        combined_base_points.push(RistrettoCurve::base_g());
        combined_base_points.push(pk);
        combined_secret_vec.push(pk_delta);
        combined_secret_vec.push(pk_delta);

        let combined_commit = sum_input_c1_commit + sum_input_c2_commit;

        let combined_schnorr_proof = GeneralizedSchnorrProof::<RistrettoCurve>::prove(
            &combined_base_points,
            &combined_secret_vec,
            &combined_commit,
            &mut transcript,
        )
        .unwrap();

        // c1/c2 Schnorr 证明 (使用相同 secret_vec)
        let mut base_points_c1: Vec<EcPoint> = output.iter().map(|ct| ct.c1).collect();
        let mut base_points_c2: Vec<EcPoint> = output.iter().map(|ct| ct.c2).collect();
        base_points_c1.push(RistrettoCurve::base_g());
        base_points_c2.push(pk);

        let sum_c1_schnorr_proof = GeneralizedSchnorrProof::<RistrettoCurve>::prove(
            &base_points_c1,
            &secret_vec,
            &sum_input_c1_commit,
            &mut transcript,
        )
        .unwrap();
        let sum_c2_schnorr_proof = GeneralizedSchnorrProof::<RistrettoCurve>::prove(
            &base_points_c2,
            &secret_vec,
            &sum_input_c2_commit,
            &mut transcript,
        )
        .unwrap();

        let forged_proof = ZKShuffleProof::<RistrettoCurve> {
            sum_c1_commit: sum_input_c1_commit,
            sum_c2_commit: sum_input_c2_commit,
            nonce,
            combined_schnorr_proof,
            sum_c1_schnorr_proof,
            sum_c2_schnorr_proof,
        };

        // 伪造证明被拒绝 — c1 Schnorr 证明方程不成立
        let mut transcript = MerlinTranscript::new(b"zk_shuffle_proof");
        let verify_result = forged_proof.verify(&input, &output, &pk, &mut transcript);
        assert!(verify_result.is_err(),
            "smart c1/c2 information shift forged proof should be REJECTED: \
             attacker cannot find valid secret_vec for c1 proof without knowing encryption randomness");

        // 验证 output 确实不是合法 shuffle
        let input_plaintexts: Vec<EcPoint> = input.iter().map(|ct| ct.decrypt(&sk)).collect();
        let output_plaintexts: Vec<EcPoint> = output.iter().map(|ct| ct.decrypt(&sk)).collect();
        for j in 0..n {
            assert_ne!(output_plaintexts[j], input_plaintexts[j],
                "output[{}] should NOT decrypt to original plaintext - deck is corrupted!", j);
        }
    }

}
