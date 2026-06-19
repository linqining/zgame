use crate::crypto::curve::{Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric};
use crate::zk_shuffle::transcript_ext::CryptoTranscript;
use rand_core::OsRng;
use std::marker::PhantomData;

/// Labels used in the Merlin transcript for DLEq proof generation/verification.
pub struct DLEqProofLabels {
    pub pk: &'static [u8],
    pub input_c1: &'static [u8],
    pub input_c2: &'static [u8],
    pub output_c1: &'static [u8],
    pub output_c2: &'static [u8],
    pub per_card_commitment: &'static [u8],
    pub commitment_pk: &'static [u8],
    pub d2: &'static [u8],
    pub nonce: &'static [u8],
    pub challenge: &'static [u8],
}

/// Trait distinguishing different DLEq proof kinds (remask vs leave).
///
/// Each kind provides its own transcript labels and d2 computation direction:
/// - Remask: d2 = output.c2 - input.c2 (adds encryption layer)
/// - Leave:  d2 = input.c2 - output.c2 (removes encryption layer)
pub trait DLEqProofKind<C: Curve> {
    /// Transcript labels for this proof kind.
    fn labels() -> &'static DLEqProofLabels;

    /// Compute the d2 value from input and output ciphertext c2 components.
    fn compute_d2(input_c2: &C::Point, output_c2: &C::Point) -> C::Point;

    /// Whether to validate output ciphertexts with `is_valid()` in verify().
    /// 兼容 Move 合约：remask_proof 校验输入和输出密文有效性，
    /// leave_proof 仅校验输入密文有效性。
    fn validates_output_ciphertexts() -> bool;
}

/// Marker type for remask DLEq proofs.
#[derive(Debug, Clone, Copy)]
pub struct RemaskKind;

/// Marker type for leave DLEq proofs.
#[derive(Debug, Clone, Copy)]
pub struct LeaveKind;

impl<C: Curve> DLEqProofKind<C> for RemaskKind {
    fn labels() -> &'static DLEqProofLabels {
        static LABELS: DLEqProofLabels = DLEqProofLabels {
            pk: b"remask_pk",
            input_c1: b"remask_input_c1",
            input_c2: b"remask_input_c2",
            output_c1: b"remask_output_c1",
            output_c2: b"remask_output_c2",
            per_card_commitment: b"remask_per_card_commitment",
            commitment_pk: b"remask_commitment_pk",
            d2: b"remask_d2",
            nonce: b"remask_nonce",
            challenge: b"remask_challenge",
        };
        &LABELS
    }

    fn compute_d2(input_c2: &C::Point, output_c2: &C::Point) -> C::Point {
        output_c2.clone() - input_c2.clone()
    }

    fn validates_output_ciphertexts() -> bool {
        // 兼容 Move 合约 remask_proof::verify：校验输入和输出密文有效性
        true
    }
}

impl<C: Curve> DLEqProofKind<C> for LeaveKind {
    fn labels() -> &'static DLEqProofLabels {
        static LABELS: DLEqProofLabels = DLEqProofLabels {
            pk: b"leave_pk",
            input_c1: b"leave_input_c1",
            input_c2: b"leave_input_c2",
            output_c1: b"leave_output_c1",
            output_c2: b"leave_output_c2",
            per_card_commitment: b"leave_per_card_commitment",
            commitment_pk: b"leave_commitment_pk",
            d2: b"leave_d2",
            nonce: b"leave_nonce",
            challenge: b"leave_challenge",
        };
        &LABELS
    }

    fn compute_d2(input_c2: &C::Point, output_c2: &C::Point) -> C::Point {
        input_c2.clone() - output_c2.clone()
    }

    fn validates_output_ciphertexts() -> bool {
        // 兼容 Move 合约 leave_proof::verify：仅校验输入密文有效性
        false
    }
}

/// Generic per-card DLEq proof structure.
///
/// Parameterized by curve type `C` and proof kind `K` (RemaskKind or LeaveKind).
/// The proof kind determines the transcript labels and the direction of the
/// d2 computation (output - input for remask, input - output for leave).
#[derive(Debug, Clone)]
pub struct DLEqProof<C: Curve, K: DLEqProofKind<C>> {
    /// Per-card DLEq commitments: A_i = input_cts[i].c1 * ω
    /// These bind each card individually, preventing aggregate-only attacks
    /// where a malicious prover modifies pairs of output cards while
    /// preserving the aggregate relationship.
    pub per_card_commitments: Vec<C::Point>,
    /// Commitment for pk DLEq: B = G * ω
    pub commitment_pk: C::Point,
    /// Single response: s = ω + c * sk (shared witness across all cards)
    pub response: C::Scalar,
    /// Nonce for uniqueness
    pub nonce: C::Scalar,
    _kind: PhantomData<K>,
}

impl<C: Curve, K: DLEqProofKind<C>> DLEqProof<C, K>
{
    /// Reconstruct a DLEqProof from its constituent parts.
    ///
    /// This is intended for deserialization (e.g., from JSON). For proof
    /// generation, use [`DLEqProof::prove`] instead.
    pub fn from_parts(
        per_card_commitments: Vec<C::Point>,
        commitment_pk: C::Point,
        response: C::Scalar,
        nonce: C::Scalar,
    ) -> Self {
        DLEqProof {
            per_card_commitments,
            commitment_pk,
            response,
            nonce,
            _kind: PhantomData,
        }
    }

    /// Generate a DLEq proof that the same secret key was used across all cards.
    pub fn prove(
        input_cts: &[ElGamalCiphertextGeneric<C>],
        output_cts: &[ElGamalCiphertextGeneric<C>],
        player_sk: &C::Scalar,
        player_pk: &C::Point,
        transcript: &mut impl CryptoTranscript,
    ) -> Self {
        // 兼容 Move 合约：使用严格长度（无 n_cards 截断）。
        // verify() 会强制 input_cts.len() == output_cts.len() == per_card_commitments.len()。
        let n = input_cts.len().min(output_cts.len());
        let mut rng = OsRng;

        let omega = C::Scalar::random(&mut rng);

        // Per-card commitments: A_i = input_cts[i].c1 * ω
        let per_card_commitments: Vec<C::Point> = input_cts[..n]
            .iter()
            .map(|ct| ct.c1 * omega)
            .collect();

        // pk DLEq commitment: B = G * ω
        let commitment_pk = C::base_g() * omega;

        let nonce = C::Scalar::random(&mut rng);

        // Compute d2 values using the kind-specific direction
        let d2_values: Vec<C::Point> = (0..n)
            .map(|i| K::compute_d2(&input_cts[i].c2, &output_cts[i].c2))
            .collect();

        // Derive challenge using Merlin Transcript (properly hashes all inputs)
        let labels = K::labels();
        transcript.append_point::<C>(labels.pk, player_pk);
        for ct in &input_cts[..n] {
            transcript.append_point::<C>(labels.input_c1, &ct.c1);
            transcript.append_point::<C>(labels.input_c2, &ct.c2);
        }
        for ct in &output_cts[..n] {
            transcript.append_point::<C>(labels.output_c1, &ct.c1);
            transcript.append_point::<C>(labels.output_c2, &ct.c2);
        }
        for a_i in &per_card_commitments {
            transcript.append_point::<C>(labels.per_card_commitment, a_i);
        }
        transcript.append_point::<C>(labels.commitment_pk, &commitment_pk);
        for d2 in &d2_values {
            transcript.append_point::<C>(labels.d2, d2);
        }
        transcript.append_scalar::<C>(labels.nonce, &nonce);
        let c = transcript.challenge::<C>(labels.challenge).scalar;

        let response = omega + c * *player_sk;

        DLEqProof {
            per_card_commitments,
            commitment_pk,
            response,
            nonce,
            _kind: PhantomData,
        }
    }

    /// Verify a DLEq proof.
    pub fn verify(
        &self,
        input_cts: &[ElGamalCiphertextGeneric<C>],
        output_cts: &[ElGamalCiphertextGeneric<C>],
        player_pk: &C::Point,
        transcript: &mut impl CryptoTranscript,
    ) -> bool {
        // 兼容 Move 合约 leave_proof/remask_proof::verify：n 来源于 per_card_commitments 长度
        let n = self.per_card_commitments.len();

        // M-P15: 空输入校验——n == 0 时无任何牌需要 remask/leave，proof 无意义，拒绝验证。
        if n == 0 {
            tracing::error!("Invalid proof: n == 0");
            return false;
        }

        // 1. 检查长度一致（严格相等，匹配 Move 合约）
        if n != input_cts.len() {
            tracing::error!("Invalid input_cts length: {} != {}", n, input_cts.len());
            return false;
        }
        if n != output_cts.len() {
            tracing::error!("Invalid output_cts length: {} != {}", n, output_cts.len());
            return false;
        }

        // M6 修复：拒绝恒等元 player_pk——sk=0 时 d2=0，证明平凡成立但操作为 no-op
        if player_pk.is_identity() {
            tracing::error!("Invalid player_pk: identity");
            return false;
        }

        // 2. 检查 c1 不变性 + M7 修复：校验密文有效性 + 计算 d2 values
        let mut d2_values: Vec<C::Point> = Vec::with_capacity(n);
        for i in 0..n {
            // M7: 校验输入密文有效性（c1/c2 非 identity）
            if !input_cts[i].is_valid() {
                tracing::error!("Invalid input ciphertext at index {}", i);
                return false;
            }
            // M7: RemaskKind 也校验输出密文有效性（匹配 Move remask_proof::verify）
            if K::validates_output_ciphertexts() && !output_cts[i].is_valid() {
                tracing::error!("Invalid output ciphertext at index {}", i);
                return false;
            }
            if input_cts[i].c1 != output_cts[i].c1 {
                tracing::error!(
                    "c1 mismatch at index {} (n={}): input_c1={:?} output_c1={:?}",
                    i, n, input_cts[i].c1, output_cts[i].c1
                );
                return false;
            }
            d2_values.push(K::compute_d2(&input_cts[i].c2, &output_cts[i].c2));
        }

        // M-P17:点非 identity——点非 identity——identity 承诺削弱证明安全性
        if self.commitment_pk.is_identity() {
            tracing::error!("Invalid commitment_pk: identity");
            return false;
        }

        // 3. 构建 challenge：追加到 transcript
        let labels = K::labels();
        transcript.append_point::<C>(labels.pk, player_pk);
        for ct in &input_cts[..n] {
            transcript.append_point::<C>(labels.input_c1, &ct.c1);
            transcript.append_point::<C>(labels.input_c2, &ct.c2);
        }
        for ct in &output_cts[..n] {
            transcript.append_point::<C>(labels.output_c1, &ct.c1);
            transcript.append_point::<C>(labels.output_c2, &ct.c2);
        }
        for a_i in &self.per_card_commitments {
            transcript.append_point::<C>(labels.per_card_commitment, a_i);
        }
        transcript.append_point::<C>(labels.commitment_pk, &self.commitment_pk);
        for d2 in &d2_values {
            transcript.append_point::<C>(labels.d2, d2);
        }
        transcript.append_scalar::<C>(labels.nonce, &self.nonce);
        let c = transcript.challenge::<C>(labels.challenge).scalar;

        // 4. 验证 pk DLEq: G * response == commitment_pk + pk * c
        if C::base_g() * self.response != self.commitment_pk + *player_pk * c {
            tracing::error!("Invalid response: {:?}", self.response);
            return false;
        }

        // 5. 验证 per-card DLEq: input_cts[i].c1 * response == per_card_commitments[i] + d2_i * c
        for i in 0..n {
            if input_cts[i].c1 * self.response != self.per_card_commitments[i] + d2_values[i] * c {
                tracing::error!("Invalid per-card commitment: {:?}", self.per_card_commitments[i]);
                return false;
            }
        }

        true
    }
}
