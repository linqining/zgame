use crate::crypto::curve::{Curve, CurveScalar, ElGamalCiphertextGeneric};
use crate::zk_shuffle::transcript_ext::TranscriptExtension;
use merlin::Transcript;
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
where
    Transcript: TranscriptExtension<C>,
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
        transcript: &mut Transcript,
    ) -> Self {
        let n = input_cts.len().min(output_cts.len()).min(C::n_cards());
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
        transcript.append_point(labels.pk, player_pk);
        for ct in &input_cts[..n] {
            transcript.append_point(labels.input_c1, &ct.c1);
            transcript.append_point(labels.input_c2, &ct.c2);
        }
        for ct in &output_cts[..n] {
            transcript.append_point(labels.output_c1, &ct.c1);
            transcript.append_point(labels.output_c2, &ct.c2);
        }
        for a_i in &per_card_commitments {
            transcript.append_point(labels.per_card_commitment, a_i);
        }
        transcript.append_point(labels.commitment_pk, &commitment_pk);
        for d2 in &d2_values {
            transcript.append_point(labels.d2, d2);
        }
        transcript.append_scalar(labels.nonce, &nonce);
        let c = transcript.challenge(labels.challenge).scalar;

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
        transcript: &mut Transcript,
    ) -> bool {
        let n = input_cts.len().min(output_cts.len()).min(C::n_cards());

        if self.per_card_commitments.len() != n {
            tracing::error!("Invalid per-card commitments {}", n);
            return false;
        }

        for i in 0..n {
            if input_cts[i].c1 != output_cts[i].c1 {
                tracing::error!("Invalid input card c1: {:?}", input_cts[i].c1);
                return false;
            }
        }

        // Compute d2 values using the kind-specific direction
        let d2_values: Vec<C::Point> = (0..n)
            .map(|i| K::compute_d2(&input_cts[i].c2, &output_cts[i].c2))
            .collect();

        // Derive challenge using Merlin Transcript
        let labels = K::labels();
        transcript.append_point(labels.pk, player_pk);
        for ct in &input_cts[..n] {
            transcript.append_point(labels.input_c1, &ct.c1);
            transcript.append_point(labels.input_c2, &ct.c2);
        }
        for ct in &output_cts[..n] {
            transcript.append_point(labels.output_c1, &ct.c1);
            transcript.append_point(labels.output_c2, &ct.c2);
        }
        for a_i in &self.per_card_commitments {
            transcript.append_point(labels.per_card_commitment, a_i);
        }
        transcript.append_point(labels.commitment_pk, &self.commitment_pk);
        for d2 in &d2_values {
            transcript.append_point(labels.d2, d2);
        }
        transcript.append_scalar(labels.nonce, &self.nonce);
        let c = transcript.challenge(labels.challenge).scalar;

        // Check pk DLEq: G * response == commitment_pk + pk * c
        if C::base_g() * self.response != self.commitment_pk + *player_pk * c {
            tracing::error!("Invalid response: {:?}", self.response);
            return false;
        }

        // Check per-card DLEq: input_cts[i].c1 * response == per_card_commitments[i] + d2_i * c
        // This proves: input_cts[i].c1 * sk = d2_i for EACH card individually
        for i in 0..n {
            if input_cts[i].c1 * self.response != self.per_card_commitments[i] + d2_values[i] * c {
                tracing::error!("Invalid per-card commitment: {:?}", self.per_card_commitments[i]);
                return false;
            }
        }

        true
    }
}
