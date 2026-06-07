use crate::crypto::curve::{Curve, CurvePoint, CurveScalar};
use merlin::Transcript;
use crate::zk_shuffle::error::VerificationError;
use crate::zk_shuffle::transcript_ext::TranscriptExtension;

/// Generalized Schnorr proof for proving that a point R is a linear combination
/// of multiple base points G_1, G_2, ..., G_n.
/// Proves: R = sum(k_i * G_i) for secret scalars k_1, k_2, ..., k_n.
#[derive(Debug, Clone)]
pub struct GeneralizedSchnorrProof<C: Curve> {
    /// Commitment point T = sum(r_i * G_i)
    pub commitment: C::Point,
    /// Response scalars s_i = r_i + c * k_i for each secret
    pub responses: Vec<C::Scalar>,
}

impl<C: Curve> GeneralizedSchnorrProof<C> {
    /// Generate a generalized Schnorr proof.
    ///
    /// # Arguments
    /// * `base_points` - Base points G_1, G_2, ..., G_n
    /// * `secrets` - Secret scalars k_1, k_2, ..., k_n
    /// * `R` - The point R = sum(k_i * G_i) to prove knowledge of
    /// * `transcript` - Merlin transcript for Fiat-Shamir transform
    ///
    /// # Security
    /// This function validates that base points are not identity to prevent
    /// trivial attacks where a base point of zero could compromise the proof.
    pub fn prove(
        base_points: &[C::Point],
        secrets: &[C::Scalar],
        R: &C::Point,
        transcript: &mut Transcript,
    ) -> Result<Self, VerificationError>
    where Transcript: TranscriptExtension<C>,
    {
        if base_points.len() != secrets.len() {
            return Err(VerificationError::LengthMismatch);
        }
        if R.is_identity() {
            return Err(VerificationError::IdentityBasePoint);
        }

        let n = base_points.len();

        // SECURITY: Validate that no base point is identity (zero point)
        for G_i in base_points.iter() {
            if G_i.is_identity() {
                return Err(VerificationError::IdentityBasePoint);
            }
        }

        // Append public values to transcript
        transcript.append_message(b"gen_schnorr_n", &(n as u64).to_le_bytes());
        for G_i in base_points {
            TranscriptExtension::<C>::append_point(transcript, b"gen_schnorr_base", G_i);
        }
        TranscriptExtension::<C>::append_point(transcript, b"gen_schnorr_R", R);

        // Generate n random scalars r_1, r_2, ..., r_n
        let r_vec: Vec<C::Scalar> = (0..n)
            .map(|_| C::Scalar::random(&mut rand_core::OsRng))
            .collect();

        // Compute commitment T = sum(r_i * G_i)
        let commitment = C::Point::vartime_multiscalar_mul(&r_vec, base_points);

        // Append commitment to transcript
        TranscriptExtension::<C>::append_point(transcript, b"gen_schnorr_commitment", &commitment);

        // Get challenge scalar c = H(G_1, ..., G_n, R, T)
        let c = TranscriptExtension::<C>::challenge(transcript, b"gen_schnorr_challenge").scalar;

        // Compute responses: s_i = r_i + c * k_i
        let responses: Vec<C::Scalar> = r_vec
            .iter()
            .zip(secrets.iter())
            .map(|(r_i, k_i)| *r_i + c * *k_i)
            .collect();

        Ok(Self {
            commitment,
            responses,
        })
    }

    /// Verify a generalized Schnorr proof.
    ///
    /// # Arguments
    /// * `base_points` - Base points G_1, G_2, ..., G_n
    /// * `R` - The claimed linear combination point
    /// * `transcript` - Merlin transcript for Fiat-Shamir transform
    ///
    /// # Security
    /// This function validates that base points are not identity to ensure
    /// the proof maintains its knowledge soundness property.
    pub fn verify(
        &self,
        base_points: &[C::Point],
        R: &C::Point,
        transcript: &mut Transcript,
    ) -> Result<(), VerificationError>
    where Transcript: TranscriptExtension<C>,
    {
        if self.responses.len() != base_points.len() {
            return Err(VerificationError::InvalidDLEQProof);
        }

        if R.is_identity() {
            return Err(VerificationError::InvalidDLEQProof);
        }

        let n = base_points.len();

        // SECURITY FIX: Validate that no base point is identity (zero point)
        for G_i in base_points.iter() {
            if G_i.is_identity(){
                return Err(VerificationError::InvalidDLEQProof);
            }
        }

        // Append public values to transcript (same as in prove)
        transcript.append_message(b"gen_schnorr_n", &(n as u64).to_le_bytes());
        for G_i in base_points {
            TranscriptExtension::<C>::append_point(transcript, b"gen_schnorr_base", G_i);
        }
        TranscriptExtension::<C>::append_point(transcript, b"gen_schnorr_R", R);

        // Append commitment to transcript
        TranscriptExtension::<C>::append_point(transcript, b"gen_schnorr_commitment", &self.commitment);

        // Get challenge scalar c
        let c = TranscriptExtension::<C>::challenge(transcript, b"gen_schnorr_challenge").scalar;

        // Verify: sum(s_i * G_i) == T + c * R
        let lhs = C::Point::vartime_multiscalar_mul(&self.responses, base_points);
        let rhs = self.commitment + *R * c;

        if lhs == rhs {
            Ok(())
        } else {
            Err(VerificationError::InvalidDLEQProof)
        }
    }
}
