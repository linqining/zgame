use crate::zk_shuffle::transcript_ext::CryptoTranscript;
use rand_core::OsRng;
use crate::crypto::curve::{Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric};
pub use crate::zk_shuffle::error::VerificationError;
use super::chaum_pedersen::ChaumPedersenDLEQProof;

#[derive(Debug, Clone)]
pub struct SwapOutCardProof<C: Curve>{
    pub user_readable_card: ElGamalCiphertextGeneric<C>,
    pub swap_out_card: ElGamalCiphertextGeneric<C>,
    /// Chaum-Pedersen proof 证明 delta_c2 和 user_pk 有共同变量 user_sk
    /// 即证明存在 user_sk 使得: delta_c1 * user_sk = delta_c2 且 G * user_sk = user_pk
    pub chaum_pedersen_proof: ChaumPedersenDLEQProof<C>,
}

impl<C: Curve> SwapOutCardProof<C>{
    /// 证明swap_out_card 是由user_readable_card 一一 替换出来的
    /// swap_scalar 是 swap_out_card - user_readable_card 的系数
    pub(crate) fn prove(user_readable_card: ElGamalCiphertextGeneric<C>, swap_out_card: ElGamalCiphertextGeneric<C>, user_sk: &C::Scalar, user_pk: &C::Point, transcript: &mut impl CryptoTranscript) -> Result<Self, VerificationError>
    {
        let delta_c1 = swap_out_card.c1 - user_readable_card.c1;
        let delta_c2 = swap_out_card.c2 - user_readable_card.c2;
        // 生成 Chaum-Pedersen DLEQ proof，证明 delta_c1 和 G 有共同的离散对数 user_sk
        // G1=delta_c1, G2=G(base point), s=user_sk, P1=delta_c2, P2=user_pk
        let chaum_pedersen_proof = ChaumPedersenDLEQProof::<C>::prove(
            delta_c1,
            C::base_g(),
            *user_sk,
            delta_c2,
            *user_pk,
            transcript,
        )?;

        Ok(Self{
            user_readable_card,
            swap_out_card,
            chaum_pedersen_proof,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ReconstructionDLEQProof<C: Curve> {
    pub commitment: C::Point,
    pub response: C::Scalar,
    pub nonce: C::Scalar,
}

impl<C: Curve> ReconstructionDLEQProof<C> {
    pub fn prove(
        points_in: &[C::Point],
        points_out: &[C::Point],
        a: C::Scalar,
        transcript: &mut impl CryptoTranscript,
    ) -> Result<Self, VerificationError>
    {
        if a == C::Scalar::zero() {
            return Err(VerificationError::InvalidDLEQProof);
        }
        let nonce = C::Scalar::random(&mut OsRng);
        transcript.append_scalar::<C>(b"recon_dleq_nonce", &nonce);
        for point in points_in {
            transcript.append_point::<C>(b"recon_dleq_point", point);
        }
        for point in points_out {
            transcript.append_point::<C>(b"recon_dleq_point", point);
        }
        let base_coefficient = transcript.challenge::<C>(b"recon_dleq_coefficient").scalar;

        let mut sum_point_total = C::Point::identity();
        let mut coefficient = base_coefficient;
        for point in points_in {
            sum_point_total = sum_point_total + *point * coefficient;
            coefficient = coefficient * base_coefficient;
        }

        if sum_point_total.is_identity() {
            return Err(VerificationError::InvalidDLEQProof);
        }

        let w = C::Scalar::random(&mut OsRng);
        let commitment = sum_point_total * w;
        transcript.append_point::<C>(b"recon_dleq_A", &commitment);
        let c = transcript.challenge::<C>(b"recon_dleq_challenge").scalar;
        let response = w + a * c;
        Ok(Self {
            commitment,
            response,
            nonce,
        })
    }

    pub fn verify(
        &self,
        points_in: &[C::Point],
        points_out: &[C::Point],
        transcript: &mut impl CryptoTranscript,
    ) -> Result<(), VerificationError>
    {
        if self.commitment.is_identity() {
            return Err(VerificationError::InvalidDLEQProof);
        }
        transcript.append_scalar::<C>(b"recon_dleq_nonce", &self.nonce);
        for point in points_in {
            transcript.append_point::<C>(b"recon_dleq_point", point);
        }
        for point in points_out {
            transcript.append_point::<C>(b"recon_dleq_point", point);
        }
        let base_coefficient = transcript.challenge::<C>(b"recon_dleq_coefficient").scalar;

        let mut sum_point_in_total = C::Point::identity();
        let mut sum_point_out_total = C::Point::identity();

        let mut coefficient = base_coefficient;
        for (point_in, point_out) in points_in.iter().zip(points_out) {
            sum_point_in_total = sum_point_in_total + *point_in * coefficient;
            sum_point_out_total = sum_point_out_total + *point_out * coefficient;
            coefficient = coefficient * base_coefficient;
        }
        transcript.append_point::<C>(b"recon_dleq_A", &self.commitment);
        let c = transcript.challenge::<C>(b"recon_dleq_challenge").scalar;
        let lhs1 = sum_point_in_total * self.response;
        let rhs1 = self.commitment + sum_point_out_total * c;
        if lhs1 == rhs1 {
            Ok(())
        } else {
            Err(VerificationError::InvalidDLEQProof)
        }
    }
}
