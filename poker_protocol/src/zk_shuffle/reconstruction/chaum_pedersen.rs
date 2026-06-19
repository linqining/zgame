use crate::zk_shuffle::transcript_ext::CryptoTranscript;
use rand_core::OsRng;
use crate::crypto::curve::{Curve, CurvePoint, CurveScalar};
pub use crate::zk_shuffle::error::VerificationError;

/// Chaum-Pedersen DLEQ proof for proving that two points have the same discrete logarithm
/// with respect to two different base points.
/// Proves: P1 = s*G1 and P2 = s*G2 for the same secret s
#[derive(Debug, Clone)]
pub struct ChaumPedersenDLEQProof<C: Curve> {
    /// Commitment A = w*G1
    pub commitment_a: C::Point,
    /// Commitment B = w*G2
    pub commitment_b: C::Point,
    /// Response s = w + c*x (where x is the secret discrete log)
    pub response: C::Scalar,
}
impl<C: Curve> ChaumPedersenDLEQProof<C> {
    /// Prove that P1 = s*G1 and P2 = s*G2 for the same secret s
    ///
    /// # Arguments
    /// * `G1` - First base point
    /// * `G2` - Second base point
    /// * `s` - Secret scalar (the discrete logarithm)
    /// * `P1` - First point (should equal s*G1)
    /// * `P2` - Second point (should equal s*G2)
    /// * `transcript` - Merlin transcript for Fiat-Shamir
    pub fn prove(
        G1: C::Point,
        G2: C::Point,
        s: C::Scalar,
        P1: C::Point,
        P2: C::Point,
        transcript: &mut impl CryptoTranscript,
    ) -> Result<Self, VerificationError>
    {
        // SECURITY: Reject identity base points to prevent trivial attacks
        if G1.is_identity() || G2.is_identity() {
            return Err(VerificationError::IdentityBasePoint);
        }

        // 兼容 Move 合约 chaum_pedersen::verify 的 M5 修复：
        // 拒绝恒等元公钥点 P1/P2——若 P1=P2=identity，x=0 即可使等式平凡成立
        if P1.is_identity() || P2.is_identity() {
            return Err(VerificationError::IdentityBasePoint);
        }

        // 兼容 Move 合约 chaum_pedersen::prove/verify 的 transcript 标签：
        // Move 使用 cp_G1/cp_G2/cp_P1/cp_P2，Rust 须保持一致。
        // Append public values to transcript
        transcript.append_point::<C>(b"cp_G1", &G1);
        transcript.append_point::<C>(b"cp_G2", &G2);
        transcript.append_point::<C>(b"cp_P1", &P1);
        transcript.append_point::<C>(b"cp_P2", &P2);

        // Generate random nonce w
        let w = C::Scalar::random(&mut OsRng);

        // Compute commitments: A = w*G1, B = w*G2
        let commitment_a = G1 * w;
        let commitment_b = G2 * w;

        // 兼容 Move 合约 M-P17 修复：校验承诺点非 identity——identity 承诺削弱证明安全性
        if commitment_a.is_identity() || commitment_b.is_identity() {
            return Err(VerificationError::InvalidDLEQProof);
        }

        // Append commitments to transcript
        transcript.append_point::<C>(b"cp_commitment_a", &commitment_a);
        transcript.append_point::<C>(b"cp_commitment_b", &commitment_b);

        // Get challenge scalar from transcript
        let c = transcript.challenge::<C>(b"cp_challenge").scalar;

        // Compute response: s = w + c*x
        let response = w + s * c;

        Ok(Self {
            commitment_a,
            commitment_b,
            response,
        })
    }

    /// Verify the Chaum-Pedersen DLEQ proof
    ///
    /// # Arguments
    /// * `G1` - First base point
    /// * `G2` - Second base point
    /// * `P1` - First point (claimed to be s*G1)
    /// * `P2` - Second point (claimed to be s*G2)
    /// * `transcript` - Merlin transcript for Fiat-Shamir
    pub fn verify(
        &self,
        G1: C::Point,
        G2: C::Point,
        P1: C::Point,
        P2: C::Point,
        transcript: &mut impl CryptoTranscript,
    ) -> Result<(), VerificationError>
    {
        // SECURITY: Reject identity base points to prevent trivial attacks
        if G1.is_identity() || G2.is_identity() {
            return Err(VerificationError::IdentityBasePoint);
        }

        // 兼容 Move 合约 chaum_pedersen::verify 的 M5 修复：
        // 拒绝恒等元公钥点 P1/P2——若 P1=P2=identity，x=0 即可使等式平凡成立
        if P1.is_identity() || P2.is_identity() {
            return Err(VerificationError::IdentityBasePoint);
        }

        // 兼容 Move 合约 M-P17 修复：校验承诺点非 identity——identity 承诺削弱证明安全性
        if self.commitment_a.is_identity() || self.commitment_b.is_identity() {
            return Err(VerificationError::InvalidDLEQProof);
        }

        // 兼容 Move 合约 chaum_pedersen::verify 的 transcript 标签：
        // Move 使用 cp_G1/cp_G2/cp_P1/cp_P2，Rust 须保持一致。
        // Append public values to transcript
        transcript.append_point::<C>(b"cp_G1", &G1);
        transcript.append_point::<C>(b"cp_G2", &G2);
        transcript.append_point::<C>(b"cp_P1", &P1);
        transcript.append_point::<C>(b"cp_P2", &P2);

        // Append commitments to transcript
        transcript.append_point::<C>(b"cp_commitment_a", &self.commitment_a);
        transcript.append_point::<C>(b"cp_commitment_b", &self.commitment_b);

        // Get challenge scalar from transcript
        let c = transcript.challenge::<C>(b"cp_challenge").scalar;

        // Verify: s*G1 = A + c*P1
        let lhs1 = G1 * self.response;
        let rhs1 = self.commitment_a + P1 * c;

        // Verify: s*G2 = B + c*P2
        let lhs2 = G2 * self.response;
        let rhs2 = self.commitment_b + P2 * c;

        if lhs1 == rhs1 && lhs2 == rhs2 {
            Ok(())
        } else {
            Err(VerificationError::InvalidDLEQProof)
        }
    }
}
