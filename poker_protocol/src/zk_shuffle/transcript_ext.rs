use merlin::Transcript;
use crate::crypto::curve::Curve;

/// Challenge scalar extracted from a transcript, generic over the curve.
#[derive(Debug, Clone)]
pub struct Challenge<C: Curve> {
    pub scalar: C::Scalar,
}

/// Extension trait for merlin::Transcript to support curve-generic point/scalar operations.
pub trait TranscriptExtension<C: Curve> {
    /// Append a curve point to the transcript.
    fn append_point(&mut self, label: &'static [u8], point: &C::Point);

    /// Append a scalar to the transcript.
    fn append_scalar(&mut self, label: &'static [u8], scalar: &C::Scalar);

    /// Get a challenge scalar from the transcript.
    fn challenge(&mut self, label: &'static [u8]) -> Challenge<C>;
}

impl TranscriptExtension<crate::crypto::curve::RistrettoCurve> for Transcript {
    fn append_point(&mut self, label: &'static [u8], point: &curve25519_dalek::ristretto::RistrettoPoint) {
        self.append_message(label, point.compress().as_bytes());
    }

    fn append_scalar(&mut self, label: &'static [u8], scalar: &curve25519_dalek::scalar::Scalar) {
        self.append_message(label, scalar.as_bytes());
    }

    fn challenge(&mut self, label: &'static [u8]) -> Challenge<crate::crypto::curve::RistrettoCurve> {
        let mut buf = [0u8; 64];
        self.challenge_bytes(label, &mut buf);
        let scalar = curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(&buf);
        Challenge { scalar }
    }
}
