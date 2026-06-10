use merlin::Transcript;
use crate::crypto::curve::{Curve, CurvePoint, CurveScalar};

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

impl<C: Curve> TranscriptExtension<C> for Transcript {
    fn append_point(&mut self, label: &'static [u8], point: &C::Point) {
        self.append_message(label, point.compress().as_ref());
    }

    fn append_scalar(&mut self, label: &'static [u8], scalar: &C::Scalar) {
        self.append_message(label, &scalar.as_bytes());
    }

    fn challenge(&mut self, label: &'static [u8]) -> Challenge<C> {
        let mut buf = [0u8; 64];
        self.challenge_bytes(label, &mut buf);
        let scalar = C::Scalar::from_bytes_mod_order(&buf);
        Challenge { scalar }
    }
}
