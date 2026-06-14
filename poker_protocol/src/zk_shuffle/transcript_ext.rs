use crate::crypto::curve::{Curve, CurvePoint, CurveScalar};
use sha3::Digest;

// ========== CryptoTranscript trait ==========

/// Trait abstracting the Fiat-Shamir transcript operations.
///
/// Two implementations are provided:
/// - `MerlinTranscript`: wraps `merlin::Transcript` (STROBE-based, used off-chain)
/// - `FiatShamirTranscript`: SHA3-256 based (matches the Move contract implementation)
///
/// Use `MerlinTranscript` for off-chain verification, and `FiatShamirTranscript`
/// when the proof needs to be verified on-chain by the Move contract.
pub trait CryptoTranscript {
    /// Create a new transcript with the given protocol name.
    fn new(protocol_name: &'static [u8]) -> Self;

    /// Append a message to the transcript with a label.
    fn append_message(&mut self, label: &'static [u8], message: &[u8]);

    /// Fill the buffer with challenge bytes.
    fn challenge_bytes(&mut self, label: &'static [u8], dest: &mut [u8]);

    /// Append a curve point to the transcript.
    fn append_point<C: Curve>(&mut self, label: &'static [u8], point: &C::Point);

    /// Append a scalar to the transcript.
    fn append_scalar<C: Curve>(&mut self, label: &'static [u8], scalar: &C::Scalar);

    /// Generate a challenge scalar from the transcript.
    fn challenge<C: Curve>(&mut self, label: &'static [u8]) -> Challenge<C>;
}

/// Challenge scalar extracted from a transcript, generic over the curve.
#[derive(Debug, Clone)]
pub struct Challenge<C: Curve> {
    pub scalar: C::Scalar,
}

// ========== MerlinTranscript (wraps merlin::Transcript) ==========

/// Wrapper around `merlin::Transcript` implementing `CryptoTranscript`.
pub struct MerlinTranscript {
    inner: merlin::Transcript,
}

impl std::fmt::Debug for MerlinTranscript {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MerlinTranscript").finish_non_exhaustive()
    }
}

impl CryptoTranscript for MerlinTranscript {
    fn new(protocol_name: &'static [u8]) -> Self {
        MerlinTranscript {
            inner: merlin::Transcript::new(protocol_name),
        }
    }

    fn append_message(&mut self, label: &'static [u8], message: &[u8]) {
        self.inner.append_message(label, message);
    }

    fn challenge_bytes(&mut self, label: &'static [u8], dest: &mut [u8]) {
        self.inner.challenge_bytes(label, dest);
    }

    fn append_point<C: Curve>(&mut self, label: &'static [u8], point: &C::Point) {
        self.inner.append_message(label, point.compress().as_ref());
    }

    fn append_scalar<C: Curve>(&mut self, label: &'static [u8], scalar: &C::Scalar) {
        self.inner.append_message(label, &scalar.as_bytes());
    }

    fn challenge<C: Curve>(&mut self, label: &'static [u8]) -> Challenge<C> {
        let mut buf = [0u8; 64];
        self.inner.challenge_bytes(label, &mut buf);
        let scalar = C::Scalar::from_bytes_mod_order_wide(&buf);
        Challenge { scalar }
    }
}

// ========== FiatShamirTranscript (SHA3-256, matches Move contract) ==========

/// Fiat-Shamir Transcript using SHA3-256, matching the Move contract implementation.
///
/// The state is `SHA3-256(current_state || label || message)`.
/// This is compatible with the `bls_transcript.move` on-chain implementation.
#[derive(Debug)]
pub struct FiatShamirTranscript {
    state: Vec<u8>,
}

impl CryptoTranscript for FiatShamirTranscript {
    fn new(protocol_name: &'static [u8]) -> Self {
        let state = sha3::Sha3_256::digest(protocol_name).to_vec();
        FiatShamirTranscript { state }
    }

    fn append_message(&mut self, label: &'static [u8], message: &[u8]) {
        let mut data = self.state.clone();
        data.extend_from_slice(label);
        data.extend_from_slice(message);
        self.state = sha3::Sha3_256::digest(&data).to_vec();
    }

    fn challenge_bytes(&mut self, label: &'static [u8], dest: &mut [u8]) {
        // Append "challenge" label then hash state to scalar
        self.append_message(label, b"challenge");
        let hash = sha3::Sha3_256::digest(&self.state);
        let copy_len = dest.len().min(hash.len());
        dest[..copy_len].copy_from_slice(&hash[..copy_len]);
    }

    fn append_point<C: Curve>(&mut self, label: &'static [u8], point: &C::Point) {
        let point_bytes = point.compress();
        self.append_message(label, point_bytes.as_ref());
    }

    fn append_scalar<C: Curve>(&mut self, label: &'static [u8], scalar: &C::Scalar) {
        self.append_message(label, &scalar.as_bytes());
    }

    fn challenge<C: Curve>(&mut self, label: &'static [u8]) -> Challenge<C> {
        // Matches Move contract: append "challenge" message, then hash_to_scalar
        self.append_message(label, b"challenge");
        let scalar = C::hash_to_scalar(&self.state);
        Challenge { scalar }
    }
}
