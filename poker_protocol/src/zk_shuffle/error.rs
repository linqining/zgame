

#[derive(Debug, Clone, PartialEq)]
pub enum VerificationError {
    InvalidProofAtPosition(usize),
    LengthMismatch,
    NoCardsReplaced,
    PlayerNotFound,
    TooManyCardsReplaced,
    InvalidC2Consistency,
    InvalidPlaintext,
    InvalidDummyCount,
    InvalidSecretKey,
    ReplayDetected,
    InvalidRevealToken,
    InvalidDLEQProof,
    IdentityBasePoint,
    InvalidOperation,
}
