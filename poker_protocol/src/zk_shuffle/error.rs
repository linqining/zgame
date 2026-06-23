
#[derive(Debug, Clone, PartialEq)]
pub enum VerificationError {
    InvalidProofAtPosition(usize),
    LengthMismatch,
    PlayerNotFound,
    TooManyCardsReplaced,
    InvalidC2Consistency,
    InvalidPlaintext,
    InvalidSecretKey,
    ReplayDetected,
    InvalidRevealToken,
    InvalidDLEQProof,
    IdentityBasePoint,
    InvalidOperation,
    InvalidCiphertext,
    InvalidCoefficient,
    InvalidInput,
    /// General entry not found error
    EntryNotFound,
    /// Proof verification failed
    ProofVerificationFailed,
    /// Invalid public key format (e.g., malformed hex)
    InvalidPublicKey,
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerificationError::InvalidProofAtPosition(pos) => write!(f, "Invalid proof at position {}", pos),
            VerificationError::LengthMismatch => write!(f, "Length mismatch"),
            VerificationError::PlayerNotFound => write!(f, "Player not found"),
            VerificationError::TooManyCardsReplaced => write!(f, "Too many cards replaced"),
            VerificationError::InvalidC2Consistency => write!(f, "Invalid c2 consistency"),
            VerificationError::InvalidPlaintext => write!(f, "Invalid plaintext"),
            VerificationError::InvalidSecretKey => write!(f, "Invalid secret key"),
            VerificationError::ReplayDetected => write!(f, "Replay detected"),
            VerificationError::InvalidRevealToken => write!(f, "Invalid reveal token"),
            VerificationError::InvalidDLEQProof => write!(f, "Invalid DLEQ proof"),
            VerificationError::IdentityBasePoint => write!(f, "Identity base point"),
            VerificationError::InvalidOperation => write!(f, "Invalid operation"),
            VerificationError::InvalidCiphertext => write!(f, "Invalid ciphertext"),
            VerificationError::InvalidCoefficient => write!(f, "Invalid coefficient"),
            VerificationError::InvalidInput => write!(f, "Invalid input"),
            VerificationError::EntryNotFound => write!(f, "Entry not found"),
            VerificationError::ProofVerificationFailed => write!(f, "Proof verification failed"),
            VerificationError::InvalidPublicKey => write!(f, "Invalid public key"),
        }
    }
}

impl std::error::Error for VerificationError {}
