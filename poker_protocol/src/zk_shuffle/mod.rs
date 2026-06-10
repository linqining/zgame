pub mod shuffle_proof;
pub mod remask_proof;
pub mod reconstruction;
pub mod reveal_token_proof;
pub mod generalized_schnorr_proof;
pub mod error;
pub mod transcript_ext;

pub use shuffle_proof::*;
use crate::crypto::DefaultCurve;

/// Type alias for BLS12-381 shuffle proof (DefaultCurve).
pub type ShuffleProof = ZKShuffleProof<DefaultCurve>;
