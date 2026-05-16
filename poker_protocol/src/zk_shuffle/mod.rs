pub mod shuffle_proof;
pub mod remask_proof;

pub use shuffle_proof::*;
pub type ConsistencyProof = ZKConsistencyProof;
pub type ShuffleProof = ZKShuffleProofV3;
