use crate::crypto::{EcPoint, Scalar, BASE_G};
use sha2::{Sha256, Digest};
use rand_core::RngCore;
use ff::{Field, PrimeField};
use group::{Group, GroupEncoding};
use std::collections::HashMap;
use hex;

fn pk_to_hex(pk: &EcPoint) -> String {
    hex::encode(pk.to_affine().to_bytes())
}

#[derive(Debug, Clone)]
pub struct PKOwnershipProof {
    pub commitment: EcPoint,
    pub response: Scalar,
}

impl PKOwnershipProof {
    pub fn prove(sk: &Scalar, pk: &EcPoint, rng: &mut impl RngCore) -> Self {
        let w = Scalar::random(rng);
        let commitment = *BASE_G * w;

        let mut hasher = Sha256::new();
        hasher.update(BASE_G.to_affine().to_bytes());
        hasher.update(pk.to_affine().to_bytes());
        hasher.update(commitment.to_affine().to_bytes());
        let challenge_bytes = hasher.finalize();
        let mut challenge_arr = [0u8; 32];
        challenge_arr.copy_from_slice(&challenge_bytes[..32]);
        let challenge = Option::<Scalar>::from(Scalar::from_repr(challenge_arr.into()))
            .unwrap_or(Scalar::ZERO);

        let response = w + challenge * sk;

        PKOwnershipProof { commitment, response }
    }

    pub fn verify(&self, pk: &EcPoint) -> bool {
        if bool::from(self.commitment.is_identity()) {
            return false;
        }

        let mut hasher = Sha256::new();
        hasher.update(BASE_G.to_affine().to_bytes());
        hasher.update(pk.to_affine().to_bytes());
        hasher.update(self.commitment.to_affine().to_bytes());
        let challenge_bytes = hasher.finalize();
        let mut challenge_arr = [0u8; 32];
        challenge_arr.copy_from_slice(&challenge_bytes[..32]);
        let challenge = Option::<Scalar>::from(Scalar::from_repr(challenge_arr.into()))
            .unwrap_or(Scalar::ZERO);

        let lhs = *BASE_G * &self.response;
        let rhs = self.commitment + pk * &challenge;

        lhs == rhs
    }
}

#[derive(Debug, Clone)]
pub struct PlayerKeyEntry {
    pub pk: EcPoint,
    pub proof: PKOwnershipProof,
}

#[derive(Debug)]
pub struct KeyManager {
    entries: HashMap<String, PlayerKeyEntry>,
    aggregated_pk: EcPoint,
}

impl KeyManager {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            aggregated_pk: EcPoint::IDENTITY,
        }
    }

    pub fn register_player(
        &mut self,
        pk: EcPoint,
        proof: PKOwnershipProof,
    ) -> Result<(), &'static str> {
        if self.entries.contains_key(&pk_to_hex(&pk)) {
            return Err("Player already registered");
        }

        if !proof.verify(&pk) {
            return Err("PK ownership proof verification failed");
        }

        let entry = PlayerKeyEntry {
            pk,
            proof,
        };

        self.aggregated_pk = self.aggregated_pk + entry.pk;
        self.entries.insert(pk_to_hex(&pk), entry);

        Ok(())
    }

    pub fn leave_player(
        &mut self,
        pk: EcPoint,
        sk: &Scalar,
    ) -> Result<EcPoint, &'static str> {
        let entry = self.entries.get(&pk_to_hex(&pk))
            .ok_or("Player not found")?;

        let claimed_pk = *BASE_G * sk;
        if claimed_pk != entry.pk {
            return Err("Secret key does not match registered public key");
        }

        let pk = entry.pk;
        self.aggregated_pk = self.aggregated_pk - pk;
        self.entries.remove(&pk_to_hex(&pk));

        Ok(pk)
    }

    pub fn remove_player(&mut self, player_pk: String) -> Option<PlayerKeyEntry> {
        if let Some(entry) = self.entries.remove(&player_pk) {
            self.aggregated_pk = self.aggregated_pk - entry.pk;
            Some(entry)
        } else {
            None
        }
    }

    pub fn verify_all_proofs(&self) -> bool {
        self.entries.values().all(|e| e.proof.verify(&e.pk))
    }

    pub fn get_aggregated_pk(&self) -> EcPoint {
        self.aggregated_pk
    }



    pub fn get_player_pks(&self) -> Vec<String> {
        self.entries.keys().cloned().collect()
    }

    pub fn player_count(&self) -> usize {
        self.entries.len()
    }

    pub fn contains_player(&self, player_pk: String) -> bool {
        self.entries.contains_key(&player_pk)
    }

    pub fn iter_entries(&self) -> impl Iterator<Item = &PlayerKeyEntry> {
        self.entries.values()
    }

    pub fn verify_pk_proof_for_player(&self, player_pk: String) -> bool {
        self.entries.get(&player_pk)
            .map(|e| e.proof.verify(&e.pk))
            .unwrap_or(false)
    }

    pub fn compute_aggregate_from_pks(pks: &[EcPoint]) -> EcPoint {
        pks.iter().fold(EcPoint::IDENTITY, |agg, pk| agg + pk)
    }
}

impl Default for KeyManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_pk_ownership_proof() {
        let sk = Scalar::random(&mut OsRng);
        let pk = *BASE_G * &sk;

        let proof = PKOwnershipProof::prove(&sk, &pk, &mut OsRng);
        assert!(proof.verify(&pk), "Valid proof should verify");

        let wrong_pk = *BASE_G * &Scalar::random(&mut OsRng);
        assert!(!proof.verify(&wrong_pk), "Wrong pk should fail verification");
    }

    #[test]
    fn test_register_with_pk_and_proof() {
        let mut km = KeyManager::new();

        let sk0 = Scalar::random(&mut OsRng);
        let pk0 = *BASE_G * &sk0;
        let proof0 = PKOwnershipProof::prove(&sk0, &pk0, &mut OsRng);

        km.register_player(pk0, proof0).expect("Register P0 should succeed");

        let sk1 = Scalar::random(&mut OsRng);
        let pk1 = *BASE_G * &sk1;
        let proof1 = PKOwnershipProof::prove(&sk1, &pk1, &mut OsRng);

        km.register_player(pk1, proof1).expect("Register P1 should succeed");

        assert_eq!(km.player_count(), 2);
        assert_eq!(km.get_aggregated_pk(), pk0 + pk1);
        assert!(km.verify_all_proofs());
    }

    #[test]
    fn test_register_rejects_invalid_proof() {
        let mut km = KeyManager::new();

        let sk = Scalar::random(&mut OsRng);
        let pk = *BASE_G * &sk;
        let wrong_sk = Scalar::random(&mut OsRng);
        let wrong_pk = *BASE_G * &wrong_sk;
        let bad_proof = PKOwnershipProof::prove(&wrong_sk, &wrong_pk, &mut OsRng);

        let result = km.register_player(pk, bad_proof);
        assert!(result.is_err(), "Should reject proof for wrong pk");
    }

    #[test]
    fn test_leave_player_with_correct_sk() {
        let mut km = KeyManager::new();

        let sk0 = Scalar::random(&mut OsRng);
        let pk0 = *BASE_G * &sk0;
        let proof0 = PKOwnershipProof::prove(&sk0, &pk0, &mut OsRng);
        km.register_player(pk0, proof0).unwrap();

        let sk1 = Scalar::random(&mut OsRng);
        let pk1 = *BASE_G * &sk1;
        let proof1 = PKOwnershipProof::prove(&sk1, &pk1, &mut OsRng);
        km.register_player(pk1, proof1).unwrap();

        assert_eq!(km.get_aggregated_pk(), pk0 + pk1);

        let removed_pk = km.leave_player(pk0, &sk0).unwrap();
        assert_eq!(removed_pk, pk0);
        assert_eq!(km.player_count(), 1);
        assert_eq!(km.get_aggregated_pk(), pk1);
        assert!(!km.contains_player(pk_to_hex(&pk0)));
    }

    #[test]
    fn test_leave_player_rejects_wrong_sk() {
        let mut km = KeyManager::new();

        let sk = Scalar::random(&mut OsRng);
        let pk = *BASE_G * &sk;
        let proof = PKOwnershipProof::prove(&sk, &pk, &mut OsRng);
        km.register_player(pk, proof).unwrap();

        let wrong_sk = Scalar::random(&mut OsRng);
        let result = km.leave_player(pk, &wrong_sk);
        assert!(result.is_err(), "Wrong sk should be rejected on leave");
        assert!(km.contains_player(pk_to_hex(&pk)), "Player should still exist after failed leave");
    }

    #[test]
    fn test_remove_player_force_without_sk() {
        let mut km = KeyManager::new();

        let sk = Scalar::random(&mut OsRng);
        let pk = *BASE_G * &sk;
        let proof = PKOwnershipProof::prove(&sk, &pk, &mut OsRng);
        km.register_player(pk, proof).unwrap();

        let entry = km.remove_player(pk_to_hex(&pk));
        assert!(entry.is_some());
        assert!(!km.contains_player(pk_to_hex(&pk)));
        assert_eq!(km.get_aggregated_pk(), EcPoint::IDENTITY);
    }

    #[test]
    fn test_duplicate_register_fails() {
        let mut km = KeyManager::new();

        let sk = Scalar::random(&mut OsRng);
        let pk = *BASE_G * &sk;
        let proof = PKOwnershipProof::prove(&sk, &pk, &mut OsRng);

        km.register_player(pk.clone(), proof.clone()).unwrap();
        let result = km.register_player(pk, proof);
        assert!(result.is_err(), "Duplicate registration should fail");
    }

    #[test]
    fn test_empty_aggregate_is_identity() {
        let km = KeyManager::new();
        assert_eq!(km.get_aggregated_pk(), EcPoint::IDENTITY);
        assert_eq!(km.player_count(), 0);
    }

    #[test]
    fn test_register_then_leave_reregister() {
        let mut km = KeyManager::new();

        let sk = Scalar::random(&mut OsRng);
        let pk = *BASE_G * &sk;
        let proof = PKOwnershipProof::prove(&sk, &pk, &mut OsRng);

        km.register_player(pk.clone(), proof).unwrap();
        km.leave_player(pk, &sk).unwrap();

        let new_sk = Scalar::random(&mut OsRng);
        let new_pk = *BASE_G * &new_sk;
        let new_proof = PKOwnershipProof::prove(&new_sk, &new_pk, &mut OsRng);
        km.register_player(new_pk, new_proof).expect("Re-register after leave should succeed");
        assert_eq!(km.player_count(), 1);
    }
}
