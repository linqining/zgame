use crate::crypto::{
    ElGamalCiphertext, Plaintext, Scalar, EcPoint, PublicKey,
    BASE_G, N_CARDS, encrypt_batch, DefaultCurve,
};
use crate::z_poker::convert::{hex_to_scalar,scalar_to_hex, ecpoint_to_hex, hex_to_ecpoint};
use crate::zk_shuffle::reconstruction::{reconstruct_deck, ReconstructProof};
use crate::zk_shuffle::{ShuffleProof};

use crate::zk_shuffle::error::VerificationError;
use crate::zk_shuffle::remask_proof::{RemaskProof, remask_ciphertext};
use crate::crypto::curve::{Curve, CurveScalar, CurvePoint};
use super::card::{PlayingCard, standard_deck};
use super::key_manager::{KeyManager, PKOwnershipProof};
use rand_core::{OsRng, RngCore, CryptoRng};
use std::collections::HashMap;
use hex;
use crate::zk_shuffle::reveal_token_proof::{RevealTokenAndProof, ExpelHandState,RevealTokenProof};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GamePhase {
    Setup,
    Shuffling,
    Dealing,
    Playing,
    Reveal,
    Finished,
}

#[derive(Debug, Clone)]
pub struct GameConfig {
    pub num_players: usize,
    pub cards_per_player: usize,
    pub community_cards: usize,
}

impl Default for GameConfig {
    fn default() -> Self {
        Self {
            num_players: 9,
            cards_per_player: 2,
            community_cards: 5,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClientPlayer {
    pub sk: Scalar,
    pub pk: EcPoint,
}

impl ClientPlayer {
    pub fn new() -> Self {
        let sk = Scalar::random(&mut OsRng);
        let pk = *BASE_G * sk;
        Self {  sk, pk }
    }

    pub fn new_with_sk_hex(sk_hex: String) -> Result<Self, VerificationError> {
        let sk = hex_to_scalar(&sk_hex).map_err(|_| VerificationError::InvalidSecretKey)?;
        let pk = *BASE_G * &sk;
        Ok(Self {  sk, pk })
    }

    pub fn get_sk_and_pk_hex(&self) -> (String, String) {
        (scalar_to_hex(&self.sk), ecpoint_to_hex(&self.pk))
    }

    pub fn decrypt_card(&self, ct: &ElGamalCiphertext) -> Plaintext {
        ct.decrypt(&self.sk)
    }

    pub fn decrypt_playing_card(&self, ct: &ElGamalCiphertext, other_tokens :Vec<EcPoint>,deck_plaintext: Vec<Plaintext>) -> Option<PlayingCard> {
        let token = self.generate_reveal_token(ct);
        let other_tokens_sum = other_tokens.iter().sum::<EcPoint>();
        let plain_text = token.encrypted_card.c2 - token.reveal_token - other_tokens_sum;
        let index = deck_plaintext.iter().position(|p| p == &plain_text);
        if let Some(index) = index {
            return PlayingCard::from_index(index);
        }
        None
    }

    pub fn decrypt_readable_card(&self, ct: &ElGamalCiphertext,deck_plaintext: Vec<Plaintext>) -> Option<PlayingCard> {
        let token = self.generate_reveal_token(ct);
        let plain_text = token.encrypted_card.c2 - token.reveal_token;
        let index = deck_plaintext.iter().position(|p| p == &plain_text);
        if let Some(index) = index {
            return PlayingCard::from_index(index);
        }
        None
    }

    pub fn generate_pk_proof(&self) -> PKOwnershipProof {
        PKOwnershipProof::prove(&self.sk, &self.pk, &mut OsRng)
    }

    pub fn peek_own_card(&self, ct: &ElGamalCiphertext) -> Plaintext {
        ct.decrypt(&self.sk)
    }

    pub fn peek_card(&self, ct: &ElGamalCiphertext,tokens: &[RevealToken],plain_cards: &[Plaintext]) -> Result<(Plaintext,ElGamalCiphertext), VerificationError> {
        for token in tokens {
            token.proof.verify(&token.encrypted_card, &token.reveal_token, &token.user_public_key).map_err(|_| VerificationError::InvalidRevealToken)?;
        }
        let self_token = ct.gen_reveal_token(&self.sk);
        let other_tokens_sum = tokens.iter().map(|token| token.reveal_token).sum::<EcPoint>();

        let plain_text = ct.c2 - self_token - other_tokens_sum;
        if !plain_cards.contains(&plain_text) {
            return Err(VerificationError::InvalidPlaintext);
        }
        let mut user_readable_card = ct.clone();
        user_readable_card.c2 -= other_tokens_sum;
        Ok((plain_text,user_readable_card))
    }

    pub fn verify_and_reveal_from_token(token: &RevealToken) -> Result<Plaintext, VerificationError> {
        token.proof.verify(&token.encrypted_card, &token.reveal_token, &token.user_public_key)
            .map_err(|_| VerificationError::InvalidRevealToken)?;
        Ok(token.encrypted_card.c2 - token.reveal_token)
    }

    pub fn generate_reveal_token(&self, ct: &ElGamalCiphertext) -> RevealToken {
        let reveal_token = ct.gen_reveal_token(&self.sk);
        let proof = RevealTokenProof::<DefaultCurve>::prove(&self.sk, &self.pk, ct, &reveal_token, &mut OsRng);
        RevealToken {
            user_public_key: self.pk,
            encrypted_card: ct.clone(),
            proof,
            reveal_token,
        }
    }

    pub fn batch_generate_reveal_token(&self, cts: &[ElGamalCiphertext]) -> Vec<RevealToken> {
        let mut tokens = Vec::new();
        for ct in cts {
            tokens.push(self.generate_reveal_token(ct));
        }
        tokens
    }

    pub fn shuffle(&self, deck_encrypted: &[ElGamalCiphertext], agg_pk: &EcPoint) -> ShuffleRound {
        let mut transcript = merlin::Transcript::new(b"poker_protocol_player_shuffle");
        ShuffleRound::execute( deck_encrypted, agg_pk, &mut transcript, &mut OsRng)
    }

    // curr_share_pk: 当前分享的公钥,不包含自己
    pub fn join_game_and_shuffle(&self, input_cards: &[ElGamalCiphertext], curr_share_pk: &EcPoint) -> JoinGameAndShuffleRound {
        let share_pk = *curr_share_pk + self.pk;
        let pk_proof = self.generate_pk_proof();
        let mask_and_shuffle_round = MaskAndShuffleRound::execute(input_cards, &share_pk, self.sk.clone(), &self.pk, &mut OsRng);
        JoinGameAndShuffleRound{
            pk_hex: hex::encode(self.pk.compress().as_ref()),
            pk_ownership_proof: pk_proof,
            mask_and_shuffle_round,
        }
    }

    pub fn reveal_own_card(
        &self,
        hand_index: usize,
        hand_encrypted: &[ElGamalCiphertext],
        _deck_plaintext: &[Plaintext],
        _agg_pk: &EcPoint,
    ) -> Result<RevealToken, VerificationError> {
        if hand_index >= hand_encrypted.len() {
            return Err(VerificationError::LengthMismatch);
        }

        let encrypted_card = hand_encrypted[hand_index].clone();
        let reveal_token = encrypted_card.gen_reveal_token(&self.sk);
        let proof = RevealTokenProof::<DefaultCurve>::prove(&self.sk, &self.pk, &encrypted_card, &reveal_token, &mut OsRng);

        Ok(RevealToken {
            user_public_key: self.pk,
            encrypted_card,
            proof,
            reveal_token,
        })
    }

    pub fn reveal_community(
        &self,
        comm_plaintext: Plaintext,
    ) -> RevealToken {
        let ct_for_self = ElGamalCiphertext::encrypt(&comm_plaintext, &self.pk, &Scalar::random(&mut OsRng));
        let reveal_token = ct_for_self.gen_reveal_token(&self.sk);
        let proof = RevealTokenProof::<DefaultCurve>::prove(&self.sk, &self.pk, &ct_for_self, &reveal_token, &mut OsRng);

        RevealToken {
            user_public_key: self.pk,
            encrypted_card: ct_for_self,
            proof,
            reveal_token,
        }
    }

    pub fn remask_card(&self, ct: &ElGamalCiphertext, pk: &EcPoint) -> (ElGamalCiphertext, Scalar) {
        let alpha = Scalar::random(&mut OsRng);
        let remasked = ct.re_encrypt(pk, &alpha);
        (remasked, alpha)
    }

    pub fn distributed_decrypt(
        &self,
        ct: &ElGamalCiphertext,
        other_tokens: &[EcPoint],
    ) -> Plaintext {
        let self_token = ct.gen_reveal_token(&self.sk);
        let all_tokens_sum: EcPoint = other_tokens.iter().cloned().chain(std::iter::once(self_token)).sum();
        ct.c2 - all_tokens_sum
    }

    pub fn distributed_decrypt_from_tokens(
        ct: &ElGamalCiphertext,
        tokens: &[RevealToken],
    ) -> Result<Plaintext, VerificationError> {
        for token in tokens {
            token.proof.verify(&token.encrypted_card, &token.reveal_token, &token.user_public_key)
                .map_err(|_| VerificationError::InvalidRevealToken)?;
        }
        let tokens_sum: EcPoint = tokens.iter().map(|t| t.reveal_token).sum();
        Ok(ct.c2 - tokens_sum)
    }

    pub fn mask_card(&self, plaintext: &Plaintext, pk: &EcPoint) -> (ElGamalCiphertext, Scalar) {
        let r = Scalar::random(&mut OsRng);
        let encrypted = ElGamalCiphertext::encrypt(plaintext, pk, &r);
        (encrypted, r)
    }

    pub fn reconstruct(&self,origin_cards: &[Plaintext], user_readable_cards: &[ElGamalCiphertext], coefficient: &Scalar) ->  Result<ReconstructDeck, VerificationError>  {
        let (s_vec, output_cards, swap_out_cards) = reconstruct_deck(origin_cards, user_readable_cards, &self.sk, &self.pk, coefficient)?;
        let mut transcript = merlin::Transcript::new(b"zk_poker_reconstruct");
        let reconstruct_proof = ReconstructProof::<DefaultCurve>::prove(origin_cards.to_vec(), user_readable_cards.to_vec(), output_cards.clone(), swap_out_cards.clone(), &self.sk,&self.pk, s_vec, &mut transcript)?;
        Ok(ReconstructDeck {
            output_cards,
            swap_cards: swap_out_cards.into_iter().map(|(_, ct)| ct).collect(),
            proof: reconstruct_proof,
        })
    }
}

#[derive(Debug, Clone)]
pub struct RevealState {
    pub pending_players: Vec<PublicKey>, // 待亮牌的玩家
    pub reveal_tokens: Vec<RevealTokenSimple>, // 每个玩家的reveal_token
}

//todo user flod, add is_leave state
#[derive(Debug, Clone)]
pub struct PlayerState {
    pub pk_hex: String,
    pub pk: PublicKey,
    pub hand_encrypted: Vec<PlayerEncryptedCard>,
}


#[derive(Debug)]
pub struct ShuffleRound {
    pub input_cards: Vec<ElGamalCiphertext>,
    pub output_cards: Vec<ElGamalCiphertext>,
    pub proof: ShuffleProof,
}

impl ShuffleRound {
    pub fn execute(
        input_cards: &[ElGamalCiphertext],
        share_pk: &EcPoint,
        transcript: &mut merlin::Transcript,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Self {
        //todo 用户传入permute，核心是用户洗牌
        let  permute: [usize; N_CARDS] = {
            let mut arr: Vec<usize> = (0..N_CARDS).collect();
            use rand::seq::SliceRandom;
            arr.shuffle(rng);
            let mut fixed = [0usize; N_CARDS];
            fixed.copy_from_slice(&arr);
            fixed
        };

        let mut r_values = Vec::with_capacity(N_CARDS);
        let mut output = Vec::with_capacity(N_CARDS);

        for j in 0..N_CARDS {
            let r_j = Scalar::random(&mut *rng);
            r_values.push(r_j);
            let i = permute[j];
            output.push(input_cards[i].re_encrypt(share_pk, &r_j));
        }

        let proof = ShuffleProof::prove(
            input_cards, &output, &permute, &r_values, share_pk, &mut *rng, transcript,
        ).expect("shuffle prove failed: identity base point in input cards");

        ShuffleRound {
            input_cards: input_cards.to_vec(),
            output_cards: output,
            proof,
        }
    }

    pub fn verify(&self, share_pk: &EcPoint, transcript: &mut merlin::Transcript) -> bool {
        self.proof.verify(&self.input_cards, &self.output_cards, share_pk, transcript).is_ok()
    }
}

// 中途加入并洗牌的牌局
#[derive(Debug)]
pub struct JoinGameAndShuffleRound {
    pub pk_hex: String,
    pub pk_ownership_proof: PKOwnershipProof,
    pub mask_and_shuffle_round: MaskAndShuffleRound,
}

// 中途加入并洗牌的牌局
#[derive(Debug)]
pub struct MaskAndShuffleRound {
    pub mask_cards: Vec<ElGamalCiphertext>,
    pub output_cards: Vec<ElGamalCiphertext>,
    pub proof: ShuffleProof,
    pub remask_proof: RemaskProof<DefaultCurve>,
}

impl MaskAndShuffleRound {
    pub fn execute(
        input_cards: &[ElGamalCiphertext],
        share_pk: &EcPoint,
        player_sk: Scalar,
        player_pk: &EcPoint,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Self {
        use merlin::Transcript;

        // 创建共享 transcript，绑定 remask_proof 和 shuffle_proof
        let mut transcript = Transcript::new(b"poker_protocol_mask_shuffle");

        let mut mask_cards: Vec<ElGamalCiphertext> = vec![];
        for i in 0..input_cards.len() {
            let remask_card = remask_ciphertext(&input_cards[i], &player_sk, player_pk, rng)
                .expect("remask_ciphertext failed: c1 is identity (should not happen for valid encrypted cards)");
            mask_cards.push(remask_card);
        }
        let remask_proof = RemaskProof::<DefaultCurve>::prove(input_cards, &mask_cards, &player_sk, player_pk, &mut transcript);
        let shuffle_round = ShuffleRound::execute(&mask_cards, share_pk, &mut transcript, rng);
        Self {
            mask_cards,
            output_cards: shuffle_round.output_cards,
            proof: shuffle_round.proof,
            remask_proof,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PlayerEncryptedCard {
    pub card_index: u32,
    pub encrypted_card: ElGamalCiphertext,
    pub reveal_state: RevealState,
    pub playing_card: Option<PlayingCard>,
}

impl PlayerEncryptedCard {
    fn get_readable_card(&self,user_pk: PublicKey) -> Option<ElGamalCiphertext> {
        if self.reveal_state.pending_players.contains(&user_pk) && self.reveal_state.pending_players.len()==1{
            let sum_token: EcPoint = self.reveal_state.reveal_tokens.iter().map(|t| t.reveal_token).sum();
            let mut readable_card = self.encrypted_card.clone();
            readable_card.c2 -= sum_token;
            Some(readable_card)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone)]
pub struct DealResult {
    pub player_pk: String,
    pub encrypted_cards: Vec<ElGamalCiphertext>,
}

#[derive(Debug)]
pub struct RevealToken {
    pub encrypted_card: ElGamalCiphertext,
    pub proof: RevealTokenProof<DefaultCurve>,
    pub reveal_token: EcPoint,
    pub user_public_key: PublicKey,
}

#[derive(Debug)]
pub struct ReconstructDeck {
    pub output_cards: Vec<ElGamalCiphertext>,
    pub swap_cards: Vec<ElGamalCiphertext>,
    pub proof: ReconstructProof<DefaultCurve>,
}

#[derive(Debug, Clone)]
pub struct RevealTokenSimple {
    pub proof: RevealTokenProof<DefaultCurve>,
    pub reveal_token: EcPoint,
    pub user_public_key: PublicKey,
}

impl RevealToken {
    fn is_ok(&self) -> bool {
        self.proof.verify(&self.encrypted_card, &self.reveal_token, &self.user_public_key).is_ok()
    }
}

impl Clone for RevealToken {
    fn clone(&self) -> Self {
        RevealToken {
            user_public_key: self.user_public_key,
            encrypted_card: self.encrypted_card.clone(),
            proof: self.proof.clone(),
            reveal_token: self.reveal_token,
        }
    }
}

#[derive(Debug)]
pub struct ExpelRecord {
    pub expelled_player_pk: String,
    pub output_cards: Vec<ElGamalCiphertext>,
    pub expelled_card_positions: Vec<usize>,
    pub user_cards: Vec<ElGamalCiphertext>,
    pub agg_pk_at_proof_time: EcPoint,
    pub departed_player_pk: EcPoint,
}



#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpelSessionPhase {
    Initiated,
    Collecting,
    Finalized,
}

#[derive(Debug, Clone)]
pub struct ExpelSummary {
    pub expelled_player_pk: String,
    pub remaining_players: usize,
    pub proofs_accepted: usize,
    pub cards_redealt: usize,
    pub deck_size: usize,
    pub community_revealed: usize,
}

#[derive(Debug, Clone)]
pub struct ExpelStateResponse {
    pub expelled_players: Vec<String>,
    pub expel_records_count: usize,
    pub active_players: Vec<String>,
    pub can_continue: bool,
}
#[derive(Debug)]
pub struct MentalPokerGame {
    pub config: GameConfig,
    pub key_manager: KeyManager,
    pub players: HashMap<String, PlayerState>,
    pub deck_plaintext: Vec<Plaintext>,
    pub deck_encrypted: Vec<ElGamalCiphertext>,
    pub shuffle_rounds: Vec<ShuffleRound>,
    pub deal_results: Vec<DealResult>,
    pub community_cards_encrypted: Vec<PlayerEncryptedCard>,
    pub community_cards: Vec<Option<RevealToken>>,
    pub revealed_cards: HashMap<usize, Plaintext>,
    pub expelled_players: Vec<String>,
    pub expel_records: Vec<ExpelRecord>,
    pub entrusted_sk: HashMap<String, Scalar>,
}

/// Derive 52 deterministic, independent EcPoints as card plaintexts.
///
/// Uses hash-to-scalar approach: for each index i, hash a domain-separated
/// label to a scalar, then multiply by the generator. This ensures:
/// - Deterministic: all parties derive the same 52 points
/// - Independent: no subset of points has known DL relation to any other
/// - Non-identity: generator * non-zero scalar is never identity
fn new_plain_text() -> Vec<Plaintext> {
    let mut rng = rand::thread_rng();
    let mut random_bytes = [0u8; 32];
    rng.fill_bytes(&mut random_bytes);
    let random_bytes = hex::encode(random_bytes);
    let random_bytes = random_bytes.as_bytes();
    let random_bytes = random_bytes.to_vec();
    let random_bytes = random_bytes;
    (0..N_CARDS)
        .map(|i| {
            let label = format!("zgame/poker/{}/{}", String::from_utf8_lossy(&random_bytes), i);
            DefaultCurve::base_g() * DefaultCurve::hash_to_scalar(label.as_bytes())
        })
        .collect()
}

impl MentalPokerGame {
    pub fn new(config: GameConfig) -> Self {
        let n_community = config.community_cards;
        let deck_plaintext = new_plain_text();
        let initial_encrypt_deck = deck_plaintext
        .iter()
        .map(|c|{
            ElGamalCiphertext{
                c1: *BASE_G,
                c2: *c,
            }
        }).collect();
        Self {
            config,
            key_manager: KeyManager::new(),
            players: HashMap::new(),
            deck_plaintext: deck_plaintext,
            deck_encrypted: initial_encrypt_deck,
            shuffle_rounds: vec![],
            deal_results: vec![],
            community_cards_encrypted: vec![],
            community_cards: vec![None; n_community],
            revealed_cards: HashMap::new(),
            expelled_players: vec![],
            expel_records: vec![],
            entrusted_sk: HashMap::new(),
        }
    }

    pub fn reset(&mut self){
        let agg_pk = self.key_manager.get_aggregated_pk();
        let initial_encrypt_deck = self.deck_plaintext
        .iter()
        .map(|c|{
            ElGamalCiphertext{
                c1: *BASE_G,
                c2: *c+agg_pk,
            }
        }).collect();
        self.deck_encrypted = initial_encrypt_deck;
        self.shuffle_rounds.clear();
        self.deal_results.clear();
        self.community_cards_encrypted.clear();
        self.community_cards.clear();
        self.revealed_cards.clear();
        self.expelled_players.clear();
        self.expel_records.clear();
        self.entrusted_sk.clear();
        for (_,p) in self.players.iter_mut() {
            p.hand_encrypted.clear();
        }
    }

    pub fn register_player(&mut self, pk_hex: String, pk: EcPoint, proof: PKOwnershipProof) -> &PlayerState {
        self.key_manager.register_player( pk, proof)
            .expect("register should succeed");
        let state = PlayerState {
            pk_hex: pk_hex.clone(),
            pk,
            hand_encrypted: vec![],
        };
        let pk_hex_ref = pk_hex.clone();
        self.players.insert(pk_hex, state);
        self.players.get(&pk_hex_ref).unwrap()
    }

    pub fn list_unreveal_community_cards_encrypted(&self) -> Vec<PlayerEncryptedCard> {
        self.community_cards_encrypted.iter().filter(|c| !c.playing_card.is_some()).map(|c| c.clone()).collect()
    }

    pub fn list_revealed_cards(&self) -> (HashMap<String,Vec<PlayingCard>>, Vec<PlayingCard>) {
        let mut player_revealed_map = HashMap::new();
        let comm_revealed_cards = self.community_cards_encrypted.iter().filter(|c| c.playing_card.is_some()).map(|c| c.playing_card.unwrap()).collect();
        for (pk,p) in self.players.iter() {
            let revealed_cards = p.hand_encrypted.iter().filter(|c| c.playing_card.is_some()).map(|c| c.playing_card.unwrap()).collect();
            player_revealed_map.insert(pk.clone(), revealed_cards);
        }
        (player_revealed_map, comm_revealed_cards)
    }

    pub fn list_revealed_community_cards(&self) -> Vec<PlayingCard> {
        let comm_revealed_cards = self.community_cards_encrypted.iter().filter(|c| c.playing_card.is_some()).map(|c| c.playing_card.unwrap()).collect();
        comm_revealed_cards
    }

    pub fn leave_player(&mut self, player_pk: &str) -> Result<(), VerificationError> {
        if !self.players.contains_key(player_pk) {
            return Err(VerificationError::NoCardsReplaced);
        }
        if let Some(_p) = self.players.remove(player_pk) {
            self.deal_results.retain(|dr| dr.player_pk != player_pk);
            self.expelled_players.push(player_pk.to_string());
            self.key_manager.remove_player(player_pk.to_string());
        }
        Ok(())
    }

    pub fn encrypt_deck(&mut self) {
        let mut rng = OsRng;
        self.deck_encrypted = encrypt_batch(&self.deck_plaintext, &self.key_manager.get_aggregated_pk(), &mut rng);
    }

    pub fn submit_shuffle(&mut self, player_pk: &str, round: ShuffleRound) -> Result<(), VerificationError> {
        if !self.players.contains_key(player_pk) {
            return Err(VerificationError::PlayerNotFound);
        }

        let mut transcript = merlin::Transcript::new(b"poker_protocol_player_shuffle");
        if !round.verify(&self.key_manager.get_aggregated_pk(), &mut transcript) {
            return Err(VerificationError::InvalidDummyCount);
        }

        self.deck_encrypted = round.output_cards.clone();
        self.shuffle_rounds.push(round);
        Ok(())
    }

    pub fn deal_to_player(&mut self, player_pk: &str, n: usize) -> Result<(), VerificationError> {

        let pending_players: Vec<EcPoint> = self.players.values().map(|p| p.pk).collect::<Vec<_>>();

        let player = self.players.get_mut(player_pk)
            .ok_or(VerificationError::PlayerNotFound)?;

        let pk_hex = player.pk_hex.clone();
        let mut card_index = Self::get_current_deal_num(&self.deal_results, &self.community_cards_encrypted);
        if card_index + n > self.deck_encrypted.len() {
            return Err(VerificationError::TooManyCardsReplaced);
        }
        let mut player_encrypted_cards = Vec::with_capacity(n);
        let mut encrypted_cards = Vec::with_capacity(n);
        for _ in 0..n {
            player_encrypted_cards.push(PlayerEncryptedCard {
                card_index: card_index as u32,
                encrypted_card: self.deck_encrypted[card_index].clone(),
                reveal_state: RevealState {
                    pending_players: pending_players.clone(),
                    reveal_tokens: Vec::new(),
                },
                playing_card: None,
            });
            encrypted_cards.push(self.deck_encrypted[card_index].clone());
            card_index += 1;
        }
        player.hand_encrypted.extend(player_encrypted_cards);
        self.deal_results.push(DealResult {
            player_pk: pk_hex,
            encrypted_cards,
        });
        Ok(())
    }

    // 获取已发牌数量
    fn get_current_deal_num(deal_results: &[DealResult], community_cards_encrypted: &[PlayerEncryptedCard]) -> usize {
        let mut deal_idx = 0;
        for dr in deal_results {
            deal_idx += dr.encrypted_cards.len();
        }
        deal_idx += community_cards_encrypted.len();
        deal_idx
    }

    pub fn deal_community_cards_encrypted(&mut self, n:usize) -> Vec<ElGamalCiphertext> {
        let mut encrypted_cards = Vec::with_capacity(n);
        let pending_players = self.players.values().map(|p| p.pk.clone()).collect::<Vec<_>>();
        let deal_num = Self::get_current_deal_num(&self.deal_results, &self.community_cards_encrypted);
        for num in 0..n {
            let curr_idx = deal_num + num;
            let encrypt_card = self.deck_encrypted[curr_idx].clone();
            encrypted_cards.push(encrypt_card.clone());
            self.community_cards_encrypted.push(PlayerEncryptedCard {
                card_index:curr_idx as u32,
                encrypted_card: encrypt_card.clone(),
                reveal_state: RevealState {
                    pending_players: pending_players.clone(),
                    reveal_tokens: Vec::new(),
                },
                playing_card: None,
            });
        }
        encrypted_cards
    }

    pub fn get_hand_encrypted(&self, player_pk: &str) -> Option<&[PlayerEncryptedCard]> {
        self.players.get(player_pk).map(|p| p.hand_encrypted.as_slice())
    }
    pub fn get_hand_plaintext(&self, player_pk: &str) -> Result<Vec<PlayingCard>, VerificationError> {
        let player = self.players.get(player_pk)
            .ok_or(VerificationError::NoCardsReplaced)?;
        let plaintexts: Vec<Plaintext> = player.hand_encrypted.iter().filter(|card| card.reveal_state.pending_players.is_empty()).map(|card|
             {
                let mut reveal_tokens = EcPoint::identity();
                for token in &card.reveal_state.reveal_tokens{
                    reveal_tokens = reveal_tokens + token.reveal_token;
                }
                card.encrypted_card.c2 - reveal_tokens
             }
            ).collect();
        let mut ret = Vec::new();
        for plaintext in plaintexts{
            let playing_cards: Option<PlayingCard> = Self::plaintext_to_playingcard_static(&self.deck_plaintext, &plaintext);
            if let Some(card) = playing_cards{
                ret.push(card);
            }
        }
        Ok(ret)
    }


    pub fn aggregated_pk(&self) -> EcPoint {
        self.key_manager.get_aggregated_pk()
    }

    pub fn submit_reveal_token(
        &mut self,
        token: RevealToken,
        player_pk: &str,
    ) -> Result<(), VerificationError> {
        let valid = self.verify_reveal_token(&token, player_pk)?;
        if !valid{
            return Err(VerificationError::InvalidRevealToken);
        }
        let pk_point = hex_to_ecpoint(player_pk).unwrap();
        for (pk, state) in self.players.iter_mut(){
            for card in state.hand_encrypted.iter_mut(){
                if card.reveal_state.pending_players.is_empty(){
                    continue;
                }
                if card.encrypted_card == token.encrypted_card{
                    card.reveal_state.reveal_tokens.push(RevealTokenSimple {
                        proof: token.proof,
                        reveal_token: token.reveal_token,
                        user_public_key: token.proof.user_public_key,
                    });
                    card.reveal_state.pending_players.retain(|p| *p != token.proof.user_public_key);
                    if card.reveal_state.pending_players.is_empty(){
                        let plain_text = card.encrypted_card.c2 - card.reveal_state.reveal_tokens.iter().map(|t| t.reveal_token).sum::<EcPoint>();
                        let playing_card = Self::plaintext_to_playingcard_static(&self.deck_plaintext, &plain_text);
                        card.playing_card = playing_card;
                    }
                }
            }
        }
        for card in self.community_cards_encrypted.iter_mut(){
            if card.reveal_state.pending_players.is_empty(){
                continue;
            }
            let encrypt_card = card.encrypted_card.clone();
            if encrypt_card == token.encrypted_card{
                tracing::debug!("[submit_reveal_token]  match {} found", card.card_index);
                card.reveal_state.reveal_tokens.push(RevealTokenSimple {
                    proof: token.proof,
                    reveal_token: token.reveal_token,
                    user_public_key: token.proof.user_public_key,
                });
                card.reveal_state.pending_players.retain(|p| *p != pk_point);
                if card.reveal_state.pending_players.is_empty(){
                    let plain_text = card.encrypted_card.c2 - card.reveal_state.reveal_tokens.iter().map(|t| t.reveal_token).sum::<EcPoint>();
                    let playing_card = Self::plaintext_to_playingcard_static(&self.deck_plaintext, &plain_text);
                    card.playing_card = playing_card;
                }
            }
        }
        Ok(())
    }

    pub fn verify_reveal_token(
        &self,
        token: &RevealToken,
        player_pk: &str,
    ) -> Result<bool, VerificationError> {
        let player = self.players.get(player_pk)
            .ok_or(VerificationError::NoCardsReplaced)?;

        if token.proof.user_public_key != player.pk {
            return Ok(false);
        }

        token.proof.verify(
            &token.encrypted_card,
            &token.reveal_token,
            &token.user_public_key,
        ).map(|_| true).map_err(|_| VerificationError::InvalidDummyCount)
    }

    pub fn submit_community_reveal(
        &mut self,
        token: RevealToken,
        comm_index: usize,
        revealer_pk: &str,
    ) -> Result<(), VerificationError> {
        if comm_index >= self.config.community_cards {
            return Err(VerificationError::LengthMismatch);
        }
        let offset = self.config.num_players * self.config.cards_per_player;
        let deck_index = offset + comm_index;

        let _valid = self.verify_community_reveal(&token, revealer_pk)?;
        let revealed_plaintext = token.encrypted_card.c2 - token.reveal_token;
        self.community_cards[comm_index] = Some(token.clone());
        self.revealed_cards.insert(deck_index, revealed_plaintext);
        Ok(())
    }

    pub fn verify_community_reveal(
        &self,
        token: &RevealToken,
        revealer_pk: &str,
    ) -> Result<bool, VerificationError> {
        let revealer = self.players.get(revealer_pk)
            .ok_or(VerificationError::NoCardsReplaced)?;

        if token.proof.user_public_key != revealer.pk {
            return Ok(false);
        }

        token.proof.verify(
            &token.encrypted_card,
            &token.reveal_token,
            &token.user_public_key,
        ).map(|_| true).map_err(|_| VerificationError::InvalidDummyCount)
    }



    pub fn is_valid_deck_plaintext(&self, pt: &Plaintext) -> bool {
        self.deck_plaintext.iter().any(|dpt| dpt == pt)
    }

    pub fn redeal_to_player(
        &mut self,
        player_pk: &str,
        hand_index: usize,
        current_pt: Plaintext,
    ) -> Result<ElGamalCiphertext, VerificationError> {
        let player = self.players.get(player_pk)
            .ok_or(VerificationError::NoCardsReplaced)?;

        if hand_index >= player.hand_encrypted.len() {
            return Err(VerificationError::LengthMismatch);
        }

        if self.is_valid_deck_plaintext(&current_pt) {
            return Err(VerificationError::InvalidDummyCount);
        }
        // todo reconstruct deck后dealindex 需要重置
        let deal_num = Self::get_current_deal_num(&self.deal_results, &self.community_cards_encrypted);
        if deal_num >= self.deck_encrypted.len() {
            return Err(VerificationError::TooManyCardsReplaced);
        }

        let redeal_ct = self.deck_encrypted[deal_num].clone();

        // 维护 deal_num：记录新的发牌结果
        self.deal_results.push(DealResult {
            player_pk: player_pk.to_string(),
            encrypted_cards: vec![redeal_ct.clone()],
        });

        // 替换玩家手牌中失败的牌
        let pending_players: Vec<EcPoint> = self.players.values().map(|p| p.pk).collect();
        if let Some(player) = self.players.get_mut(player_pk) {
            player.hand_encrypted[hand_index] = PlayerEncryptedCard {
                card_index: deal_num as u32,
                encrypted_card: redeal_ct.clone(),
                reveal_state: RevealState {
                    pending_players,
                    reveal_tokens: Vec::new(),
                },
                playing_card: None,
            };
        }

        Ok(redeal_ct)
    }

    /// 重新发牌（不验证 plaintext），用于客户端报告解密失败的场景
    pub fn redeal_to_player_unchecked(
        &mut self,
        player_pk: &str,
        hand_index: usize,
    ) -> Result<ElGamalCiphertext, VerificationError> {
        let player = self.players.get(player_pk)
            .ok_or(VerificationError::PlayerNotFound)?;

        if hand_index >= player.hand_encrypted.len() {
            return Err(VerificationError::LengthMismatch);
        }

        let deal_num = Self::get_current_deal_num(&self.deal_results, &self.community_cards_encrypted);
        if deal_num >= self.deck_encrypted.len() {
            return Err(VerificationError::TooManyCardsReplaced);
        }

        let redeal_ct = self.deck_encrypted[deal_num].clone();

        // 维护 deal_num
        self.deal_results.push(DealResult {
            player_pk: player_pk.to_string(),
            encrypted_cards: vec![redeal_ct.clone()],
        });

        // 替换玩家手牌中失败的牌，重置 reveal_state
        let pending_players: Vec<EcPoint> = self.players.values().map(|p| p.pk).collect();
        if let Some(player) = self.players.get_mut(player_pk) {
            player.hand_encrypted[hand_index] = PlayerEncryptedCard {
                card_index: deal_num as u32,
                encrypted_card: redeal_ct.clone(),
                reveal_state: RevealState {
                    pending_players,
                    reveal_tokens: Vec::new(),
                },
                playing_card: None,
            };
        }

        Ok(redeal_ct)
    }

    fn plaintext_to_playingcard_static(deck_plaintext: &[Plaintext], pt: &Plaintext) -> Option<PlayingCard> {
        let position = deck_plaintext.iter().position(|dpt| dpt == pt);
        let standard_deck = standard_deck();
        if let Some(index) = position{
            return Some(standard_deck[index]);
        }
        None
    }

    pub fn get_game_state_summary(&self) -> String {
        format!(
            "MentalPokerGame( players={}, shuffles={}, dealt={}, community_revealed={}/{}, expelled={}, entrusted={})",
            self.players.len(),
            self.shuffle_rounds.len(),
            self.deal_results.len(),
            self.community_cards.iter().filter(|x| x.is_some()).count(),
            self.config.community_cards,
            self.expelled_players.len(),
            self.entrusted_sk.len(),
        )
    }

    pub fn entrust_player(&mut self, player_pk: &str, sk: &Scalar) -> Result<(), VerificationError> {
        let player = self.players.get(player_pk)
            .ok_or(VerificationError::NoCardsReplaced)?;

        let claimed_pk = *BASE_G * sk;
        if claimed_pk != player.pk {
            return Err(VerificationError::NoCardsReplaced);
        }

        self.entrusted_sk.insert(player_pk.to_string(), *sk);
        Ok(())
    }

    pub fn is_entrusted(&self, player_pk: &str) -> bool {
        self.entrusted_sk.contains_key(player_pk)
    }

    pub fn get_entrusted_sk(&self, player_pk: &str) -> Option<&Scalar> {
        self.entrusted_sk.get(player_pk)
    }

    // 只能给离开了游戏的玩家调用
    pub fn proxy_shuffle_for(&mut self, player_pk: &str) -> Result<(), VerificationError> {
        if !self.players.contains_key(player_pk) {
            return Err(VerificationError::NoCardsReplaced);
        }

        let agg_pk = self.key_manager.get_aggregated_pk();
        let mut rng = OsRng;
        let mut transcript = merlin::Transcript::new(b"poker_protocol_force_shuffle");

        let round = ShuffleRound::execute(&self.deck_encrypted, &agg_pk, &mut transcript, &mut rng);

        let mut transcript = merlin::Transcript::new(b"poker_protocol_force_shuffle");
        if !round.verify(&agg_pk, &mut transcript) {
            return Err(VerificationError::InvalidDummyCount);
        }

        self.deck_encrypted = round.output_cards.clone();
        self.shuffle_rounds.push(round);
        Ok(())
    }

    pub fn proxy_reveal_card_for(&mut self, player_pk: &str, card_index: usize) -> Result<RevealToken, VerificationError> {
        let sk = self.entrusted_sk.get(player_pk)
            .ok_or(VerificationError::NoCardsReplaced)?
            .clone();

        let player = self.players.get(player_pk)
            .ok_or(VerificationError::NoCardsReplaced)?;

        let hand = &player.hand_encrypted;
        if card_index >= hand.len() {
            return Err(VerificationError::LengthMismatch);
        }

        let player_card = hand[card_index].clone();
        let reveal_token = player_card.encrypted_card.gen_reveal_token(&sk);
        let proof = RevealTokenProof::<DefaultCurve>::prove(&sk, &player.pk, &player_card.encrypted_card, &reveal_token, &mut OsRng);

        Ok(RevealToken {
            user_public_key: player.pk,
            encrypted_card: player_card.encrypted_card,
            proof,
            reveal_token,
        })
    }

    pub fn proxy_reveal_community_for(&mut self, player_pk: &str, comm_plaintext: Plaintext) -> Result<RevealToken, VerificationError> {
        let sk = self.entrusted_sk.get(player_pk)
            .ok_or(VerificationError::NoCardsReplaced)?
            .clone();

        let player = self.players.get(player_pk)
            .ok_or(VerificationError::NoCardsReplaced)?;

        let ct_for_self = ElGamalCiphertext::encrypt(&comm_plaintext, &player.pk, &Scalar::random(&mut OsRng));
        let reveal_token = ct_for_self.gen_reveal_token(&sk);
        let proof = RevealTokenProof::<DefaultCurve>::prove(&sk, &player.pk, &ct_for_self, &reveal_token, &mut OsRng);

        Ok(RevealToken {
            user_public_key: player.pk,
            encrypted_card: ct_for_self,
            proof,
            reveal_token,
        })
    }


    pub fn revoke_entrustment(&mut self, player_pk: &str) -> bool {
        self.entrusted_sk.remove(player_pk).is_some()
    }

    pub fn expel_phase_name(phase: &Option<ExpelSessionPhase>) -> &'static str {
        match phase {
            None => "None",
            Some(ExpelSessionPhase::Initiated) => "Initiated",
            Some(ExpelSessionPhase::Collecting) => "Collecting",
            Some(ExpelSessionPhase::Finalized) => "Finalized",
        }
    }
}

impl MentalPokerGame {

    pub fn init_expel_deck(&mut self) -> Vec<ElGamalCiphertext> {
        let mut init_deck_cpy: Vec<ElGamalCiphertext> = vec![ElGamalCiphertext::new_placeholder_card(); N_CARDS];
        let agg_pk = self.aggregated_pk();
        let mut rng = OsRng;
        init_deck_cpy.iter_mut().map(|x| x.re_encrypt(&agg_pk, &Scalar::random(&mut rng))).collect::<Vec<_>>()
    }


    pub fn finalize_expel_session(&mut self, target_player_pk: &str) -> Result<ExpelSummary, VerificationError> {
        if !self.expelled_players.contains(&target_player_pk.to_string()) {
            return Err(VerificationError::NoCardsReplaced);
        }

        let active_player_pks: Vec<String> = self.players.keys()
            .filter(|pk| *pk != target_player_pk && !self.expelled_players.contains(*pk))
            .cloned()
            .collect();

        let mut redealt_count = 0usize;
        for player_pk in &active_player_pks {
            if let Some(hand_data) = self.get_hand_encrypted(player_pk) {
                let hand_vec = hand_data.to_vec();
                for idx in 0..hand_vec.len() {
                    let pt = match self.peek_card_after_expel(player_pk, idx) {
                        Ok(pt) => pt,
                        Err(_) => continue,
                    };
                    if !self.is_valid_deck_plaintext(&pt) {
                        if self.redeal_to_player(player_pk, idx, pt).is_ok() {
                            redealt_count += 1;
                        }
                    }
                }
            }
        }

        let summary = ExpelSummary {
            expelled_player_pk: target_player_pk.to_string(),
            remaining_players: active_player_pks.len(),
            proofs_accepted: self.expel_records.iter()
                .filter(|r| r.expelled_player_pk == *target_player_pk)
                .count(),
            cards_redealt: redealt_count,
            deck_size: self.deck_encrypted.len(),
            community_revealed: self.community_cards.iter().filter(|x| x.is_some()).count(),
        };

        Ok(summary)
    }

    pub fn peek_card_after_expel(&self, player_pk: &str, card_index: usize) -> Result<Plaintext, VerificationError> {
        let hand = self.get_hand_encrypted(player_pk)
            .ok_or(VerificationError::NoCardsReplaced)?;
        if card_index >= hand.len() {
            return Err(VerificationError::LengthMismatch);
        }
        let ct = &hand[card_index];
        let player = self.players.get(player_pk)
            .ok_or(VerificationError::NoCardsReplaced)?;
        let active_sk_entries: Vec<Scalar> = self.players.values()
            .filter_map(|p| {
                if p.pk_hex == *player_pk { return None; }
                if self.expelled_players.contains(&p.pk_hex) { return None; }
                self.entrusted_sk.get(&p.pk_hex).cloned()
            })
            .collect();

        let mut token_sum = EcPoint::identity();

        for sk in &active_sk_entries {
            let token = ct.encrypted_card.gen_reveal_token(sk);
            token_sum = token_sum + token;
        }

        Ok(ct.encrypted_card.c2 - token_sum)
    }

    pub fn get_expel_state(&self) -> ExpelStateResponse {
        ExpelStateResponse {
            expelled_players: self.expelled_players.clone(),
            expel_records_count: self.expel_records.len(),
            active_players: self.players.keys().cloned().collect(),
            can_continue: self.players.len() > self.expelled_players.len() && self.expelled_players.len() > 0,
        }
    }

    pub fn is_player_active(&self, player_pk: &str) -> bool {
        self.players.contains_key(player_pk) && !self.expelled_players.contains(&player_pk.to_string())
    }

    pub fn force_expel_player(&mut self, target_player_pk: &str) -> Result<ExpelSummary, VerificationError> {
        let hand = self.get_hand_encrypted(target_player_pk)
            .ok_or(VerificationError::NoCardsReplaced)?
            .to_vec();

        if hand.is_empty() {
            return Err(VerificationError::NoCardsReplaced);
        }

        let player = self.players.get(target_player_pk)
            .ok_or(VerificationError::NoCardsReplaced)?;

        let player_pk_val = player.pk;

        let agg_pk = self.key_manager.get_aggregated_pk();
        let mut expelled_positions: Vec<usize> = Vec::new();
        let mut expelled_plaintexts: Vec<Plaintext> = Vec::new();

        for ct in &hand {
            let mut token_sum = EcPoint::identity();
            for (_pk, sk_entry) in &self.entrusted_sk {
                let token = ct.encrypted_card.gen_reveal_token(sk_entry);
                token_sum = token_sum + token;
            }
            let decrypted = ct.encrypted_card.c2 - token_sum;

            if let Some(pos) = self.deck_plaintext.iter().position(|pt| *pt == decrypted) {
                expelled_positions.push(pos);
                expelled_plaintexts.push(decrypted);
            }
        }

        if expelled_positions.is_empty() {
            return Err(VerificationError::NoCardsReplaced);
        }

        let all_r_new: Vec<Scalar> = (0..N_CARDS).map(|_| Scalar::random(&mut OsRng)).collect();
        let placeholder = ElGamalCiphertext::new_placeholder_card();
        let output_cards: Vec<ElGamalCiphertext> = self.deck_plaintext.iter().enumerate().map(|(i, _pt)| {
            if expelled_positions.contains(&i) {
                placeholder.re_encrypt(&agg_pk, &all_r_new[i])
            } else {
                ElGamalCiphertext::encrypt(&self.deck_plaintext[i], &agg_pk, &all_r_new[i])
            }
        }).collect();

        self.deck_encrypted = output_cards.clone();
        self.expelled_players.push(target_player_pk.to_string());
        self.key_manager.remove_player(target_player_pk.to_string());

        if let Some(p) = self.players.get_mut(target_player_pk) {
            p.hand_encrypted.clear();
        }

        self.deal_results.retain(|dr| dr.player_pk != target_player_pk);

        let active_player_pks: Vec<String> = self.players.keys()
            .filter(|pk| *pk != target_player_pk && !self.expelled_players.contains(*pk))
            .cloned()
            .collect();

        let mut redealt_count = 0usize;
        for player_pk in &active_player_pks {
            if let Some(hand_data) = self.get_hand_encrypted(player_pk) {
                let hand_vec = hand_data.to_vec();
                for idx in 0..hand_vec.len() {
                    let pt = match self.peek_card_after_expel(&player_pk, idx) {
                        Ok(pt) => pt,
                        Err(_) => continue,
                    };
                    if !self.is_valid_deck_plaintext(&pt) {
                        if self.redeal_to_player(&player_pk, idx, pt).is_ok() {
                            redealt_count += 1;
                        }
                    }
                }
            }
        }

        let summary = ExpelSummary {
            expelled_player_pk: target_player_pk.to_string(),
            remaining_players: active_player_pks.len(),
            proofs_accepted: 1,
            cards_redealt: redealt_count,
            deck_size: self.deck_encrypted.len(),
            community_revealed: self.community_cards.iter().filter(|x| x.is_some()).count(),
        };

        Ok(summary)
    }

    pub fn verify_all_pk_proofs(&self) -> bool {
        self.key_manager.verify_all_proofs()
    }

    pub fn get_all_reveal_tokens_for_card(
        &self,
        card_ct: &ElGamalCiphertext,
    ) -> Vec<RevealToken> {
        self.players.keys()
            .filter_map(|pk| {
                if self.entrusted_sk.contains_key(pk) {
                    let sk = &self.entrusted_sk[pk];
                    let pk_val = &self.players[pk].pk;
                    let reveal_token = card_ct.gen_reveal_token(sk);
                    let proof = RevealTokenProof::<DefaultCurve>::prove(sk, pk_val, card_ct, &reveal_token, &mut OsRng);
                    Some(RevealToken {
                        user_public_key: *pk_val,
                        encrypted_card: card_ct.clone(), proof, reveal_token })
                } else {
                    None
                }
            })
            .collect()
    }

    // 用户可解出的tokan
    pub fn get_player_readable_tokens(
        &self,
    ) -> HashMap<String, Vec<ElGamalCiphertext>> {
        let mut player_map = HashMap::new();
        for (player_pk,player) in  self.players.clone() {
            let mut player_readable_cards = Vec::with_capacity(player.hand_encrypted.len());
            for ct in &player.hand_encrypted {
                if let Some(readable_card) = ct.get_readable_card(player.pk.clone()) {
                    player_readable_cards.push(readable_card);
                }
            }
            player_map.insert(player_pk.clone(), player_readable_cards);
        }
        player_map
    }

    pub fn unmask_card(
        &self,
        card_ct: &ElGamalCiphertext,
        tokens: &[RevealToken],
    ) -> Result<Plaintext, VerificationError> {
        ClientPlayer::distributed_decrypt_from_tokens(card_ct, tokens)
    }

    pub fn compute_aggregate_key_from_pks(pks: &[EcPoint]) -> EcPoint {
        pks.iter().fold(EcPoint::identity(), |agg, pk| agg + pk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::BASE_G;

    fn create_test_player() -> ClientPlayer {
        ClientPlayer::new()
    }

    fn create_test_expel_hand_state(
        player: &ClientPlayer,
        agg_pk: &EcPoint,
        card_indices: &[usize],
    ) -> Vec<ExpelHandState<DefaultCurve>> {
        card_indices.iter().map(|&idx| {
            let pt = new_plain_text()[idx];
            let r = Scalar::random(&mut OsRng);
            let encrypted_card = ElGamalCiphertext::encrypt(&pt, agg_pk, &r);

            let reveal_token = encrypted_card.gen_reveal_token(&player.sk);
            let proof = RevealTokenProof::<DefaultCurve>::prove(&player.sk, &player.pk, &encrypted_card, &reveal_token, &mut OsRng);

            let token_and_proof = RevealTokenAndProof::<DefaultCurve> {
                reveal_token,
                proof,
            };

            ExpelHandState::<DefaultCurve> {
                hand_encrypted: encrypted_card,
                reveal_tokens: vec![token_and_proof],
            }
        }).collect()
    }

    #[test]
    fn test_reveal_token_generation_and_verification() {
        let player = create_test_player();
        let agg_pk = player.pk;

        let pt = new_plain_text()[0];
        let r = Scalar::random(&mut OsRng);
        let encrypted_card = ElGamalCiphertext::encrypt(&pt, &agg_pk, &r);

        let reveal_token = encrypted_card.gen_reveal_token(&player.sk);
        let proof = RevealTokenProof::<DefaultCurve>::prove(&player.sk, &player.pk, &encrypted_card, &reveal_token, &mut OsRng);

        let verify_result = proof.verify(&encrypted_card, &reveal_token, &player.pk);
        assert!(verify_result.is_ok(), "Proof should verify: {:?}", verify_result);

        let decrypted = encrypted_card.c2 - reveal_token;
        assert_eq!(decrypted, pt, "Should decrypt to original plaintext");
    }

    // ========== ShuffleRound tests ==========

    /// Helper: 生成 N_CARDS 张加密牌（无 placeholder）
    fn make_full_encrypted_cards(pk: &EcPoint) -> Vec<ElGamalCiphertext> {
        new_plain_text().iter()
            .map(|pt| ElGamalCiphertext::encrypt(pt, pk, &Scalar::random(&mut OsRng)))
            .collect()
    }

    /// Helper: 比较两个 EcPoint 集合是否包含相同的点（不考虑顺序）
    fn assert_same_point_set(a: &[EcPoint], b: &[EcPoint]) {
        let mut a_compressed: Vec<_> = a.iter().map(|p| p.compress().as_ref().to_vec()).collect();
        let mut b_compressed: Vec<_> = b.iter().map(|p| p.compress().as_ref().to_vec()).collect();
        a_compressed.sort();
        b_compressed.sort();
        assert_eq!(a_compressed, b_compressed);
    }

    #[test]
    fn test_shuffle_round_execute_and_verify() {
        let sk = Scalar::random(&mut OsRng);
        let pk = *BASE_G * sk;
        let input = make_full_encrypted_cards(&pk);

        let mut transcript = merlin::Transcript::new(b"test_shuffle_round");
        let round = ShuffleRound::execute(&input, &pk, &mut transcript, &mut OsRng);

        // verify 应通过
        let mut transcript = merlin::Transcript::new(b"test_shuffle_round");
        assert!(round.verify(&pk, &mut transcript), "honest shuffle round should verify");

        // output 牌数应等于 input
        assert_eq!(round.output_cards.len(), N_CARDS);
        assert_eq!(round.input_cards.len(), N_CARDS);

        // output 应是 input 的重加密+排列，解密后明文集合应相同
        let input_pts: Vec<EcPoint> = input.iter().map(|ct| ct.decrypt(&sk)).collect();
        let output_pts: Vec<EcPoint> = round.output_cards.iter().map(|ct| ct.decrypt(&sk)).collect();
        assert_same_point_set(&input_pts, &output_pts);
    }

    #[test]
    fn test_shuffle_round_wrong_pk_fails() {
        let sk = Scalar::random(&mut OsRng);
        let pk = *BASE_G * sk;
        let input = make_full_encrypted_cards(&pk);

        let mut transcript = merlin::Transcript::new(b"test_shuffle_round_wrong_pk");
        let round = ShuffleRound::execute(&input, &pk, &mut transcript, &mut OsRng);

        let wrong_sk = Scalar::random(&mut OsRng);
        let wrong_pk = *BASE_G * wrong_sk;
        let mut transcript = merlin::Transcript::new(b"test_shuffle_round_wrong_pk");
        assert!(!round.verify(&wrong_pk, &mut transcript), "verify with wrong pk should fail");
    }

    #[test]
    fn test_shuffle_round_tampered_output_fails() {
        let sk = Scalar::random(&mut OsRng);
        let pk = *BASE_G * sk;
        let input = make_full_encrypted_cards(&pk);

        let mut transcript = merlin::Transcript::new(b"test_shuffle_round_tampered");
        let mut round = ShuffleRound::execute(&input, &pk, &mut transcript, &mut OsRng);

        // 篡改 output[0]
        round.output_cards[0] = round.output_cards[0].re_encrypt(&pk, &Scalar::random(&mut OsRng));
        let mut transcript = merlin::Transcript::new(b"test_shuffle_round_tampered");
        assert!(!round.verify(&pk, &mut transcript), "tampered output should fail verify");
    }

    #[test]
    fn test_shuffle_round_tampered_input_fails() {
        let sk = Scalar::random(&mut OsRng);
        let pk = *BASE_G * sk;
        let input = make_full_encrypted_cards(&pk);

        let mut transcript = merlin::Transcript::new(b"test_shuffle_round_tampered_input");
        let round = ShuffleRound::execute(&input, &pk, &mut transcript, &mut OsRng);

        // 篡改 input[1]
        let mut tampered_input = input.clone();
        tampered_input[1] = ElGamalCiphertext::encrypt(
            &(*BASE_G * Scalar::from_u64(99u64)), &pk, &Scalar::random(&mut OsRng),
        );
        let tampered_round = ShuffleRound {
            input_cards: tampered_input,
            output_cards: round.output_cards.clone(),
            proof: round.proof,
        };
        let mut transcript = merlin::Transcript::new(b"test_shuffle_round_tampered_input");
        assert!(!tampered_round.verify(&pk, &mut transcript), "tampered input should fail verify");
    }

    #[test]
    fn test_shuffle_round_deterministic_permutation() {
        // 多次 execute 应产生不同排列（概率极高）
        let sk = Scalar::random(&mut OsRng);
        let pk = *BASE_G * sk;
        let input = make_full_encrypted_cards(&pk);

        let mut transcript1 = merlin::Transcript::new(b"test_shuffle_round_det1");
        let round1 = ShuffleRound::execute(&input, &pk, &mut transcript1, &mut OsRng);
        let mut transcript2 = merlin::Transcript::new(b"test_shuffle_round_det2");
        let round2 = ShuffleRound::execute(&input, &pk, &mut transcript2, &mut OsRng);

        // 两次 output 的 c1 不应完全相同（随机排列+随机重加密）
        let same = round1.output_cards.iter().zip(round2.output_cards.iter())
            .all(|(a, b)| a.c1 == b.c1);
        assert!(!same, "two shuffles should produce different outputs with overwhelming probability");
    }

    #[test]
    fn test_mask_and_shuffle_round_execute_and_verify() {
        let player_sk = Scalar::random(&mut OsRng);
        let player_pk = *BASE_G * player_sk;
        let agg_sk = Scalar::random(&mut OsRng);
        let agg_pk = *BASE_G * agg_sk;
        let share_pk = agg_pk + player_pk;

        let input = make_full_encrypted_cards(&share_pk);
        let round = MaskAndShuffleRound::execute(&input, &share_pk, player_sk, &player_pk, &mut OsRng);

        // 验证时需要按与 prove 相同的顺序重建 transcript 状态：
        // 1. 先验证 remask_proof（吸收 remask 数据到 transcript）
        // 2. 再验证 shuffle_proof（在 remask 数据之后继续吸收 shuffle 数据）

        // remask proof 应通过
        let mut transcript = merlin::Transcript::new(b"poker_protocol_mask_shuffle");
        assert!(round.remask_proof.verify(&input, &round.mask_cards, &player_pk, &mut transcript),
            "remask proof should verify");

        // shuffle proof 应通过（使用同一个 transcript，状态已包含 remask 数据）
        assert!(round.proof.verify(
            &round.mask_cards,
            &round.output_cards,
            &share_pk,
            &mut transcript,
        ).is_ok(), "shuffle proof should verify");

        // output 牌数应等于 input
        assert_eq!(round.output_cards.len(), N_CARDS);
        assert_eq!(round.mask_cards.len(), N_CARDS);
    }

    #[test]
    fn test_new_plain_text(){
        let plain_text = new_plain_text();
        println!("{:?}", plain_text);
    }

}
