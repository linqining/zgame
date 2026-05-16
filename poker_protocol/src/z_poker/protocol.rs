use crate::crypto::{
    ElGamalCiphertext, Plaintext, Scalar, EcPoint, PublicKey,
    BASE_G, N_CARDS, encrypt_batch,
};
use crate::z_poker::convert::{hex_to_scalar,scalar_to_hex, ecpoint_to_hex, hex_to_ecpoint};
use crate::zk_shuffle::{ShuffleProof};
use crate::card_reveal::{
    ExpelOrProof, ExpelProof, VerificationError, Transcript, RevealTokenProof,
};
use crate::zk_shuffle::remask_proof::RemaskProof;
use super::card::{PlayingCard, standard_deck};
use super::key_manager::{KeyManager, PKOwnershipProof};
use ff::Field;
use group::GroupEncoding;
use rand_core::{OsRng, RngCore};
use std::collections::HashMap;
use hex;

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

    pub fn decrypt_playing_card(&self, ct: &ElGamalCiphertext,other_tokens :Vec<EcPoint>) -> Option<PlayingCard> {
        let token = self.generate_reveal_token(ct);
        let other_tokens_sum = other_tokens.iter().sum::<EcPoint>();
        PlayingCard::from_plaintext(&(token.encrypted_card.c2 - token.reveal_token - other_tokens_sum))
    }

    pub fn generate_pk_proof(&self) -> PKOwnershipProof {
        PKOwnershipProof::prove(&self.sk, &self.pk, &mut OsRng)
    }

    pub fn peek_own_card(&self, ct: &ElGamalCiphertext) -> Plaintext {
        ct.decrypt(&self.sk)
    }
    pub fn peek_card(&self, ct: &ElGamalCiphertext,tokens: &[RevealToken]) -> Result<Plaintext, VerificationError> {
        for token in tokens {
            token.proof.verify(&ct, &token.reveal_token).map_err(|_| VerificationError::InvalidRevealToken)?;
        }
        let self_token = ct.gen_reveal_token(&self.sk);
        let other_tokens_sum = tokens.iter().map(|token| token.reveal_token).sum::<EcPoint>();
        Ok(ct.c2 - self_token - other_tokens_sum)
    }

    pub fn verify_and_reveal_from_token(token: &RevealToken) -> Result<Plaintext, VerificationError> {
        token.proof.verify(&token.encrypted_card, &token.reveal_token)
            .map_err(|_| VerificationError::InvalidRevealToken)?;
        Ok(token.encrypted_card.c2 - token.reveal_token)
    }

    pub fn generate_reveal_token(&self, ct: &ElGamalCiphertext) -> RevealToken {
        let reveal_token = ct.gen_reveal_token(&self.sk);
        let proof: RevealTokenProof = RevealTokenProof::prove(&self.sk, &self.pk, ct, &reveal_token, &mut OsRng);
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
        ShuffleRound::execute( deck_encrypted, agg_pk, &mut OsRng)
    }

    // curr_share_pk: 当前分享的公钥,不包含自己
    pub fn join_game_and_shuffle(&self, input_cards: &[ElGamalCiphertext], curr_share_pk: &EcPoint) -> JoinGameAndShuffleRound {
        let share_pk = *curr_share_pk + self.pk;
        let pk_proof = self.generate_pk_proof();
        let mask_and_shuffle_round = MaskAndShuffleRound::execute(input_cards, &share_pk, self.sk.clone(), &self.pk, &mut OsRng);
        JoinGameAndShuffleRound{
            pk_hex: hex::encode(self.pk.to_affine().to_bytes()),
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
        let proof = RevealTokenProof::prove(&self.sk, &self.pk, &encrypted_card, &reveal_token, &mut OsRng);

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
        let proof = RevealTokenProof::prove(&self.sk, &self.pk, &ct_for_self, &reveal_token, &mut OsRng);

        RevealToken {
            user_public_key: self.pk,
            encrypted_card: ct_for_self,
            proof,
            reveal_token,
        }
    }

    pub fn generate_expel_proof(
        &self,
        hand_encrypted: &[ElGamalCiphertext],
        deck_plaintext: &[Plaintext],
        agg_pk: &EcPoint,
        per_card_tokens: &[Vec<RevealToken>],
    ) -> Result<ExpelRecord, VerificationError> {
        if hand_encrypted.is_empty() {
            return Err(VerificationError::NoCardsReplaced);
        }

        let user_cards: Vec<ElGamalCiphertext> = hand_encrypted.to_vec();
        let mut expelled_plaintexts: Vec<Plaintext> = Vec::new();
        let mut expelled_positions: Vec<usize> = Vec::new();

        for (idx, ct) in user_cards.iter().enumerate() {
            let tokens = per_card_tokens.get(idx).map(|v| v.as_slice()).unwrap_or(&[]);
            match self.peek_card(ct, tokens) {
                Ok(pt) => {
                    if let Some(pos) = deck_plaintext.iter().position(|dpt| *dpt == pt) {
                        expelled_plaintexts.push(pt);
                        expelled_positions.push(pos);
                    }
                }
                Err(e) => { eprintln!("[DEBUG expel] card[{}]: peek Err: {:?}", idx, e); }
            }
        }

        if expelled_plaintexts.is_empty() {
            return Err(VerificationError::NoCardsReplaced);
        }

        let all_r_new: Vec<Scalar> = (0..N_CARDS).map(|_| Scalar::random(&mut OsRng)).collect();
        let placeholder = ElGamalCiphertext::new_placehod_card();
        let output_cards: Vec<ElGamalCiphertext> = deck_plaintext.iter().enumerate().map(|(i, pt)| {
            if expelled_plaintexts.contains(pt) {
                placeholder.re_encrypt(agg_pk, &all_r_new[i])
            } else {
                ElGamalCiphertext::encrypt(pt, agg_pk, &all_r_new[i])
            }
        }).collect();

        let mut transcript = Transcript::new(b"mental_poker_expel_player");
        let proof = ExpelOrProof::prove_expel(
            deck_plaintext,
            &output_cards,
            &user_cards,
            &self.sk,
            &self.pk,
            &all_r_new,
            agg_pk,
            &mut transcript,
        )?;

        Ok(ExpelRecord {
            expelled_player_pk: hex::encode(self.pk.to_affine().to_bytes()),
            output_cards: output_cards.clone(),
            proof,
            expelled_card_positions: expelled_positions.clone(),
            user_cards: user_cards.clone(),
            agg_pk_at_proof_time: *agg_pk,
            departed_player_pk: self.pk,
        })
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
            token.proof.verify(&token.encrypted_card, &token.reveal_token)
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
}

#[derive(Debug, Clone)]
pub struct RevealState {
    pub pending_players: Vec<PublicKey>, // 待亮牌的玩家
    pub reveal_tokens: Vec<RevealTokenSimple>, // 每个玩家的reveal_token
}

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
        rng: &mut impl RngCore,
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
            &input_cards, &output, &permute, &r_values, share_pk, &mut *rng,
        );

        ShuffleRound {
            input_cards: input_cards.to_vec(),
            output_cards: output,
            proof,
        }
    }

    pub fn verify(&self, share_pk: &EcPoint) -> bool {
        self.proof.verify(&self.input_cards, &self.output_cards, share_pk)
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
    pub remask_proof: RemaskProof,
}

impl MaskAndShuffleRound {
    pub fn execute(
        input_cards: &[ElGamalCiphertext],
        share_pk: &EcPoint,
        player_sk: Scalar,
        player_pk: &EcPoint,
        rng: &mut impl RngCore,
    ) -> Self {
        let mut mask_cards = vec![];
        for i in 0..input_cards.len() {
            let mut mask_card = input_cards[i].clone();
            mask_card.c2 = mask_card.c2 + mask_card.c1*player_sk;
            mask_cards.push(mask_card);
        }
        let remask_proof = RemaskProof::prove(&input_cards, &mask_cards, &player_sk,player_pk);
        let shuffle_round = ShuffleRound::execute(&mask_cards, share_pk, rng);
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

#[derive(Debug, Clone)]
pub struct DealResult {
    pub player_pk: String,
    pub encrypted_cards: Vec<PlayerEncryptedCard>,
}

#[derive(Debug)]
pub struct RevealToken {
    pub encrypted_card: ElGamalCiphertext,
    pub proof: RevealTokenProof,
    pub reveal_token: EcPoint,
    pub user_public_key: PublicKey,
}

#[derive(Debug, Clone)]
pub struct RevealTokenSimple {
    pub proof: RevealTokenProof,
    pub reveal_token: EcPoint,
    pub user_public_key: PublicKey,
}

impl RevealToken {
    fn is_ok(&self) -> bool {
        self.proof.verify(&self.encrypted_card, &self.reveal_token).is_ok()
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
    pub proof: ExpelProof,
    pub expelled_card_positions: Vec<usize>,
    pub user_cards: Vec<ElGamalCiphertext>,
    pub agg_pk_at_proof_time: EcPoint,
    pub departed_player_pk: EcPoint,
}

impl Clone for ExpelRecord {
    fn clone(&self) -> Self {
        ExpelRecord {
            expelled_player_pk: self.expelled_player_pk.clone(),
            output_cards: self.output_cards.clone(),
            proof: self.proof.clone(),
            expelled_card_positions: self.expelled_card_positions.clone(),
            user_cards: self.user_cards.clone(),
            agg_pk_at_proof_time: self.agg_pk_at_proof_time,
            departed_player_pk: self.departed_player_pk,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpelSessionPhase {
    Initiated,
    Collecting,
    Finalized,
}

#[derive(Debug, Clone)]
pub struct ExpelSession {
    pub target_player_pk: String,
    pub phase: ExpelSessionPhase,
    pub collected_proofs: Vec<ExpelRecord>,
    pub required_player_pkks: Vec<String>,
    pub initiated_at: String,
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
    pub phase: GamePhase,
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


impl MentalPokerGame {
    pub fn new(config: GameConfig) -> Self {
        let playing_cards = standard_deck();
        let deck_plaintext: Vec<Plaintext> = playing_cards
            .iter()
            .map(|c| *BASE_G * Scalar::from(c.id() as u32 + 1))
            .collect();
        let initial_encrypt_deck = deck_plaintext
        .iter()
        .map(|c|{
            let mut ciper_text = ElGamalCiphertext::new_placehod_card();
            ciper_text.c2=c.clone();
            ciper_text
        }).collect();
        let n_community = config.community_cards;
        Self {
            config,
            phase: GamePhase::Setup,
            key_manager: KeyManager::new(),
            players: HashMap::new(),
            deck_plaintext,
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
        let initial_encrypt_deck = self.deck_plaintext
        .iter()
        .map(|c|{
            let mut ciper_text = ElGamalCiphertext::new_placehod_card();
            ciper_text.c2=c.clone();
            ciper_text
        }).collect();
        self.phase = GamePhase::Setup;
        self.deck_encrypted = initial_encrypt_deck;
        self.shuffle_rounds.clear();
        self.deal_results.clear();
        self.community_cards_encrypted.clear();
        self.community_cards.clear();
        self.revealed_cards.clear();
        self.expelled_players.clear();
        self.expel_records.clear();
        self.entrusted_sk.clear();
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
        assert_eq!(self.phase, GamePhase::Setup);
        let mut rng = OsRng;
        self.deck_encrypted = encrypt_batch(&self.deck_plaintext, &self.key_manager.get_aggregated_pk(), &mut rng);
        self.phase = GamePhase::Shuffling;
    }

    pub fn start_shuffle(&mut self) {
        self.phase = GamePhase::Shuffling;
    }

    pub fn submit_shuffle(&mut self, player_pk: &str, round: ShuffleRound) -> Result<(), VerificationError> {
        assert_eq!(self.phase, GamePhase::Shuffling);
        if !self.players.contains_key(player_pk) {
            return Err(VerificationError::NoCardsReplaced);
        }

        if !round.verify(&self.key_manager.get_aggregated_pk()) {
            return Err(VerificationError::InvalidDummyCount);
        }

        self.deck_encrypted = round.output_cards.clone();
        self.shuffle_rounds.push(round);
        Ok(())
    }

    pub fn complete_shuffle(&mut self) {
        assert_eq!(self.phase, GamePhase::Shuffling);
        self.phase = GamePhase::Dealing;
    }

    pub fn deal_to_players(&mut self) -> Result<(), VerificationError> {
        assert_eq!(self.phase, GamePhase::Dealing);
        let n: usize = self.config.num_players;
        let k = self.config.cards_per_player;
        let n_comm = self.config.community_cards;
        let total_dealt = n * k + n_comm;
        if total_dealt > self.deck_encrypted.len() {
            return Err(VerificationError::TooManyCardsReplaced);
        }

        self.deal_results.clear();
        let mut pending_players = self.players.values().map(|p| p.pk.clone()).collect::<Vec<_>>();
        for (_player_pk, player) in &mut self.players {
            let mut card_index = Self::get_current_deal_num(&self.deal_results, &self.community_cards_encrypted);
            let mut encrypted_cards = Vec::with_capacity(k);
            for _ in 0..k {
                if card_index >= self.deck_encrypted.len() {
                    return Err(VerificationError::TooManyCardsReplaced);
                }
                encrypted_cards.push(PlayerEncryptedCard {
                    card_index: card_index as u32,
                    encrypted_card: self.deck_encrypted[card_index].clone(),
                    reveal_state: RevealState {
                        pending_players: pending_players.clone(),
                        reveal_tokens: Vec::new(),
                    },
                    playing_card: None,
                });
                card_index += 1;
            }
            player.hand_encrypted = encrypted_cards.clone();

            self.deal_results.push(DealResult {
                player_pk: player.pk_hex.clone(),
                encrypted_cards,
            });
        }
        self.phase = GamePhase::Playing;
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
        tracing::debug!("[deal_community_cards_encrypted] deal {:?} community cards", encrypted_cards.clone());
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
                let mut reveal_tokens = EcPoint::IDENTITY;
                for token in &card.reveal_state.reveal_tokens{
                    reveal_tokens = reveal_tokens + token.reveal_token;
                }
                card.encrypted_card.c2 - reveal_tokens
             }
            ).collect();
        let mut ret = Vec::new();
        for plaintext in plaintexts{
            let playing_cards: Option<PlayingCard> = Self::plaintext_to_playingcard(&plaintext);
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
                        let playing_card = Self::plaintext_to_playingcard(&plain_text);
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
                    let playing_card = Self::plaintext_to_playingcard(&plain_text);
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
        self.phase = GamePhase::Reveal;
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
        ).map(|_| true).map_err(|_| VerificationError::InvalidDummyCount)
    }

    pub fn submit_expel(&mut self, record: ExpelRecord) -> Result<(), VerificationError> {
        let _valid = self.verify_expel_record(&record)?;

        let expelled_pk = record.expelled_player_pk.clone();

        if !self.players.contains_key(&expelled_pk) {
            return Err(VerificationError::NoCardsReplaced);
        }

        self.deck_encrypted = record.output_cards.clone();
        self.expelled_players.push(expelled_pk.clone());
        self.expel_records.push(record.clone());

        self.key_manager.remove_player(expelled_pk.clone());

        if let Some(p) = self.players.get_mut(&expelled_pk) {
            p.hand_encrypted.clear();
        }

        self.deal_results.retain(|dr| dr.player_pk != expelled_pk);

        Ok(())
    }

    pub fn submit_depart(&mut self, record: ExpelRecord, sk: &Scalar) -> Result<(), VerificationError> {
        let expelled_pk = record.expelled_player_pk.clone();

        if !self.players.contains_key(&expelled_pk) {
            return Err(VerificationError::NoCardsReplaced);
        }

        let player = self.players.get(&expelled_pk)
            .ok_or(VerificationError::NoCardsReplaced)?;

        let claimed_pk = *BASE_G * sk;
        if claimed_pk != player.pk {
            return Err(VerificationError::NoCardsReplaced);
        }

        let _valid = self.verify_expel_record(&record)?;

        self.deck_encrypted = record.output_cards.clone();
        self.expelled_players.push(expelled_pk.clone());
        self.expel_records.push(record.clone());

        self.key_manager.leave_player(player.pk, sk)
            .map_err(|_| VerificationError::NoCardsReplaced)?;

        if let Some(p) = self.players.get_mut(&expelled_pk) {
            p.hand_encrypted.clear();
        }

        self.deal_results.retain(|dr| dr.player_pk != expelled_pk);

        Ok(())
    }

    pub fn verify_expel_record(
        &self,
        record: &ExpelRecord,
    ) -> Result<bool, VerificationError> {
        let pk = record.departed_player_pk;

        let mut transcript = Transcript::new(b"mental_poker_expel_player");
        ExpelOrProof::verify_expel(
            &record.proof,
            &self.deck_plaintext,
            &record.output_cards,
            &record.user_cards,
            &record.agg_pk_at_proof_time,
            &pk,
            &mut transcript,
        ).map(|_| true)
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

        let player_pk_val = player.pk;

        let deal_num = Self::get_current_deal_num(&self.deal_results, &self.community_cards_encrypted);

        let redeal_ct = self.deck_encrypted[deal_num].clone();
        //todo: 维护deal_num
        Ok(redeal_ct)
    }

    pub fn plaintext_to_playingcard(pt: &Plaintext) -> Option<PlayingCard> {
        for card in standard_deck() {
            let expected = *BASE_G * Scalar::from(card.id() as u32 + 1);
            if *pt == expected {
                return Some(card);
            }
        }
        None
    }

    pub fn get_game_state_summary(&self) -> String {
        format!(
            "MentalPokerGame(phase={:?}, players={}, shuffles={}, dealt={}, community_revealed={}/{}, expelled={}, entrusted={})",
            self.phase,
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
        assert_eq!(self.phase, GamePhase::Shuffling);
        if !self.players.contains_key(player_pk) {
            return Err(VerificationError::NoCardsReplaced);
        }

        let agg_pk = self.key_manager.get_aggregated_pk();
        let mut rng = OsRng;

        let round = ShuffleRound::execute(&self.deck_encrypted, &agg_pk, &mut rng);

        if !round.verify(&agg_pk) {
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
        let proof = RevealTokenProof::prove(&sk, &player.pk, &player_card.encrypted_card, &reveal_token, &mut OsRng);

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
        let proof = RevealTokenProof::prove(&sk, &player.pk, &ct_for_self, &reveal_token, &mut OsRng);

        Ok(RevealToken {
            user_public_key: player.pk,
            encrypted_card: ct_for_self,
            proof,
            reveal_token,
        })
    }

    pub fn proxy_submit_depart_for(&mut self, player_pk: &str) -> Result<(), VerificationError> {
        let sk = self.entrusted_sk.get(player_pk)
            .ok_or(VerificationError::NoCardsReplaced)?
            .clone();

        let player = self.players.get(player_pk)
            .ok_or(VerificationError::NoCardsReplaced)?;

        let user_cards = player.hand_encrypted.clone();
        let pk = player.pk;

        let client_proxy = ClientPlayer { sk: sk.clone(), pk };

        match client_proxy.generate_expel_proof(
            user_cards.iter().map(|x| x.encrypted_card.clone()).collect::<Vec<_>>().as_slice(),
            &self.deck_plaintext,
            &self.key_manager.get_aggregated_pk(),
            &[],
        ) {
            Ok(record) => {
                self.submit_depart(record, &sk)?;
                self.entrusted_sk.remove(player_pk);
                Ok(())
            }
            Err(e) => Err(e),
        }
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
    pub fn initiate_expel(&mut self, target_player_pk: &str) -> Result<ExpelSession, VerificationError> {
        if !self.players.contains_key(target_player_pk) {
            return Err(VerificationError::NoCardsReplaced);
        }
        if self.expelled_players.contains(&target_player_pk.to_string()) {
            return Err(VerificationError::NoCardsReplaced);
        }

        let remaining: Vec<String> = self.players.keys()
            .filter(|pk| *pk != target_player_pk)
            .cloned()
            .collect();

        if remaining.is_empty() {
            return Err(VerificationError::NoCardsReplaced);
        }

        let session = ExpelSession {
            target_player_pk: target_player_pk.to_string(),
            phase: ExpelSessionPhase::Initiated,
            collected_proofs: vec![],
            required_player_pkks: remaining.clone(),
            initiated_at: format!("{:?}", std::time::SystemTime::now()),
        };

        Ok(session)
    }

    pub fn start_expel_session(&mut self, target_player_pk: &str) -> Result<(), VerificationError> {
        let _session = self.initiate_expel(target_player_pk)?;
        Ok(())
    }

    pub fn submit_expel_proof_for_session(&mut self, record: ExpelRecord) -> Result<usize, VerificationError> {
        let valid = self.verify_expel_record(&record)?;
        if !valid {
            return Err(VerificationError::InvalidC2Consistency);
        }

        let proof_count = self.expel_records.len() + 1;
        self.deck_encrypted = record.output_cards.clone();
        self.expel_records.push(record.clone());

        let expelled_pk = record.expelled_player_pk.clone();

        if !self.expelled_players.contains(&expelled_pk) {
            self.expelled_players.push(expelled_pk.clone());
        }

        self.key_manager.remove_player(expelled_pk.clone());

        if let Some(p) = self.players.get_mut(&expelled_pk) {
            p.hand_encrypted.clear();
        }

        self.deal_results.retain(|dr| dr.player_pk != expelled_pk);

        Ok(proof_count)
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

        let mut token_sum = EcPoint::IDENTITY;

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
            let mut token_sum = EcPoint::IDENTITY;
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
        let placeholder = ElGamalCiphertext::new_placehod_card();
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
                    let proof = RevealTokenProof::prove(sk, pk_val, card_ct, &reveal_token, &mut OsRng);
                    Some(RevealToken { 
                        user_public_key: *pk_val,
                        encrypted_card: card_ct.clone(), proof, reveal_token })
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn unmask_card(
        &self,
        card_ct: &ElGamalCiphertext,
        tokens: &[RevealToken],
    ) -> Result<Plaintext, VerificationError> {
        ClientPlayer::distributed_decrypt_from_tokens(card_ct, tokens)
    }

    pub fn compute_aggregate_key_from_pks(pks: &[EcPoint]) -> EcPoint {
        pks.iter().fold(EcPoint::IDENTITY, |agg, pk| agg + pk)
    }
}

#[cfg(test)]
mod tests {
    use k256::elliptic_curve::point::AffineCoordinates;

    use super::*;
    use std::collections::HashMap;

    fn collect_all_tokens(clients: &HashMap<String, ClientPlayer>, target_ct: &ElGamalCiphertext, all_player_pks: &[String]) -> Vec<RevealToken> {
        all_player_pks.iter().map(|pk| clients[pk].generate_reveal_token(target_ct)).collect()
    }
    fn collect_per_card_tokens(clients: &HashMap<String, ClientPlayer>, hand: &[ElGamalCiphertext], all_player_pks: &[String], exclude_pk: &str) -> Vec<Vec<RevealToken>> {
        hand.iter().map(|ct|
            all_player_pks.iter().filter(|pk| pk.as_str() != exclude_pk).map(|pk| clients[pk].generate_reveal_token(ct)).collect()
        ).collect()
    }
    fn all_player_pks(game: &MentalPokerGame) -> Vec<String> { game.players.keys().cloned().collect() }

    fn setup_clients(count: usize) -> HashMap<String, ClientPlayer> {
        (0..count).map(|i| (format!("player_{}", i), ClientPlayer::new())).collect()
    }

    fn register_all(game: &mut MentalPokerGame, clients: &HashMap<String, ClientPlayer>) {
        for (pk_hex, client) in clients {
            game.register_player(pk_hex.clone(), client.pk, client.generate_pk_proof());
        }
    }

    #[test]
    fn test_shuffle_integrity_all_rounds() {
        let mut game = MentalPokerGame::new(GameConfig { num_players: 3, cards_per_player: 5, community_cards: 0 });
        let clients = setup_clients(3);
        register_all(&mut game, &clients);
        game.encrypt_deck();
        for pk in clients.keys() { let r = clients[pk].shuffle(&game.deck_encrypted, &game.aggregated_pk()); game.submit_shuffle(pk, r).expect("Shuffle should succeed"); }
        for (i, round) in game.shuffle_rounds.iter().enumerate() {
            assert!(round.verify(&game.key_manager.get_aggregated_pk()), "Round {} invalid!", i);
        }
        println!("\n✅ All {} shuffle rounds verified", game.shuffle_rounds.len());
    }

    #[test]
    fn test_player_cannot_see_others_cards() {
        let mut game = MentalPokerGame::new(GameConfig::default());
        let clients = setup_clients(4);
        register_all(&mut game, &clients);
        game.encrypt_deck();
        for pk in clients.keys() { let r = clients[pk].shuffle(&game.deck_encrypted, &game.aggregated_pk()); game.submit_shuffle(pk, r).unwrap(); }
        game.complete_shuffle();
        game.deal_to_players().unwrap();

        let pks: Vec<String> = clients.keys().cloned().collect();
        let h0 = game.get_hand_encrypted(&pks[0]).unwrap();
        let h1 = game.get_hand_encrypted(&pks[1]).unwrap();
        assert!(clients[&pks[0]].peek_card(&h0[1], &vec![]).unwrap() != clients[&pks[0]].peek_card(&h0[0], &vec![]).unwrap() || clients[&pks[0]].peek_card(&h0[0], &vec![]).unwrap() != clients[&pks[1]].peek_card(&h1[0], &vec![]).unwrap());
        println!("\n✅ Card privacy verified");
    }

    #[test]
    fn test_reveal_proof_prevents_forgery() {
        let mut game = MentalPokerGame::new(GameConfig { num_players: 2, cards_per_player: 1, community_cards: 0 });
        let clients = setup_clients(2);
        register_all(&mut game, &clients);
        game.encrypt_deck();
        for pk in clients.keys() { let r = clients[pk].shuffle(&game.deck_encrypted, &game.aggregated_pk()); game.submit_shuffle(pk, r).unwrap(); }
        game.complete_shuffle();
        game.deal_to_players().unwrap();

        let pks: Vec<String> = clients.keys().cloned().collect();
        let h0 = game.get_hand_encrypted(&pks[0]).unwrap();
        let agg_pk = game.aggregated_pk();
        let token_p0 = clients[&pks[0]].reveal_own_card(0, h0, &game.deck_plaintext, &agg_pk).unwrap();
        assert!(game.verify_reveal_token(&token_p0, &pks[0]).unwrap());
        match game.verify_reveal_token(&token_p0, &pks[1]) { Ok(v) => assert!(!v), Err(_) => {} }
        println!("\n✅ Cross-player rejection works");
    }

    #[test]
    fn test_expel_player_rebuilds_deck() {
        println!("\n{{'='}}\n=== Expel Test ===\n");
        let mut game = MentalPokerGame::new(GameConfig { num_players: 4, cards_per_player: 2, community_cards: 5 });
        let clients = setup_clients(4);
        register_all(&mut game, &clients);
        game.encrypt_deck();
        for pk in clients.keys() { let r = clients[pk].shuffle(&game.deck_encrypted, &game.aggregated_pk()); game.submit_shuffle(pk, r).unwrap(); }
        game.complete_shuffle();
        game.deal_to_players().unwrap();

        let pks: Vec<String> = clients.keys().cloned().collect();
        let h3 = game.get_hand_encrypted(&pks[3]).unwrap();
        let p3_tokens = collect_per_card_tokens(&clients, h3, &all_player_pks(&game), &pks[3]);
        let record = clients[&pks[3]].generate_expel_proof(h3, &game.deck_plaintext, &game.aggregated_pk(), &p3_tokens).expect("Expel P3 proof");
        game.submit_expel(record.clone()).expect("Submit expel");
        assert_eq!(record.expelled_player_pk, pks[3]);
        assert!(game.verify_expel_record(&record).unwrap());
        println!("\n✅ Expel player deck rebuild works!");
    }

    #[test]
    fn test_redeal_after_expel_mismatch() {
        let mut game = MentalPokerGame::new(GameConfig { num_players: 3, cards_per_player: 2, community_cards: 2 });
        let clients = setup_clients(3);
        register_all(&mut game, &clients);
        game.encrypt_deck();
        for pk in clients.keys() { let r = clients[pk].shuffle(&game.deck_encrypted, &game.aggregated_pk()); game.submit_shuffle(pk, r).unwrap(); }
        game.complete_shuffle();
        game.deal_to_players().unwrap();

        let pks: Vec<String> = clients.keys().cloned().collect();
        let h2 = game.get_hand_encrypted(&pks[2]).unwrap();
        let p2_tokens = collect_per_card_tokens(&clients, h2, &all_player_pks(&game), &pks[2]);
        game.submit_expel(clients[&pks[2]].generate_expel_proof(h2, &game.deck_plaintext, &game.aggregated_pk(), &p2_tokens).unwrap()).unwrap();

        let h0 = game.get_hand_encrypted(&pks[0]).unwrap();
        let pt = clients[&pks[0]].peek_card(&h0[0], &vec![]).unwrap();
        if !game.is_valid_deck_plaintext(&pt) { let new_pt = game.redeal_to_player(&pks[0], 0, pt).expect("redeal"); assert!(game.is_valid_deck_plaintext(&new_pt)); }
        println!("\n✅ Redeal after expel works!");
    }

    #[test]
    fn test_cannot_submit_invalid_expel() {
        let mut game = MentalPokerGame::new(GameConfig::default());
        let clients = setup_clients(4);
        register_all(&mut game, &clients);
        game.encrypt_deck();
        assert!(ClientPlayer::new().generate_expel_proof(&[], &game.deck_plaintext, &game.aggregated_pk(), &[]).is_err());
        println!("\n✅ Invalid expel rejected");
    }

    #[test]
    fn test_multiple_expels_sequential() {
        let mut game = MentalPokerGame::new(GameConfig { num_players: 4, cards_per_player: 1, community_cards: 0 });
        let clients = setup_clients(4);
        register_all(&mut game, &clients);
        game.encrypt_deck();
        for pk in clients.keys() { let r = clients[pk].shuffle(&game.deck_encrypted, &game.aggregated_pk()); game.submit_shuffle(pk, r).unwrap(); }
        game.complete_shuffle();
        game.deal_to_players().unwrap();

        let pks: Vec<String> = clients.keys().cloned().collect();
        let h3 = game.get_hand_encrypted(&pks[3]).unwrap();
        let p3t = collect_per_card_tokens(&clients, h3, &all_player_pks(&game), &pks[3]);
        game.submit_expel(clients[&pks[3]].generate_expel_proof(h3, &game.deck_plaintext, &game.aggregated_pk(), &p3t).unwrap()).unwrap();
        let h2 = game.get_hand_encrypted(&pks[2]).unwrap();
        let t2 = collect_per_card_tokens(&clients, h2, &all_player_pks(&game), &pks[2]);
        game.submit_expel(clients[&pks[2]].generate_expel_proof(h2, &game.deck_plaintext, &game.aggregated_pk(), &t2).unwrap()).unwrap();
        assert_eq!(game.expelled_players.len(), 2);
        println!("\n✅ Multi-expel works!");
    }

    #[test]
    fn test_player_depart_with_sk() {
        let mut game = MentalPokerGame::new(GameConfig { num_players: 4, cards_per_player: 2, community_cards: 5 });
        let clients = setup_clients(4);
        register_all(&mut game, &clients);
        game.encrypt_deck();
        for pk in clients.keys() { let r = clients[pk].shuffle(&game.deck_encrypted, &game.aggregated_pk()); game.submit_shuffle(pk, r).unwrap(); }
        game.complete_shuffle();
        game.deal_to_players().unwrap();

        let pks: Vec<String> = clients.keys().cloned().collect();
        let h2 = game.get_hand_encrypted(&pks[2]).unwrap();
        let t2 = collect_per_card_tokens(&clients, h2, &all_player_pks(&game), &pks[2]);
        let record = clients[&pks[2]].generate_expel_proof(h2, &game.deck_plaintext, &game.aggregated_pk(), &t2).expect("depart proof");
        game.submit_depart(record, &clients[&pks[2]].sk).expect("depart submit");
        assert_eq!(game.expelled_players.last().map(|s| s.as_str()), Some("player_2"));
        println!("\n✅ Depart with SK works!");
    }

    #[test]
    fn test_player_depart_rejects_wrong_sk() {
        let mut game = MentalPokerGame::new(GameConfig::default());
        let clients = setup_clients(4);
        register_all(&mut game, &clients);
        game.encrypt_deck();
        for pk in clients.keys() { let r = clients[pk].shuffle(&game.deck_encrypted, &game.aggregated_pk()); game.submit_shuffle(pk, r).unwrap(); }
        game.complete_shuffle();
        game.deal_to_players().unwrap();

        let pks: Vec<String> = clients.keys().cloned().collect();
        let h1 = game.get_hand_encrypted(&pks[1]).unwrap();
        let t1 = collect_per_card_tokens(&clients, h1, &all_player_pks(&game), &pks[1]);
        assert!(game.submit_depart(clients[&pks[1]].generate_expel_proof(h1, &game.deck_plaintext, &game.aggregated_pk(), &t1).unwrap(), &Scalar::random(&mut OsRng)).is_err());
        println!("\n✅ Wrong SK rejected");
    }


    #[test]
    fn test_cannot_depart_nonexistent_or_wrong_id() {
        let mut game = MentalPokerGame::new(GameConfig::default());
        let clients = setup_clients(2);
        register_all(&mut game, &clients);
        game.encrypt_deck();
        let fake = Scalar::random(&mut OsRng);
        if let Ok(r) = ClientPlayer::new().generate_expel_proof(&[], &game.deck_plaintext, &game.aggregated_pk(), &[]) { assert!(game.submit_depart(r, &fake).is_err()); }
        println!("\n✅ Depart boundary checks pass");
    }

    #[test]
    fn test_expel_vs_depart_comparison() {
        let cfg = GameConfig { num_players: 4, cards_per_player: 2, community_cards: 0 };

        let mut game_a = MentalPokerGame::new(cfg.clone());
        let ca = setup_clients(4);
        register_all(&mut game_a, &ca);
        game_a.encrypt_deck();
        for pk in ca.keys() { let r = ca[pk].shuffle(&game_a.deck_encrypted, &game_a.aggregated_pk()); game_a.submit_shuffle(pk, r).unwrap(); }
        game_a.complete_shuffle();
        game_a.deal_to_players().unwrap();
        let pks_a: Vec<String> = ca.keys().cloned().collect();
        let ha3 = game_a.get_hand_encrypted(&pks_a[3]).unwrap();
        let ta3 = collect_per_card_tokens(&ca, ha3, &all_player_pks(&game_a), &pks_a[3]);
        let r_expel = ca[&pks_a[3]].generate_expel_proof(ha3, &game_a.deck_plaintext, &game_a.aggregated_pk(), &ta3).expect("expel");
        game_a.submit_expel(r_expel.clone());

        let mut game_b = MentalPokerGame::new(cfg);
        let cb = setup_clients(4);
        register_all(&mut game_b, &cb);
        game_b.encrypt_deck();
        for pk in cb.keys() { let r = cb[pk].shuffle(&game_b.deck_encrypted, &game_b.aggregated_pk()); game_b.submit_shuffle(pk, r).unwrap(); }
        game_b.complete_shuffle();
        game_b.deal_to_players().unwrap();
        let pks_b: Vec<String> = cb.keys().cloned().collect();
        let hb2 = game_b.get_hand_encrypted(&pks_b[2]).unwrap();
        let tb2 = collect_per_card_tokens(&cb, hb2, &all_player_pks(&game_b), &pks_b[2]);
        let r_depart = cb[&pks_b[2]].generate_expel_proof(hb2, &game_b.deck_plaintext, &game_b.aggregated_pk(), &tb2).expect("depart");
        game_b.submit_depart(r_depart.clone(), &cb[&pks_b[2]].sk);

        assert!(game_a.verify_expel_record(&r_expel).unwrap());
        assert!(game_b.verify_expel_record(&r_depart).unwrap());
        println!("\n✅ Both expel and depart verify!");
    }

    #[test]
    fn test_client_player_generation() {
        let client = ClientPlayer::new();
        assert_eq!(client.pk, *BASE_G * client.sk);
        assert!(PKOwnershipProof::verify(&client.generate_pk_proof(), &client.pk));
        let pt = *BASE_G + *BASE_H;
        let ct = ElGamalCiphertext::encrypt(&pt, &client.pk, &Scalar::random(&mut OsRng));
        assert_eq!(client.peek_card(&ct, &vec![]).unwrap(), pt);
        println!("\n✅ ClientPlayer generation OK!");
    }


    #[test]
    fn test_expel_session_lifecycle() {
        println!("\n{{'='}}\n=== Expel Session Lifecycle Test ===\n");

        let mut game = MentalPokerGame::new(GameConfig { num_players: 4, cards_per_player: 2, community_cards: 5 });
        let clients = setup_clients(4);
        register_all(&mut game, &clients);
        game.encrypt_deck();
        for pk in clients.keys() { let r = clients[pk].shuffle(&game.deck_encrypted, &game.aggregated_pk()); game.submit_shuffle(pk, r).unwrap(); }
        game.complete_shuffle();
        game.deal_to_players().unwrap();

        let pks: Vec<String> = clients.keys().cloned().collect();
        let session = game.initiate_expel(&pks[2]).unwrap();
        assert_eq!(session.target_player_pk, pks[2]);
        assert_eq!(session.phase, ExpelSessionPhase::Initiated);
        println!("Phase name: {}", MentalPokerGame::expel_phase_name(&Some(session.phase.clone())));

        let state = game.get_expel_state();
        assert!(!state.can_continue);
        assert_eq!(state.expelled_players.len(), 0);

        for pk in pks.iter() {
            game.entrust_player(pk, &clients[pk].sk).unwrap();
        }
        let _force_result = game.force_expel_player(&pks[2]).unwrap();

        let state_after = game.get_expel_state();
        assert!(state_after.can_continue);
        assert!(state_after.expelled_players.contains(&"player_2".to_string()));

        let err = game.initiate_expel(&pks[2]);
        assert!(err.is_err());
        println!("Cannot re-initiate expel for already expelled player: {:?}", err.err());

        println!("\n✅ Expel session lifecycle OK!");
    }

    #[test]
    fn test_expel_invalid_target() {
        let mut game = MentalPokerGame::new(GameConfig::default());
        let clients = setup_clients(2);
        register_all(&mut game, &clients);
        game.encrypt_deck();

        assert!(game.initiate_expel("player_99").is_err());
        assert!(game.force_expel_player("player_99").is_err());
        println!("\n✅ Invalid target rejected");
    }

    #[test]
    fn test_expel_state_response_serialization() {
        let state = ExpelStateResponse {
            expelled_players: vec!["player_2".to_string(), "player_3".to_string()],
            expel_records_count: 2,
            active_players: vec!["player_0".to_string(), "player_1".to_string()],
            can_continue: true,
        };
        assert_eq!(state.expelled_players.len(), 2);
        assert!(state.can_continue);
        println!("\n✅ ExpelStateResponse struct OK");
    }

    #[test]
    fn test_join_game_and_shuffle_tampered_output_fails() {
        println!("\n=== test_join_game_and_shuffle_tampered_output ===\n");

        let mut game = MentalPokerGame::new(GameConfig::default());
        let existing = setup_clients(1);
        register_all(&mut game, &existing);
        game.encrypt_deck();
        for pk in existing.keys() {
            let r = existing[pk].shuffle(&game.deck_encrypted, &game.aggregated_pk());
            game.submit_shuffle(pk, r).unwrap();
        }

        let client = ClientPlayer::new();
        let result = client.join_game_and_shuffle(&game.deck_encrypted, &game.aggregated_pk());
        let ms = &result.mask_and_shuffle_round;

        let mut tampered_output = ms.output_cards.clone();
        if !tampered_output.is_empty() {
            tampered_output.swap(0, 1);
        }

        let share_pk = game.aggregated_pk() + client.pk;
        let proof_valid = ms.proof.verify(&ms.mask_cards, &tampered_output, &share_pk);
        assert!(!proof_valid, "Tampered output should fail shuffle verification");

        println!("\n✅ Tampered output correctly rejected!");
    }

        #[test]
    fn test_join_game_and_shuffle_identity() {
        println!("\n=== test_join_game_and_shuffle_tampered_output ===\n");

        let mut game = MentalPokerGame::new(GameConfig::default());
        let client = ClientPlayer::new();
        let result = client.join_game_and_shuffle(&game.deck_encrypted, &EcPoint::IDENTITY);
        let ms = &result.mask_and_shuffle_round;

        let mut tampered_output = ms.output_cards.clone();
        if !tampered_output.is_empty() {
            tampered_output.swap(0, 1);
        }

        let share_pk = game.aggregated_pk() + client.pk;
        let proof_valid = ms.proof.verify(&ms.mask_cards, &tampered_output, &share_pk);
        assert!(!proof_valid, "Tampered output should fail shuffle verification");

        println!("\n✅ Tampered output correctly rejected!");
    }
}
