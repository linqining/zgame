use super::*;
use rand::rngs::OsRng;

impl Table {
    pub fn start_reconstruct(&mut self) -> Result<(), String> {
        if self.reconstruct_state.is_active {
            return Err("Reconstruct already in progress".to_string());
        }
        self.reconstruct_state.is_active = true;
        self.reconstruct_state.timeout_start = Some(std::time::Instant::now());
        self.reconstruct_state.timeout_seconds = 10;
        self.reconstruct_state.completed_players.clear();
        self.reconstruct_state.pending_players = self.mental_poker_game.players.keys()
            .map(|k| GamePkHex::new(k.clone()))
            .collect();
        self.reconstruct_state.cards = self.mental_poker_game.deck_plaintext.clone();
        let mut rng = OsRng;
        self.reconstruct_state.coefficient = Scalar::random(&mut rng);
        self.reconstruct_state.player_readable_cards.clear();
        let player_readable_cards = self.mental_poker_game.get_player_readable_tokens();
        for (pk, cards) in player_readable_cards {
            self.reconstruct_state.player_readable_cards.insert(GamePkHex::new(pk.clone()), PlayerReadableCard{readable_cards: cards});
        }
        self.reconstruct_state.player_deck.clear();
        tracing::info!("[RECONSTRUCT] Reconstruct initiated for player {}", self.reconstruct_state.pending_players.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(","));
        Ok(())
    }

    pub fn vote_reconstruct(&mut self, voter_pk: &GamePkHex, vote: bool) -> Result<ReconstructPhase, String> {
        if !self.reconstruct_state.is_active {
            return Err("No reconstruct in progress".to_string());
        }
        if self.reconstruct_state.completed_players.contains(voter_pk) {
            return Err("Player already voted".to_string());
        }

        if vote {
            self.reconstruct_state.completed_players.push(voter_pk.clone());
            tracing::info!("[RECONSTRUCT] Player {} voted to reconstruct, votes: {}",
                voter_pk, self.reconstruct_state.completed_players.len());

            if self.reconstruct_state.completed_players.len() >= self.reconstruct_state.pending_players.len() {
                tracing::info!("[RECONSTRUCT] Vote passed, reconstruct player {}",
                    self.reconstruct_state.pending_players.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(","));
                return Ok(ReconstructPhase::Completed);
            }
        } else {
            self.reconstruct_state.reset();
            tracing::info!("[RECONSTRUCT] Vote rejected by {}", voter_pk);
            return Ok(ReconstructPhase::Initiated);
        }

        Ok(ReconstructPhase::Voting)
    }


    pub fn check_reconstruct_timeout(&mut self) -> Option<GamePkHex> {
        if !self.reconstruct_state.is_active {
            return None;
        }
        let timeout_start = match self.reconstruct_state.timeout_start {
            Some(t) => t,
            None => return None,
        };

        if timeout_start.elapsed().as_secs() >= self.reconstruct_state.timeout_seconds {
            let mut not_voted = Vec::new();
            for player_pk in self.reconstruct_state.pending_players.iter() {
                if !self.reconstruct_state.completed_players.contains(player_pk) {
                    not_voted.push(player_pk.clone());
                }
            }
            tracing::warn!("[RECONSTRUCT] Reconstruct timeout for player {:?}", not_voted.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(","));
            for player_pk in not_voted {
                self.remove_player_by_pk(&player_pk);
            }
            //todo 通知玩家被踢出
            self.reconstruct_state.reset();
            return None;
        }
        None
    }

    pub fn execute_reconstruct_if_completed(&mut self) -> bool {
        if !self.reconstruct_state.is_active {
            return false;
        }
        if self.reconstruct_state.completed_players.len() >= self.reconstruct_state.pending_players.len() {
            tracing::info!("[RECONSTRUCT] Executing reconstruct for players: {:?}",
                self.reconstruct_state.pending_players);
            self.reconstruct_state.reset();
            return true;
        }
        false
    }

    pub fn submit_reconstruct_deck(
        &mut self,
        player_pk_hex: &GamePkHex,
        output_cards: Vec<ElGamalCiphertextJson>,
        swap_cards: Vec<ElGamalCiphertextJson>,
        proof: ReconstructProofJson,
    ) -> Result<bool, String> {
        if !self.reconstruct_state.is_active {
            return Err("Reconstruct not active".to_string());
        }
        if !self.reconstruct_state.pending_players.contains(player_pk_hex) {
            return Err("Not found player".to_string());
        }

        let player = self.mental_poker_game.players.get(&**player_pk_hex)
            .map(|p| p.pk)
            .ok_or("Player not found in mental poker game")?;

        let output_cards = output_cards.iter()
            .map(|c| c.to_ciphertext())
            .collect::<Result<Vec<_>, _>>()?;
        let swap_cards = swap_cards.iter()
            .map(|c| c.to_ciphertext())
            .collect::<Result<Vec<_>, _>>()?;
        let proof = proof.to_proof()?;
        let user_readable_cards = self.reconstruct_state.player_readable_cards.get(player_pk_hex);
        if user_readable_cards.is_none() {
            return Err("Player not found in reconstruct state".to_string());
        }
        let user_readable_cards = user_readable_cards.unwrap();
        let mut transcript = merlin::Transcript::new(b"zk_poker_reconstruct");
        if proof.verify(&self.reconstruct_state.cards, &output_cards,
        &swap_cards, &user_readable_cards.readable_cards,
        &player, &mut transcript).is_err(){
            return Err("Invalid reconstruct proof".to_string());
        }

        self.reconstruct_state.player_deck.insert(player_pk_hex.clone(), output_cards);
        self.reconstruct_state.pending_players.retain(|p| p != player_pk_hex);
        self.reconstruct_state.completed_players.push(player_pk_hex.clone());
        let is_all_complete = self.reconstruct_state.pending_players.len()==0;
        if is_all_complete {
            let init_deck = self.mental_poker_game.deck_plaintext.clone();
            let deck_len = init_deck.len();
            let mut reconstruct_deck = init_deck.iter().map(|c| ElGamalCiphertext {
                c1: EcPoint::identity(),
                c2: c.clone(),
            }).collect::<Vec<_>>();
            for (_, deck) in self.reconstruct_state.player_deck.iter() {
                for (i, card) in deck.iter().enumerate() {
                    if i < deck_len {
                        reconstruct_deck[i].c1 = reconstruct_deck[i].c1 + card.c1;
                        reconstruct_deck[i].c2 = reconstruct_deck[i].c2 + card.c2 - init_deck[i];
                    }
                }
            }
            self.mental_poker_game.deck_encrypted = reconstruct_deck;
            self.reconstruct_state.reset();
        }
        Ok(is_all_complete)
    }

    pub fn get_reconstruct_public_state(&self) -> Option<ReconstructPublicState> {
        if self.reconstruct_state.is_active {
            Some(ReconstructPublicState {
                is_active: true,
                completed_players: self.reconstruct_state.completed_players.clone(),
                pending_players: self.reconstruct_state.pending_players.clone(),
                cards: self.reconstruct_state.cards.iter().map(|c| ecpoint_to_hex(c)).collect(),
                coefficient_hex: scalar_to_hex(&self.reconstruct_state.coefficient),
                player_readable_cards: self.reconstruct_state.player_readable_cards.iter().map(|(k, v)| {
                    (k.clone(), PlayerReadableCardJson {
                        readable_cards: v.readable_cards.iter().map(ElGamalCiphertextJson::from_ciphertext).collect(),
                    })
                }).collect(),
            })
        } else {
            None
        }
    }
}
