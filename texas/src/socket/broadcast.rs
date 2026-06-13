use std::sync::Arc;

use super::*;

pub(crate) async fn broadcast_to_table(io: &SocketIo, state: &Arc<SocketState>, table_id: u32, message: Option<&str>) {
    let table_views = {
        let gs = state.state.read().await;
        let Some(table) = gs.tables.get(&table_id) else { return };
        let base_client_table = table.to_client();
        table.players.iter()
            .filter_map(|(_game_pk, wallet_addr)| {
                gs.players.values()
                    .find(|p| p.wallet_address.0 == wallet_addr.0)
                    .map(|p| (p.socket_id.clone(), hide_opponent_cards(&base_client_table, &p.wallet_address)))
            })
            .collect::<Vec<_>>()
    };

    for (sid_str, table_view) in table_views {
        let payload = TableUpdatePayload {
            table: table_view,
            message: message.map(|s| s.to_string()),
            from: None,
        };
        if let Ok(sid) = sid_str.parse::<socketioxide::socket::Sid>() {
            if let Some(socket) = io.get_socket(sid) {
                tracing::info!("broadcast_to_table: socket {} found", sid_str);
                if let Err(e) = socket.emit(actions::TABLE_UPDATED, &payload) {
                    tracing::warn!("broadcast_to_table emit failed for {}: {:?}", sid_str, e);
                }
            } else {
                tracing::debug!("broadcast_to_table: socket {} not found", sid_str);
            }
        }
    }
}

pub(crate) async fn join_table_push(io: &SocketIo, state: &Arc<SocketState>, table_id: u32, wallet: WalletAddress) {    
    let gs = state.state.read().await;
    let Some(table) = gs.tables.get(&table_id) else { return };
    let base_client_table = table.to_client();
    let table_view = hide_opponent_cards(&base_client_table, &wallet);
    let payload = TableUpdatePayload {
            table: table_view,
            message: Some("".to_string()),
            from: None,
        };
    _ = io.emit(actions::TABLE_UPDATED, &payload).await;
}

impl SocketState {
    pub(crate) async fn broadcast_player_reveal_result(&self, table_id: u32, action: &str) {
        let io = match get_socket_io() {
            Some(io) => io,
            None => return,
        };
        tracing::info!("broadcast_player_reveal_result: {} {}", table_id, action);
        let (player_cards, deck_plaintext, socket_id_map) = {
            let gs = self.state.read().await;
            let table = match gs.tables.get(&table_id) {
                Some(t) => t,
                None => return,
            };
            let player_cards = table.mental_poker_game.get_player_readable_tokens();
            let socket_id_map: std::collections::HashMap<String, String> = table.players.iter()
            .filter_map(|(game_pk, wallet_addr)| {
                gs.players.values()
                    .find(|p| p.wallet_address.0 == wallet_addr.0)
                    .map(|player| (game_pk.0.clone(), player.socket_id.clone()))
            })
            .collect();
            let deck_plaintext = table.mental_poker_game.deck_plaintext
                .iter()
                .map(|p| ecpoint_to_hex(p))
                .collect::<Vec<String>>();
            (player_cards, deck_plaintext, socket_id_map)
        };

        for (player_pk, cards) in player_cards {
            let socket_id = match socket_id_map.get(&player_pk) {
                Some(s) => s,
                None => continue,
            };
            let readable_cards: Vec<ElGamalCiphertextJson> = cards.iter()
                .map(|c| ElGamalCiphertextJson::from_ciphertext(c))
                .collect();
            let payload = HandRevealResultPayload {
                table_id,
                player_pk: GamePkHex::new(player_pk.clone()),
                readable_cards,
                deck_plaintext: deck_plaintext.clone(),
            };
            if let Ok(sid) = socket_id.parse::<socketioxide::socket::Sid>() {
                if let Some(socket) = io.get_socket(sid) {
                    let _ = socket.emit(action, &payload);
                }
            }
        }
    }

    pub async fn broadcast_hand_reveal_result(&self, table_id: u32) {
        self.broadcast_player_reveal_result(table_id, actions::HAND_REVEAL_RESULT).await;
    }

    pub async fn broadcast_redeal_result(&self, table_id: u32) {
        self.broadcast_player_reveal_result(table_id, actions::REDEAL_RESULT).await;
    }

    pub async fn broadcast_redeal_notice(&self, table_id: u32) {
        let io = match get_socket_io() {
            Some(io) => io,
            None => return,
        };

        let reveal_notice = {
            let gs = self.state.read().await;
            gs.tables.get(&table_id).map(|t| {
                let phase = t.reveal_token_state.phase.clone();
                let pending = t.reveal_token_state.pending_players.clone();
                let completed = t.reveal_token_state.completed_players.clone();
                let player_assignments = t.reveal_token_state.player_assignments.clone();
                RevealNoticePayload { table_id, phase, pending_players: pending, completed_players: completed, player_assignments }
            })
        };

        if let Some(notice) = reveal_notice {
            let _ = io.to(table_room_name(table_id)).emit(actions::REDEAL_NOTICE, &notice).await;
        }
    }

    pub async fn broadcast_showdown_result(self: &Arc<Self>, table_id: u32) {
        let io = match get_socket_io() {
            Some(io) => io,
            None => return,
        };

        {
            let mut gs = self.state.write().await;
            if let Some(table) = gs.tables.get_mut(&table_id) {
                let (player_revealed_map, _) = table.mental_poker_game.list_revealed_cards();

                for seat in table.seats.values_mut() {
                    if let Some(player) = &seat.player {
                        if let Some(revealed_cards) = player_revealed_map.get(&player.pk_hex.0) {
                            if revealed_cards.len() >= 2 {
                                let hand: Vec<Card> = revealed_cards.iter()
                                    .map(|pc| Card::from_playing_card(pc))
                                    .collect();
                                seat.hand = hand;
                            }
                        }
                    }
                }
            }
        }
        broadcast_to_table(&io, self, table_id, None).await;
    }

    pub async fn broadcast_community_cards(&self, table_id: u32) {
        let io = match get_socket_io() {
            Some(io) => io,
            None => return,
        };

        let community_cards = {
            let gs = self.state.read().await;
            match gs.tables.get(&table_id) {
                Some(table) => table.mental_poker_game.list_revealed_community_cards(),
                None => return,
            }
        };

        let cards: Vec<Card> = community_cards.iter()
            .map(|pc| Card::from_playing_card(pc))
            .collect();

        let payload = CommunityRevealResultPayload {
            table_id,
            community_cards: cards,
        };
        let _ = io.to(table_room_name(table_id)).emit(actions::COMMUNITY_REVEAL_RESULT, &payload).await;
    }
}
