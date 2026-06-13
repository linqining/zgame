pub use handlers::register_handlers;

pub mod broadcast;
pub mod game_loop;
pub mod handlers;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::OnceLock;
use tokio::sync::RwLock;

use serde::{Deserialize, Serialize};
use socketioxide::{SocketIo, extract::SocketRef};

use crate::config::Config;
use crate::models::Database;
use crate::pokergame::actions;
use crate::pokergame::deck::Card;
use crate::pokergame::game_state::{ElGamalCiphertextJson, ReconstructPhase, MaskAndShuffleRoundJson, ShuffleProofJson, PlayerReadableCardJson,
    PkProofJson, ReconstructProofJson, RevealPhase, ShufflePublicState, LeaveGameRoundJson};
use crate::pokergame::player::{Player, WalletAddress, GamePkHex, GamePlayer};
use crate::pokergame::table::{ActionRequest, ClientTable, JoinError, JoinResult, RoundState, Table};
use poker_protocol::crypto::EcPoint;
use poker_protocol::z_poker::convert::{ecpoint_to_hex, hex_to_ecpoint, scalar_to_hex};

pub(crate) const MIN_START_NUM: u32 = 3;

pub(crate) fn table_room_name(table_id: u32) -> String {
    format!("table_{}", table_id)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LobbyInfo {
    pub tables: Vec<TableSummary>,
    pub players: Vec<PlayerInfo>,
    pub socket_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct JoinTablePayload {
    pub table_id: u32,
    pub pk_hex: GamePkHex,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LeaveTablePayload {
    pub table_id: u32,
    pub pk_hex: GamePkHex,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct TableSummary {
    pub id: u32,
    pub name: String,
    pub limit: u64,
    pub max_players: u32,
    pub current_number_players: usize,
    pub small_blind: u64,
    pub big_blind: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PlayerInfo {
    pub socket_id: String,
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TableLeftPayload {
    pub tables: Vec<TableSummary>,
    pub table_id: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TableUpdatePayload {
    pub table: ClientTable,
    pub message: Option<String>,
    pub from: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RaisePayload {
    pub table_id: u32,
    pub amount: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TableMessagePayload {
    pub message: String,
    pub from: String,
    pub table_id: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SitDownPayload {
    pub table_id: u32,
    pub seat_id: u32,
    pub amount: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SitDownV2Payload {
    pub token: String,
    pub table_id: u32,
    pub seat_id: u32,
    pub amount: u64,
    pub pk_hex: GamePkHex,
    pub pk_proof: PkProofJson,
    pub mask_and_shuffle_round: MaskAndShuffleRoundJson,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StandUpPayload {
    pub table_id: u32,
    pub pk_hex: GamePkHex,
    pub leave_round: LeaveGameRoundJson,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RebuyPayload {
    pub table_id: u32,
    pub seat_id: u32,
    pub amount: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SittingPayload {
    pub table_id: u32,
    pub seat_id: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ShuffleSubmitPayload {
    pub table_id: u32,
    pub pk_hex: GamePkHex,
    pub output_cards: Vec<ElGamalCiphertextJson>,
    pub shuffle_proof: ShuffleProofJson,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RevealSubmitPayload {
    pub table_id: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RedealRequestPayload {
    pub table_id: u32,
    pub player_pk: GamePkHex,
    pub failed_card_indices: Vec<usize>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ReconstructSubmitPayload {
    pub table_id: u32,
    pub pk_hex: GamePkHex,
    pub output_cards: Vec<ElGamalCiphertextJson>,
    pub swap_cards: Vec<ElGamalCiphertextJson>,
    pub proof: ReconstructProofJson,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HandRevealResultPayload {
    pub table_id: u32,
    pub player_pk: GamePkHex,
    pub readable_cards: Vec<ElGamalCiphertextJson>,
    pub deck_plaintext: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CommunityRevealResultPayload {
    pub table_id: u32,
    pub community_cards: Vec<Card>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReconstructInitiatePayload {
    pub table_id: u32,
    pub target_socket_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReconstructVotePayload {
    pub table_id: u32,
    pub vote: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ShuffleNoticePayload {
    pub table_id: u32,
    pub shuffle_state: Option<ShufflePublicState>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RevealNoticePayload {
    pub table_id: u32,
    pub phase: RevealPhase,
    pub pending_players: Vec<GamePkHex>,
    pub completed_players: Vec<GamePkHex>,
    pub player_assignments: HashMap<GamePkHex, crate::pokergame::game_state::PlayerRevealAssignment>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ReconstructNoticePayload {
    pub table_id: u32,
    pub completed_players: Vec<GamePkHex>,
    pub pending_players: Vec<GamePkHex>,
    pub cards: Vec<String>,
    pub coefficient_hex: String,
    pub player_readable_cards: HashMap<GamePkHex, PlayerReadableCardJson>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReconstructResultPayload {
    pub table_id: u32,
    pub completed_players: Vec<GamePkHex>,
    pub reconstructed: bool,
}

pub(crate) struct GameLoopEntry {
    pub _handle: tokio::task::JoinHandle<()>,
    pub action_sender: tokio::sync::mpsc::Sender<ActionRequest>,
    pub stop_sender: tokio::sync::watch::Sender<bool>,
}

pub(crate) struct GameLoopRegistry {
    pub entries: HashMap<u32, GameLoopEntry>,
}

impl GameLoopRegistry {
    pub fn new() -> Self {
        Self { entries: HashMap::new() }
    }

    pub fn contains(&self, table_id: u32) -> bool {
        self.entries.contains_key(&table_id)
    }

    pub fn get_sender(&self, table_id: u32) -> Option<tokio::sync::mpsc::Sender<ActionRequest>> {
        self.entries.get(&table_id).map(|e| e.action_sender.clone())
    }

    pub fn insert(&mut self, table_id: u32, entry: GameLoopEntry) {
        self.entries.insert(table_id, entry);
    }

    pub fn remove(&mut self, table_id: u32) {
        if let Some(entry) = self.entries.remove(&table_id) {
            let _ = entry.stop_sender.send(true);
        }
    }
}

static SOCKET_IO: OnceLock<SocketIo> = OnceLock::new();

pub fn set_socket_io(io: SocketIo) {
    let _ = SOCKET_IO.set(io);
}

pub(crate) fn get_socket_io() -> Option<SocketIo> {
    SOCKET_IO.get().cloned()
}

pub(crate) struct GameState {
    pub tables: HashMap<u32, Table>,
    pub players: HashMap<String, Player>,
    pub disconnect_cancellers: HashMap<String, tokio::sync::watch::Sender<bool>>,
}

impl GameState {
    /// Remove a player by pk_hex from the specified table and the players map.
    /// Returns the player's socket_id if found.
    pub fn remove_player_by_pk(&mut self, table_id: u32, pk_hex: &GamePkHex) -> Option<String> {
        let wallet_address = self.tables.get(&table_id)
            .and_then(|table| table.players.get(pk_hex).cloned());

        if let Some(wallet_addr) = wallet_address {
            let socket_id = self.players.iter()
                .find(|(_, p)| p.wallet_address == wallet_addr)
                .map(|(_, p)| p.socket_id.clone());

            // Remove from the specified table
            if let Some(table) = self.tables.get_mut(&table_id) {
                table.remove_player_by_pk(pk_hex);
            }

            // Remove from players map
            if let Some(ref sid) = socket_id {
                self.players.remove(sid);
            }

            socket_id
        } else {
            None
        }
    }
}

pub struct SocketState {
    pub db: Database,
    pub state: RwLock<GameState>,
    pub config: Config,
    pub game_loop_registry: RwLock<GameLoopRegistry>,
}

impl SocketState {
    pub fn new(db: Database, tables: HashMap<u32, Table>, config: Config) -> Self {
        Self {
            db,
            state: RwLock::new(GameState {
                tables,
                players: HashMap::new(),
                disconnect_cancellers: HashMap::new(),
            }),
            config,
            game_loop_registry: RwLock::new(GameLoopRegistry::new()),
        }
    }

    pub(crate) async fn get_current_tables(&self) -> Vec<TableSummary> {
        let gs = self.state.read().await;
        gs.tables
            .values()
            .map(|t| TableSummary {
                id: t.id,
                name: t.name.clone(),
                limit: t.limit,
                max_players: t.max_players,
                current_number_players: t.players.len(),
                small_blind: t.min_bet,
                big_blind: t.min_bet * 2,
            })
            .collect()
    }

    pub(crate) async fn get_current_players(&self) -> Vec<PlayerInfo> {
        let gs = self.state.read().await;
        gs.players
            .values()
            .map(|p| PlayerInfo {
                socket_id: p.socket_id.clone(),
                id: p.id.clone(),
                name: p.name.clone(),
            })
            .collect()
    }

    pub async fn get_action_sender(&self, table_id: u32) -> Option<tokio::sync::mpsc::Sender<ActionRequest>> {
        let registry = self.game_loop_registry.read().await;
        registry.get_sender(table_id)
    }

    pub async fn start_game_loop(&self, io: SocketIo, state: Arc<SocketState>, table_id: u32) {
        let mut registry = self.game_loop_registry.write().await;
        if registry.contains(table_id) {
            return;
        }
        let (tx, rx) = tokio::sync::mpsc::channel::<ActionRequest>(100);
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let handle = tokio::spawn(game_loop::game_loop_task(io, state, table_id, rx, stop_rx));
        registry.insert(table_id, GameLoopEntry {
            _handle: handle,
            action_sender: tx,
            stop_sender: stop_tx,
        });
    }

    pub async fn start_game_loop_from_ctx(&self, state: Arc<SocketState>, table_id: u32) {
        let io = match get_socket_io() {
            Some(io) => io,
            None => return,
        };
        self.start_game_loop(io, state, table_id).await;
    }

    pub async fn stop_game_loop(&self, table_id: u32) {
        tracing::info!("stop_game_loop: {}", table_id);
        let mut registry = self.game_loop_registry.write().await;
        registry.remove(table_id);
    }

    /// Resolve socket_id from a pk_hex for a given table
    pub async fn resolve_socket_id_by_pk(&self, table_id: u32, pk_hex: &GamePkHex) -> Option<String> {
        let gs = self.state.read().await;
        let wallet_addr = gs.tables.get(&table_id)
            .and_then(|table| table.players.get(pk_hex).cloned());
        if let Some(wallet_addr) = wallet_addr {
            gs.players.values()
                .find(|p| p.wallet_address == wallet_addr)
                .map(|p| p.socket_id.clone())
        } else {
            None
        }
    }

    pub async fn find_socket_id_by_pk(&self, table_id: u32, pk_hex: &GamePkHex) -> Option<String> {
        self.resolve_socket_id_by_pk(table_id, pk_hex).await
    }

    pub async fn send_shuffle_notice(&self, table_id: u32) {
        let io = match get_socket_io() {
            Some(io) => io,
            None => return,
        };

        let shuffle_notice_data = {
            let gs = self.state.read().await;
            if let Some(table) = gs.tables.get(&table_id) {
                let shuffle_state = table.get_shuffle_public_state();
                let current_pk = table.shuffle_state.current_player_pk.clone();
                let socket_id = if let Some(pk) = &current_pk {
                    if let Some(wallet_address) = table.players.get(pk) {
                        gs.players.values()
                            .find(|p| &p.wallet_address == wallet_address)
                            .map(|p| p.socket_id.clone())
                    } else {
                        None
                    }
                } else {
                    None
                };
                shuffle_state.zip(socket_id)
            } else {
                None
            }
        };

        if let Some((shuffle_state, socket_id)) = shuffle_notice_data {
            if let Ok(sid) = socket_id.parse::<socketioxide::socket::Sid>() {
                if let Some(socket) = io.get_socket(sid) {
                    let notice = ShuffleNoticePayload { table_id, shuffle_state: Some(shuffle_state) };
                    let _ = socket.emit(actions::SHUFFLE_NOTICE, &notice);
                }
            }
        }
    }

    pub async fn mark_player_sitting_out(&self, table_id: u32, wallet_address: &WalletAddress) {
        let mut gs = self.state.write().await;
        if let Some(table) = gs.tables.get_mut(&table_id) {
            for seat in table.seats.values_mut() {
                if seat.player.as_ref().map_or(false, |p| &p.wallet_address == wallet_address) {
                    seat.sitting_out = true;
                }
            }
        }
    }

    pub async fn is_player_in_seat(&self, pk_hex: &GamePkHex) -> bool {
        let gs = self.state.read().await;
        gs.tables.values().any(|table| {
            table.seats.values().any(|seat| {
                seat.player.as_ref().map_or(false, |p| &p.pk_hex == pk_hex)
            })
        })
    }

    pub async fn find_player_by_pk(&self, table_id: u32, pk_hex: &GamePkHex) -> Option<Player> {
        let gs = self.state.read().await;
        let wallet_address = gs.tables.get(&table_id).and_then(|table| table.players.get(pk_hex));
        if let Some(wallet_addr) = wallet_address {
            gs.players.iter().find(|(_, p)| &p.wallet_address == wallet_addr).map(|(_, p)| p.clone())
        } else {
            None
        }
    }

    pub async fn get_client_table(&self, table_id: u32) -> Option<ClientTable> {
        let gs = self.state.read().await;
        gs.tables.get(&table_id).map(|t| t.to_client())
    }

    pub async fn add_player_to_table(&self, table_id: u32, player: Player, pk_hex: &GamePkHex) -> Result<usize, String> {
        let mut gs = self.state.write().await;
        gs.players.insert(player.socket_id.clone(), player.clone());
        if let Some(table) = gs.tables.get_mut(&table_id) {
            table.add_player(pk_hex.clone(), player.wallet_address.clone());
            Ok(table.active_players().len())
        } else {
            Err("Table not found".to_string())
        }
    }

    pub async fn join_player_and_shuffle(
        &self,
        table_id: u32,
        player: Player,
        player_pk: EcPoint,
        pk_proof_json: PkProofJson,
        round_json: MaskAndShuffleRoundJson,
        seat_id: u32,
        amount: u64,
    ) -> Result<(bool, JoinResult), JoinError> {
        let socket_id = player.socket_id.clone();
        let pk_hex = GamePkHex::new(ecpoint_to_hex(&player_pk));
        let player_wallet_address = player.wallet_address.clone();
        let player_name = player.name.clone();
        let player_id = player.id.clone();
        let player_bankroll = player.bankroll;

        let result = {
            let mut gs = self.state.write().await;
            if let Some(table) = gs.tables.get_mut(&table_id) {
                table.join_player_and_shuffle(player, player_pk, pk_proof_json, round_json, seat_id, amount)
            } else {
                Err(JoinError::Crypto("Table not found".to_string()))
            }
        };

        match &result {
            Ok(JoinResult::JoinedAndShuffled) => {
                let mut gs = self.state.write().await;
                let already_exists = gs.players.values().any(|p| p.wallet_address == player_wallet_address);
                if !already_exists {
                    gs.players.insert(socket_id.clone(), Player {
                        socket_id: socket_id.clone(),
                        id: player_id,
                        name: player_name,
                        bankroll: player_bankroll,
                        wallet_address: player_wallet_address.clone(),
                    });
                }

                if let Some(table) = gs.tables.get_mut(&table_id) {
                    if table.is_pending_shuffle_player_empty() && table.complete_shuffle_player_count() >= MIN_START_NUM as usize  {
                        table.shuffle_state.is_active = false;
                        table.transition_to(RoundState::ShuffleComplete);
                        tracing::info!("[SHUFFLE] Player {} joined and shuffled, all players shuffled {:?}", pk_hex,table.shuffle_state.completed_players);
                        return Ok((true, JoinResult::JoinedAndShuffled));
                    } else {
                        tracing::info!("[SHUFFLE] Player {} joined and shuffled, but not enough players to start,shuffle cnt {}", pk_hex, table.complete_shuffle_player_count());
                        table.complete_or_continue_next_shuffler();
                    }
                }
                Ok((false, JoinResult::JoinedAndShuffled))
            }
            Ok(JoinResult::JoinedWaiting) => {
                let mut gs = self.state.write().await;
                let already_exists = gs.players.values().any(|p| p.wallet_address.0 == player_wallet_address.0);
                if !already_exists {
                    gs.players.insert(socket_id.clone(), Player {
                        socket_id: socket_id.clone(),
                        id: player_id,
                        name: player_name,
                        bankroll: player_bankroll,
                        wallet_address: player_wallet_address,
                    });
                }
                Ok((false, JoinResult::JoinedWaiting))
            }
            Err(e) => Err(e.clone()),
        }
    }

    pub async fn submit_verified_shuffle_for_pk(
        &self,
        table_id: u32,
        pk_hex: &GamePkHex,
        _player: Player,
        output_cards: Vec<ElGamalCiphertextJson>,
        shuffle_proof: ShuffleProofJson,
    ) -> Result<(), String> {
        let mut gs = self.state.write().await;
        if let Some(table) = gs.tables.get_mut(&table_id) {
            match table.submit_verified_shuffle(pk_hex, output_cards, shuffle_proof) {
                Ok(()) => {
                    if table.is_all_players_shuffled() && table.complete_shuffle_player_count() >= MIN_START_NUM as usize  {
                        table.shuffle_state.is_active = false;
                        table.transition_to(RoundState::ShuffleComplete);
                    } else {
                        table.complete_or_continue_next_shuffler();
                    }
                    Ok(())
                }
                Err(e) => Err(e),
            }
        } else {
            Err("Table not found".to_string())
        }
    }

    pub async fn mark_reveal_complete_for_pk(&self, table_id: u32, pk_hex: &GamePkHex) -> Result<bool, String> {
        let mut gs = self.state.write().await;
        if let Some(table) = gs.tables.get_mut(&table_id) {
            Ok(table.mark_player_reveal_complete(pk_hex))
        } else {
            Err("Table not found".to_string())
        }
    }

    pub async fn submit_reveal_tokens_for_pk(
        &self,
        table_id: u32,
        pk_hex: &GamePkHex,
        tokens: Vec<poker_protocol::z_poker::protocol::RevealToken>,
    ) -> Result<(), String> {
        let mut gs = self.state.write().await;
        if let Some(table) = gs.tables.get_mut(&table_id) {
            table.submit_player_reveal_tokens(pk_hex, tokens)
        } else {
            Err("Table not found".to_string())
        }
    }

    pub async fn get_reveal_phase_for_table(&self, table_id: u32) -> Option<crate::pokergame::game_state::RevealPhase> {
        let gs = self.state.read().await;
        gs.tables.get(&table_id).map(|t| t.reveal_token_state.phase)
    }
}

pub(crate) fn hide_opponent_cards(base: &ClientTable, wallet_address: &WalletAddress) -> ClientTable {
    let mut copy = base.clone();
    let hidden_card = Card { suit: "hidden".to_string(), rank: "hidden".to_string() };
    let hidden_hand = vec![hidden_card.clone(), hidden_card];

    let cards_dealt = !matches!(
        copy.round_state,
        RoundState::Waiting | RoundState::Shuffling | RoundState::ShuffleComplete | RoundState::HandComplete
    );

    for seat in copy.seats.values_mut() {
        let is_opponent = seat.player.as_ref().map_or(true, |p| &p.wallet_address != wallet_address);
        let is_winner_showdown = seat.last_action.as_deref() == Some(actions::WINNER) && copy.went_to_showdown;

        if is_opponent && !is_winner_showdown {
            if seat.hand.len() > 0 {
                seat.hand = hidden_hand.clone();
            } else if cards_dealt && !seat.folded && !seat.sitting_out && seat.player.is_some() {
                seat.hand = hidden_hand.clone();
            }
        }
    }
    copy
}

pub(crate) async fn send_simple_action(socket: &SocketRef, state: &Arc<SocketState>, table_id: u32, action: &str) {
    let socket_id = socket.id.to_string();
    let pk_hex = {
        let gs = state.state.read().await;
        gs.players.get(&socket_id)
            .and_then(|p| gs.tables.get(&table_id).and_then(|t| t.get_pk_hex_by_wallet_address(&p.wallet_address.0)))
    };
    if let (Some(pk_hex), Some(sender)) = (pk_hex, state.get_action_sender(table_id).await) {
        let _ = sender.send(ActionRequest { pk_hex, action: action.to_string(), amount: None }).await;
    }
}
