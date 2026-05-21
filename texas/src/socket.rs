use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use socketioxide::{
    extract::{Data, SocketRef, State},
    SocketIo,
};

use crate::auth;
use crate::config::Config;
use crate::models::Database;
use crate::pokergame::actions;
use crate::pokergame::deck::Card;
use crate::pokergame::game_state::{ElGamalCiphertextJson, ExpelPhase, MaskAndShuffleRoundJson, ShuffleProofJson,
    PkProofJson, RevealPhase, ShufflePublicState};
use crate::pokergame::player::Player;
use crate::pokergame::table::{ActionRequest, ClientTable, JoinResult, RoundState, Table};
use poker_protocol::crypto::EcPoint;

fn table_room_name(table_id: u32) -> String {
    format!("table_{}", table_id)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct LobbyInfo {
    tables: Vec<TableSummary>,
    players: Vec<PlayerInfo>,
    socket_id: String,
}

#[derive(Debug, Clone, Serialize)]
struct TableSummary {
    id: u32,
    name: String,
    limit: u64,
    max_players: u32,
    current_number_players: usize,
    small_blind: u64,
    big_blind: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PlayerInfo {
    socket_id: String,
    id: String,
    name: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TableLeftPayload {
    tables: Vec<TableSummary>,
    table_id: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TableUpdatePayload {
    table: ClientTable,
    message: Option<String>,
    from: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RaisePayload {
    table_id: u32,
    amount: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TableMessagePayload {
    message: String,
    from: String,
    table_id: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SitDownPayload {
    table_id: u32,
    seat_id: u32,
    amount: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SitDownV2Payload {
    table_id: u32,
    seat_id: u32,
    amount: u64,
    pk_hex: String,
    pk_proof: PkProofJson,
    mask_and_shuffle_round: MaskAndShuffleRoundJson,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RebuyPayload {
    table_id: u32,
    seat_id: u32,
    amount: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SittingPayload {
    table_id: u32,
    seat_id: u32,
}

#[derive(Debug, Clone, Deserialize)]
struct ShuffleSubmitPayload {
    table_id: u32,
    pk_hex: String,
    output_cards: Vec<ElGamalCiphertextJson>,
    shuffle_proof: ShuffleProofJson,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RevealSubmitPayload {
    table_id: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HandRevealPayload {
    readable_cards: Vec<ElGamalCiphertextJson>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct HandRevealResultPayload {
    table_id: u32,
    player_pk: String,
    readable_cards: Vec<ElGamalCiphertextJson>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct CommunityRevealResultPayload {
    table_id: u32,
    community_cards: Vec<Card>,
}



#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExpelInitiatePayload {
    table_id: u32,
    target_socket_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExpelVotePayload {
    table_id: u32,
    vote: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExpelForcePayload {
    table_id: u32,
    target_socket_id: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ShuffleNoticePayload {
    table_id: u32,
    shuffle_state: Option<ShufflePublicState>,
}

#[derive(Debug, Clone, Serialize)]
struct RevealNoticePayload {
    table_id: u32,
    phase: RevealPhase,
    pending_players: Vec<String>,
    completed_players: Vec<String>,
    player_assignments: HashMap<String, crate::pokergame::game_state::PlayerRevealAssignment>,
}

#[derive(Debug, Clone, Serialize)]
struct ExpelNoticePayload {
    table_id: u32,
    phase: ExpelPhase,
    completed_players: Vec<String>,
    pending_players: Vec<String>,
    expel_deck: Vec<ElGamalCiphertextJson>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExpelResultPayload {
    table_id: u32,
    phase: ExpelPhase,
    completed_players: Vec<String>,
    expelled: bool,
}

struct GameLoopEntry {
    _handle: tokio::task::JoinHandle<()>,
    action_sender: tokio::sync::mpsc::Sender<ActionRequest>,
    stop_sender: tokio::sync::watch::Sender<bool>,
}

struct GameLoopRegistry {
    entries: HashMap<u32, GameLoopEntry>,
}

impl GameLoopRegistry {
    fn new() -> Self {
        Self { entries: HashMap::new() }
    }

    fn contains(&self, table_id: u32) -> bool {
        self.entries.contains_key(&table_id)
    }

    fn get_sender(&self, table_id: u32) -> Option<tokio::sync::mpsc::Sender<ActionRequest>> {
        self.entries.get(&table_id).map(|e| e.action_sender.clone())
    }

    fn insert(&mut self, table_id: u32, entry: GameLoopEntry) {
        self.entries.insert(table_id, entry);
    }

    fn remove(&mut self, table_id: u32) {
        if let Some(entry) = self.entries.remove(&table_id) {
            let _ = entry.stop_sender.send(true);
        }
    }
}

static SOCKET_IO: OnceLock<SocketIo> = OnceLock::new();

pub fn set_socket_io(io: SocketIo) {
    let _ = SOCKET_IO.set(io);
}

struct GameState {
    tables: HashMap<u32, Table>,
    players: HashMap<String, Player>,
    disconnect_cancellers: HashMap<String, tokio::sync::watch::Sender<bool>>,
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

    fn get_current_tables(&self) -> Vec<TableSummary> {
        let gs = self.state.read().unwrap();
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

    fn get_current_players(&self) -> Vec<PlayerInfo> {
        let gs = self.state.read().unwrap();
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
        let registry = self.game_loop_registry.read().unwrap();
        registry.get_sender(table_id)
    }

    pub async fn start_game_loop(&self, io: SocketIo, state: Arc<SocketState>, table_id: u32) {
        {
            let registry = self.game_loop_registry.read().unwrap();
            if registry.contains(table_id) {
                return;
            }
        }
        let (tx, rx) = tokio::sync::mpsc::channel::<ActionRequest>(100);
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let handle = tokio::spawn(game_loop_task(io, state, table_id, rx, stop_rx));
        let mut registry = self.game_loop_registry.write().unwrap();
        registry.insert(table_id, GameLoopEntry {
            _handle: handle,
            action_sender: tx,
            stop_sender: stop_tx,
        });
    }

    pub fn start_game_loop_sync(&self, state: Arc<SocketState>, table_id: u32) {
        let Some(io) = SOCKET_IO.get().cloned() else {
            tracing::warn!("[start_game_loop_sync] SocketIo not initialized");
            return;
        };
        {
            let registry = self.game_loop_registry.read().unwrap();
            if registry.contains(table_id) {
                return;
            }
        }
        let (tx, rx) = tokio::sync::mpsc::channel::<ActionRequest>(100);
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let handle = tokio::spawn(game_loop_task(io, state, table_id, rx, stop_rx));
        let mut registry = self.game_loop_registry.write().unwrap();
        registry.insert(table_id, GameLoopEntry {
            _handle: handle,
            action_sender: tx,
            stop_sender: stop_tx,
        });
    }

    pub async fn stop_game_loop(&self, table_id: u32) {
        tracing::info!("stop_game_loop: {}", table_id);
        let mut registry = self.game_loop_registry.write().unwrap();
        registry.remove(table_id);
    }
    
    pub fn find_socket_id_by_pk(&self, pk_hex: &str) -> Option<String> {
        let gs = self.state.read().unwrap();
        gs.players.values()
            .find(|p| p.pk_hex == pk_hex)
            .map(|p| p.socket_id.clone())
    }

    pub fn is_player_in_seat(&self, pk_hex: &str) -> bool {
        let gs = self.state.read().unwrap();
        gs.tables.values().any(|table| {
            table.seats.values().any(|seat_opt| {
                seat_opt.as_ref().map_or(false, |seat| {
                    seat.player.as_ref().map_or(false, |p| p.pk_hex == pk_hex)
                })
            })
        })
    }

    pub fn find_player_by_pk(&self, pk_hex: &str) -> Option<Player> {
        let gs = self.state.read().unwrap();
        gs.players.values()
            .find(|p| p.pk_hex == pk_hex)
            .cloned()
    }

    pub fn find_table_id_by_pk(&self, pk_hex: &str) -> Option<u32> {
        let gs = self.state.read().unwrap();
        for (table_id, table) in &gs.tables {
            if table.players.iter().any(|p| p.pk_hex == pk_hex) {
                return Some(*table_id);
            }
        }
        None
    }

    pub fn get_client_table(&self, table_id: u32) -> Option<ClientTable> {
        let gs = self.state.read().unwrap();
        gs.tables.get(&table_id).map(|t| t.to_client())
    }

    pub fn add_player_to_table(&self, table_id: u32, player: Player) -> Result<usize, String> {
        let mut gs = self.state.write().unwrap();
        gs.players.insert(player.socket_id.clone(), player.clone());
        if let Some(table) = gs.tables.get_mut(&table_id) {
            table.add_player(player);
            Ok(table.active_players().len())
        } else {
            Err("Table not found".to_string())
        }
    }

    pub fn join_player_and_shuffle(
        &self,
        table_id: u32,
        player: Player,
        player_pk: EcPoint,
        pk_proof_json: PkProofJson,
        round_json: MaskAndShuffleRoundJson,
        seat_id: u32,
        amount: u64,
    ) -> Result<(bool, JoinResult), String> {
        let socket_id = player.socket_id.clone();
        let pk_hex = player.pk_hex.clone();

        let result = {
            let mut gs = self.state.write().unwrap();
            if let Some(table) = gs.tables.get_mut(&table_id) {
                table.join_player_and_shuffle(player, player_pk, pk_proof_json, round_json, seat_id, amount)
            } else {
                Err("Table not found".to_string())
            }
        };

        match &result {
            Ok(JoinResult::JoinedAndShuffled) => {
                let mut gs = self.state.write().unwrap();
                let already_exists = gs.players.values().any(|p| p.pk_hex == pk_hex);
                if !already_exists {
                    gs.players.insert(socket_id.clone(), Player {
                        socket_id: socket_id.clone(),
                        id: pk_hex.clone(),
                        name: pk_hex.clone(),
                        bankroll: 0,
                        pk_hex: pk_hex.clone(),
                        readable_hands: Vec::new(),
                    });
                }

                if let Some(table) = gs.tables.get_mut(&table_id) {
                    if table.is_pending_shuffle_palyer_empty() && table.complete_shuffle_palyer_count() >= 2 {
                        table.shuffle_state.is_active = false;
                        table.round_state = RoundState::ShuffleComplete;
                        tracing::info!("[SHUFFLE] Player {} joined and shuffled, all players shuffled", pk_hex);
                        return Ok((true, JoinResult::JoinedAndShuffled));
                    } else {
                        tracing::info!("[SHUFFLE] Player {} joined and shuffled, but not enough players to start", pk_hex);
                        table.complete_or_continue_next_shuffler();
                    }
                }
                Ok((false, JoinResult::JoinedAndShuffled))
            }
            Ok(JoinResult::JoinedWaiting) => {
                let mut gs = self.state.write().unwrap();
                let already_exists = gs.players.values().any(|p| p.pk_hex == pk_hex);
                if !already_exists {
                    gs.players.insert(socket_id.clone(), Player {
                        socket_id: socket_id.clone(),
                        id: pk_hex.clone(),
                        name: pk_hex.clone(),
                        bankroll: 0,
                        pk_hex: pk_hex.clone(),
                        readable_hands: Vec::new(),
                    });
                }
                Ok((false, JoinResult::JoinedWaiting))
            }
            Err(e) => Err(e.clone()),
        }
    }

    pub fn submit_verified_shuffle_with_round(
        &self,
        table_id: u32,
        pk_hex: &str,
        round_json: MaskAndShuffleRoundJson,
    ) -> Result<(), String> {
        let mut gs = self.state.write().unwrap();
        if let Some(table) = gs.tables.get_mut(&table_id) {
            match table.submit_verified_shuffle(pk_hex, round_json.output_cards, round_json.shuffle_proof) {
                Ok(()) => {
                    if table.is_all_players_shuffled() && table.complete_shuffle_palyer_count() >= 2 {
                        table.shuffle_state.is_active = false;
                        table.round_state = RoundState::ShuffleComplete;
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

    pub fn submit_verified_shuffle_for_pk(
        &self,
        table_id: u32,
        pk_hex: &str,
        player: Player,
        output_cards: Vec<ElGamalCiphertextJson>,
        shuffle_proof: ShuffleProofJson,
    ) -> Result<(), String> {
        let mut gs = self.state.write().unwrap();
        if let Some(table) = gs.tables.get_mut(&table_id) {
            match table.submit_verified_shuffle(pk_hex, output_cards, shuffle_proof) {
                Ok(()) => {
                    if table.is_all_players_shuffled() && table.complete_shuffle_palyer_count() >= 2 {
                        table.shuffle_state.is_active = false;
                        table.round_state = RoundState::ShuffleComplete;
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

    pub fn mark_reveal_complete_for_pk(&self, table_id: u32, pk_hex: &str) -> Result<bool, String> {
        let mut gs = self.state.write().unwrap();
        if let Some(table) = gs.tables.get_mut(&table_id) {
            Ok(table.mark_player_reveal_complete(pk_hex))
        } else {
            Err("Table not found".to_string())
        }
    }

    pub fn submit_reveal_tokens_for_pk(
        &self,
        table_id: u32,
        pk_hex: &str,
        tokens: Vec<poker_protocol::z_poker::protocol::RevealToken>,
    ) -> Result<(), String> {
        let mut gs = self.state.write().unwrap();
        if let Some(table) = gs.tables.get_mut(&table_id) {
            table.submit_player_reveal_tokens(pk_hex, tokens)
        } else {
            Err("Table not found".to_string())
        }
    }

    pub fn get_reveal_phase_for_table(&self, table_id: u32) -> Option<crate::pokergame::game_state::RevealPhase> {
        let gs = self.state.read().unwrap();
        gs.tables.get(&table_id).map(|t| t.reveal_token_state.phase)
    }

    pub fn get_player_readable_cards(&self, table_id: u32) -> Option<HashMap<String, Vec<poker_protocol::crypto::ElGamalCiphertext>>> {
        let gs = self.state.read().unwrap();
        gs.tables.get(&table_id).map(|table| {
            table.mental_poker_game.get_player_readable_tokens()
        })
    }

    pub fn broadcast_hand_reveal_result(&self, table_id: u32) {
        let io = match SOCKET_IO.get() {
            Some(io) => io.clone(),
            None => {
                tracing::warn!("[broadcast_hand_reveal_result] SocketIo not initialized");
                return;
            }
        };

        let (player_cards, socket_id_map) = {
            let gs = self.state.read().unwrap();
            let table = match gs.tables.get(&table_id) {
                Some(t) => t,
                None => return,
            };
            let player_cards = table.mental_poker_game.get_player_readable_tokens();
            let socket_id_map: HashMap<String, String> = table.players.iter()
                .filter_map(|p| {
                    gs.players.get(&p.socket_id).map(|player| (player.pk_hex.clone(), p.socket_id.clone()))
                })
                .collect();
            (player_cards, socket_id_map)
        };

        for (player_pk, cards) in player_cards {
            println!("Player {} revealed cards: {:?}", player_pk, socket_id_map);
            let socket_id = match socket_id_map.get(&player_pk) {
                Some(s) => s,
                None => continue,
            };
            let readable_cards: Vec<ElGamalCiphertextJson> = cards.iter()
                .map(|c| ElGamalCiphertextJson::from_ciphertext(c))
                .collect();
            let payload = HandRevealResultPayload {
                table_id,
                player_pk: player_pk.clone(),
                readable_cards,
            };
            if let Ok(sid) = socket_id.parse::<socketioxide::socket::Sid>() {
                if let Some(socket) = io.get_socket(sid) {
                    println!("[broadcast_hand_reveal_result] socket  found for player {}, socket_id={}", player_pk, socket_id);
                    let _ = socket.emit(actions::HAND_REVEAL_RESULT, &payload);
                }else{
                    println!("[broadcast_hand_reveal_result] socket not found for player {}, socket_id={}", player_pk, socket_id);
                }
            }else{
                println!("[broadcast_hand_reveal_result] socket_id {} is not a valid sid", socket_id);
            }
        }
    }

    pub async fn broadcast_showdown_result(self: &Arc<Self>, table_id: u32) {
        let io = match SOCKET_IO.get() {
            Some(io) => io.clone(),
            None => {
                tracing::warn!("[broadcast_showdown_result] SocketIo not initialized");
                return;
            }
        };

        {
            let mut gs = self.state.write().unwrap();
            if let Some(table) = gs.tables.get_mut(&table_id) {
                let (player_revealed_map, _) = table.mental_poker_game.list_revealed_cards();
                
                for seat_opt in table.seats.values_mut() {
                    if let Some(seat) = seat_opt {
                        if let Some(player) = &seat.player {
                            if let Some(revealed_cards) = player_revealed_map.get(&player.pk_hex) {
                                if  revealed_cards.len() >= 2 {
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
        }
        broadcast_to_table(&io, self, table_id, None).await;
    }

    
    pub fn broadcast_community_cards(&self, table_id: u32) {
        let io = match SOCKET_IO.get() {
            Some(io) => io.clone(),
            None => {
                tracing::warn!("[broadcast_community_cards] SocketIo not initialized");
                return;
            }
        };

        let community_cards = {
            let gs = self.state.read().unwrap();
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
        let _ = io.to(table_room_name(table_id)).emit(actions::COMMUNITY_REVEAL_RESULT, &payload);
    }

    pub fn register_http_player(&self, socket_id: String, player: Player) {
        let mut gs = self.state.write().unwrap();
        gs.players.insert(socket_id, player);
    }
}

fn hide_opponent_cards(table: &Table, socket_id: &str) -> ClientTable {
    let mut copy = table.to_client();
    let hidden_card = Card { suit: "hidden".to_string(), rank: "hidden".to_string() };
    let hidden_hand = vec![hidden_card.clone(), hidden_card];

    for seat_opt in copy.seats.values_mut() {
        if let Some(seat) = seat_opt {
            if seat.hand.len() > 0
                && seat.player.as_ref().map_or(true, |p| p.socket_id != socket_id)
                && !(seat.last_action.as_deref() == Some(actions::WINNER) && copy.went_to_showdown)
            {
                seat.hand = hidden_hand.clone();
            }
        }
    }
    copy
}

async fn broadcast_to_table(io: &SocketIo, state: &Arc<SocketState>, table_id: u32, message: Option<&str>) {
    let socket_ids = {
        let gs = state.state.read().unwrap();
        let Some(table) = gs.tables.get(&table_id) else { return };
        table.players.iter().map(|p| p.socket_id.clone()).collect::<Vec<_>>()
    };

    for sid_str in socket_ids {
        let table_view = {
            let gs = state.state.read().unwrap();
            match gs.tables.get(&table_id) {
                Some(t) => hide_opponent_cards(t, &sid_str),
                None => continue,
            }
        };
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

async fn game_loop_task(io: SocketIo, state: Arc<SocketState>, table_id: u32, mut action_rx: tokio::sync::mpsc::Receiver<ActionRequest>, mut stop_rx: tokio::sync::watch::Receiver<bool>) {
    tracing::info!("[GAME-LOOP] Started for table {}", table_id);
    let mut ticker = tokio::time::interval(tokio::time::Duration::from_millis(500));
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if !process_tick(&io, &state, table_id).await {
                    tracing::info!("[GAME-LOOP] Table {} process_tick signaled stop", table_id);
                    break;
                }
            }
            action = action_rx.recv() => {
                match action {
                    Some(req) => {
                        tracing::debug!("[GAME-LOOP] Table {} received action: {} from {}", table_id, req.action, req.socket_id);
                        process_action(&io, &state, table_id, req).await;
                    }
                    None => {
                        tracing::info!("[GAME-LOOP] Channel closed for table {}", table_id);
                        break;
                    }
                }
            }
            _ = stop_rx.changed() => {
                tracing::info!("[GAME-LOOP] Stop signal received for table {}", table_id);
                break;
            }
        };
    }

    {
        let mut registry = state.game_loop_registry.write().unwrap();
        registry.remove(table_id);
    }
    tracing::info!("[GAME-LOOP] Stopped for table {}", table_id);
}

async fn handle_interrupts(io: &SocketIo, state: &Arc<SocketState>, table_id: u32, expel_active: bool, shuffle_active: bool, reveal_active: bool) -> Option<bool> {
    if expel_active {
        let expel_result = {
            let mut gs = state.state.write().unwrap();
            if let Some(table) = gs.tables.get_mut(&table_id) {
                if table.execute_expel_if_completed() {
                    Some(true)
                } else if let Some(_timed_out) = table.check_expel_timeout() {
                    Some(false)
                } else {
                    None
                }
            } else { None }
        };
        if let Some(expelled) = expel_result {
            if expelled {
                broadcast_to_table(io, state, table_id, Some("Player expelled by vote")).await;
            } else {
                broadcast_to_table(io, state, table_id, Some("Expel vote timed out")).await;
            }
            return Some(true);
        }
    }

    if shuffle_active {
        let shuffle_complete = {
            let gs = state.state.read().unwrap();
            gs.tables.get(&table_id).map(|t| t.is_all_players_shuffled()).unwrap_or(false)
        };
        if shuffle_complete {
            {
                let mut gs = state.state.write().unwrap();
                if let Some(table) = gs.tables.get_mut(&table_id) {
                    table.shuffle_state.reset();
                    table.round_state = RoundState::ShuffleComplete;
                    tracing::info!("[ShuffleComplete] Table {} shuffle complete", table_id);
                }
            }
            return Some(true);
        }
        let timeout_result = {
            let mut gs = state.state.write().unwrap();
            if let Some(table) = gs.tables.get_mut(&table_id) {
                table.check_shuffle_timeout()
            } else { None }
        };
        if let Some(timed_out_pk) = timeout_result {
            tracing::info!("[TICK] Table {} shuffle timeout for player {}", table_id, timed_out_pk);
            let should_stop_early = {
                let mut gs = state.state.write().unwrap();
                if let Some(socket_id) = gs.players.values().find(|p| p.pk_hex == timed_out_pk).map(|p| p.socket_id.clone()) {
                    gs.players.remove(&socket_id);
                }

                let should_stop = if let Some(table) = gs.tables.get_mut(&table_id) {
                    table.shuffle_state.pending_players.retain(|pk| *pk != timed_out_pk);
                    table.remove_player_by_pk(&timed_out_pk);

                    if table.active_players().len() < 2 {
                        table.round_state = RoundState::Waiting;
                        table.shuffle_state.is_active = false;
                        true
                    } else {
                        false
                    }
                } else { false };

                if !should_stop {
                    if let Some(table) = gs.tables.get_mut(&table_id) {
                        table.complete_or_continue_next_shuffler();
                    }
                }
                should_stop
            };
            if should_stop_early {
                return Some(true);
            }
            let shuffle_notice_data = {
                let gs = state.state.read().unwrap();
                if let Some(table) = gs.tables.get(&table_id) {
                    let shuffle_state = table.get_shuffle_public_state();
                    let current_pk = table.shuffle_state.current_player_pk.clone();
                    
                    let socket_id = if let Some(pk) = &current_pk {
                        gs.players.values().find(|p| p.pk_hex == *pk).map(|p| p.socket_id.clone())
                    } else {
                        None
                    };
                    
                    if let (Some(st), Some(sid)) = (shuffle_state, socket_id) {
                        Some((st, sid))
                    } else {
                        None
                    }
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
            broadcast_to_table(io, state, table_id, None).await;
            return Some(true);
        }
    }

    if reveal_active {
        let timeout_result = {
            let mut gs = state.state.write().unwrap();
            if let Some(table) = gs.tables.get_mut(&table_id) {
                table.check_reveal_timeout()
            } else { None }
        };
        if let Some(timed_out_pks) = timeout_result {
            tracing::info!("[TICK] Table {} reveal token timeout for player {:?}", table_id, timed_out_pks);
            {
                let mut gs = state.state.write().unwrap();
                for timed_out_pk in &timed_out_pks {
                    if let Some(socket_id) = gs.players.values().find(|p| p.pk_hex == *timed_out_pk).map(|p| p.socket_id.clone()) {
                        if let Ok(sid) = socket_id.parse::<socketioxide::socket::Sid>() {
                            if let Some(socket) = io.get_socket(sid) {
                                socket.leave(table_room_name(table_id));
                                let _ = socket.emit(actions::TABLE_LEFT, &TableLeftPayload { tables: state.get_current_tables(), table_id });
                            }
                        }
                        gs.players.remove(&socket_id);
                    }
                }
                if let Some(table) = gs.tables.get_mut(&table_id) {
                    for timed_out_pk in timed_out_pks.clone() {
                        table.remove_player_by_pk(&timed_out_pk);
                    }
                    table.start_expel();
                }
            }
            
            let expel_notice = {
                let gs = state.state.read().unwrap();
                gs.tables.get(&table_id).map(|t| {
                    let phase = t.expel_state.phase.clone();
                    let completed_players = t.expel_state.completed_players.clone();
                    let pending_players = t.expel_state.pending_players.clone();
                    let expel_deck = t.expel_state.expel_deck.clone().into_iter().map(|c| c.into()).collect::<Vec<_>>();
                    ExpelNoticePayload { table_id, phase, completed_players, pending_players, expel_deck }
                })
            };
            if let Some(notice) = expel_notice {
                let _ = io.to(table_room_name(table_id)).emit(actions::EXPEL_NOTICE, &notice).await;
            }

            broadcast_to_table(io, state, table_id, Some(&format!("Player  timed out on reveal", ))).await;
            return Some(true);
        }
    }

    if expel_active || shuffle_active || reveal_active {
        Some(true)
    } else {
        None
    }
}

async fn handle_reveal_phase(io: &SocketIo, state: &Arc<SocketState>, table_id: u32, next_state: RoundState, is_preflop: bool) {
    {
        let mut gs = state.state.write().unwrap();
        if let Some(table) = gs.tables.get_mut(&table_id) {
            if table.reveal_token_state.is_active {
                return;
            }
            if next_state == RoundState::Showdown{
                table.start_showdown_reveal_phase();
            }else{
                if is_preflop {
                    table.start_preflop_reveal_phase();
                } else {
                    table.start_community_reveal_phase();
                }
            }
        }else{
            return;
        }
    }
    let reveal_notice = {
        let gs = state.state.read().unwrap();
        gs.tables.get(&table_id).map(|t| {
            let phase = t.reveal_token_state.phase.clone();
            let pending = t.reveal_token_state.pending_players.clone();
            let completed = t.reveal_token_state.completed_players.clone();
            let player_assignments = t.reveal_token_state.player_assignments.clone();
            RevealNoticePayload { table_id, phase, pending_players: pending, completed_players: completed, player_assignments }
        })
    };
    if let Some(notice) = reveal_notice {
        let _ = io.to(table_room_name(table_id)).emit(actions::REVEAL_NOTICE, &notice).await;
    }
    broadcast_to_table(io, state, table_id, None).await;
}

async fn process_tick(io: &SocketIo, state: &Arc<SocketState>, table_id: u32) -> bool {
    let (round_state, active_count, _betting_timeout, hand_complete_at, ready_at, showdown_at,
         shuffle_active, reveal_active, expel_active) = {
        let gs = state.state.read().unwrap();
        if let Some(table) = gs.tables.get(&table_id) {
            (table.round_state, table.active_players().len(), table.betting_timeout_start, table.hand_complete_at, table.ready_at, table.showdown_at,
             table.shuffle_state.is_active, table.reveal_token_state.is_active, table.expel_state.is_active)
        } else { return false }
    };

    if active_count == 0 {
        tracing::info!("[TICK] Table {} has no active players, stopping game loop", table_id);
        return false;
    }

    if let Some(result) = handle_interrupts(io, state, table_id, expel_active, shuffle_active, reveal_active).await {
        return result;
    }

    match round_state {
        RoundState::Waiting => {
            if active_count >= 2 {
                let io_c = io.clone();
                let state_c = state.clone();
                if let Some(ready_at) = ready_at {
                    let elapsed = ready_at.elapsed().as_secs();
                    if elapsed <= 5 {
                        tracing::debug!("[TICK] Table {} Waiting: {} active, ready countdown {}/5s", table_id, active_count, elapsed);
                        return true;
                    }
                    tracing::info!("[TICK] Table {} Waiting → starting hand ({} active)", table_id, active_count);
                    
                    let (shuffle_state, current_pk) = {
                        let mut gs = state_c.state.write().unwrap();
                        if let Some(table) = gs.tables.get_mut(&table_id) {
                            if table.active_players().len() >= 2 {
                                let _ = table.start_shuffle();
                                (table.get_shuffle_public_state(), table.shuffle_state.current_player_pk.clone())
                            } else {
                                (None, None)
                            }
                        } else {
                            (None, None)
                        }
                    };
                    
                    if let (Some(st), Some(pk)) = (shuffle_state, current_pk) {
                        let socket_id = {
                            let gs = state_c.state.read().unwrap();
                            gs.players.values().find(|p| p.pk_hex == pk).map(|p| p.socket_id.clone())
                        };
                        tracing::debug!("[TICK] Table {} ShuffleStarted: shuffle notice to {:?}", table_id, socket_id.clone());
                        if let Some(sid_str) = socket_id {
                            if let Ok(sid) = sid_str.parse::<socketioxide::socket::Sid>() {
                                if let Some(socket) = io.get_socket(sid) {
                                    let notice = ShuffleNoticePayload { table_id, shuffle_state: Some(st) };
                                    let _ = socket.emit(actions::SHUFFLE_NOTICE, &notice);
                                }
                            }
                        }
                    }
                    broadcast_to_table(&io_c, &state_c, table_id, Some("--- New hand started ---")).await;
                } else {
                    tracing::info!("[TICK] Table {} Waiting: setting ready_at, starting 5s countdown", table_id);
                    {
                        let mut gs = state_c.state.write().unwrap();
                        if let Some(table) = gs.tables.get_mut(&table_id) {
                            table.ready_at = Some(std::time::Instant::now());
                        }
                    }
                    broadcast_to_table(io, state, table_id, Some("---New hand starting in 5 seconds---")).await;
                }
            } else {
                tracing::info!("[TICK] Table {} Waiting: only {} active, stopping game loop", table_id, active_count);
                return false;
            }
        }
        RoundState::Shuffling => {
            if active_count < 2 {
                let mut gs = state.state.write().unwrap();
                if let Some(table) = gs.tables.get_mut(&table_id) {
                    table.shuffle_state.is_active = false;
                    table.round_state = RoundState::Waiting;
                }
            }
            let all_shuffled = {
                let gs = state.state.read().unwrap();
                gs.tables.get(&table_id).map(|t| t.is_all_players_shuffled()).unwrap_or(false)
            };
            if all_shuffled {
                let mut gs = state.state.write().unwrap();
                if let Some(table) = gs.tables.get_mut(&table_id) {
                    table.shuffle_state.is_active = false;
                    table.round_state = RoundState::ShuffleComplete;
                }
            }
        }
        RoundState::ShuffleComplete => {
            if active_count < 2 {
                let mut gs = state.state.write().unwrap();
                if let Some(table) = gs.tables.get_mut(&table_id) {
                    table.shuffle_state.is_active = false;
                    table.round_state = RoundState::Waiting;
                }
            }
            tracing::info!("[TICK] Table {} ShuffleComplete, resetting shuffle and starting hand", table_id);
            {
                let mut gs = state.state.write().unwrap();
                if let Some(table) = gs.tables.get_mut(&table_id) {
                    table.reset_shuffle();
                    table.start_hand();
                    //todo 这里使得start_hand会触发PreFlopReveal状态有点混乱
                    table.round_state = RoundState::PreFlopReveal;
                }
            }
            
            broadcast_to_table(io, state, table_id, Some("Shuffle complete, dealing cards")).await;
        }
        RoundState::PreFlopReveal => {
            tracing::info!("[TICK] Table {} PreFlopReveal, starting preflop reveal phase", table_id);
            handle_reveal_phase(io, state, table_id, RoundState::PreFlop, true).await;
        }
        RoundState::FlopReveal => {
            tracing::info!("[TICK] Table {} FlopReveal, starting community reveal phase", table_id);
            handle_reveal_phase(io, state, table_id, RoundState::Flop, false).await;
        }
        RoundState::TurnReveal => {
            tracing::info!("[TICK] Table {} TurnReveal, starting community reveal phase", table_id);
            handle_reveal_phase(io, state, table_id, RoundState::Turn, false).await;
        }
        RoundState::RiverReveal => {
            tracing::info!("[TICK] Table {} RiverReveal, starting community reveal phase", table_id);
            handle_reveal_phase(io, state, table_id, RoundState::River, false).await;
        }
        RoundState::ShowdownReveal => {
            tracing::info!("[TICK] Table {} ShowdownReveal, starting showdown reveal phase", table_id);
            handle_reveal_phase(io, state, table_id, RoundState::Showdown, false).await;
        }
        RoundState::PreFlop | RoundState::Flop | RoundState::Turn | RoundState::River => {
            let timeout_result = {
                let mut gs = state.state.write().unwrap();
                if let Some(table) = gs.tables.get_mut(&table_id) {
                    table.check_betting_timeout(15)
                } else { None }
            };
            if let Some(res) = timeout_result {
                tracing::info!("[TICK] Table {} {:?}: betting timeout → {}", table_id, round_state, res.message);
                broadcast_to_table(io, state, table_id, Some(&res.message)).await;
                handle_turn_advance(io, state, table_id).await;
                return true;
            }

            handle_auto_fold(io, state, table_id).await;

            let is_complete = {
                let gs = state.state.read().unwrap();
                if let Some(table) = gs.tables.get(&table_id) {
                    table.is_betting_round_complete()
                } else { false }
            };

            if is_complete {
                tracing::debug!("[TICK] Table {} {:?}: betting round complete, advancing", table_id, round_state);
                handle_turn_advance(io, state, table_id).await;
            }
        }
        RoundState::Showdown => {
            if let Some(sa) = showdown_at {
                let elapsed = sa.elapsed().as_secs();
                if elapsed >= 3 {
                    tracing::info!("[TICK] Table {} Showdown: 3s elapsed, finishing showdown", table_id);
                    {
                        let mut gs = state.state.write().unwrap();
                        if let Some(table) = gs.tables.get_mut(&table_id) {
                            table.finish_showdown();
                        }
                    }
                    broadcast_to_table(io, state, table_id, None).await;
                } else {
                    tracing::debug!("[TICK] Table {} Showdown: displaying results {}/3s", table_id, elapsed);
                }
            } else {
                tracing::warn!("[TICK] Table {} Showdown: showdown_at is None, finishing immediately", table_id);
                {
                    let mut gs = state.state.write().unwrap();
                    if let Some(table) = gs.tables.get_mut(&table_id) {
                        table.finish_showdown();
                    }
                }
                broadcast_to_table(io, state, table_id, None).await;
            }
        }
        RoundState::HandComplete => {
            if let Some(complete_at) = hand_complete_at {
                let elapsed = complete_at.elapsed().as_secs();
                if elapsed >= 5 {
                    let (active, broke_players) = {
                        let mut gs = state.state.write().unwrap();
                        if let Some(table) = gs.tables.get_mut(&table_id) {
                            let mut broke = Vec::new();
                            for seat_opt in table.seats.values_mut() {
                                if let Some(seat) = seat_opt {
                                    if seat.stack <= 0 {
                                        if let Some(player) = &seat.player {
                                            broke.push((player.id.clone(), player.socket_id.clone()));
                                        }
                                    }
                                }
                            }
                            for b in broke.iter() {
                                tracing::info!("remove_player: {}", b.0);
                                table.remove_player(&b.1);
                            }
                            table.reset_for_next_hand();
                            (table.active_players().len(), broke)
                        } else { (0, Vec::new()) }
                    };

                    let tables_info = state.get_current_tables();
                    let _ = io.emit(actions::TABLES_UPDATED, &tables_info).await;
                    
                    for (_, socket_id) in broke_players.iter() {
                        if let Ok(sid) = socket_id.parse::<socketioxide::socket::Sid>() {
                            if let Some(socket) = io.get_socket(sid) {
                                let _ = socket.emit(actions::TABLE_LEFT, &TableLeftPayload { tables: tables_info.clone(), table_id });
                            }
                        }
                    }

                    for (_, socket_id) in broke_players.iter() {
                        let player_name = {
                            let gs = state.state.read().unwrap();
                            gs.players.get(socket_id).map(|p| p.name.clone())
                        };
                        if let Some(name) = player_name {
                            broadcast_to_table(&io, &state, table_id, Some(&format!("{} left the table (broke).", name))).await;
                        }
                    }

                    tracing::info!("[TICK] Table {} HandComplete: {} active after reset, {} broke players removed", table_id, active, broke_players.len());
                    if active < 2 {
                        broadcast_to_table(io, state, table_id, Some("Waiting for more players")).await;
                        return false;
                    } else {
                        broadcast_to_table(io, state, table_id, None).await;
                    }
                }
            } else {
                tracing::info!("Table {} HandComplete: no active players", table_id);
            }
        }
    }
    true
}



async fn handle_auto_fold(io: &SocketIo, state: &Arc<SocketState>, table_id: u32) {
    let auto_fold = {
        let gs = state.state.read().unwrap();
        if let Some(table) = gs.tables.get(&table_id) {
            if let Some(turn_id) = table.turn {
                table.seats.get(&turn_id)
                    .and_then(|s| s.as_ref())
                    .and_then(|seat| {
                        if seat.disconnected && !seat.folded {
                            seat.player.as_ref().map(|p| p.socket_id.clone())
                        } else {
                            None
                        }
                    })
            } else {
                None
            }
        } else {
            None
        }
    };
    if let Some(socket_id) = auto_fold {
        let fold_result = {
            let mut gs = state.state.write().unwrap();
            if let Some(table) = gs.tables.get_mut(&table_id) {
                table.handle_fold(&socket_id)
            } else {
                None
            }
        };
        if let Some(res) = fold_result {
            broadcast_to_table(io, state, table_id, Some(&res.message)).await;
        }
    }
}

async fn handle_turn_advance(io: &SocketIo, state: &Arc<SocketState>, table_id: u32) {
    let result = {
        let mut gs = state.state.write().unwrap();
        if let Some(table) = gs.tables.get_mut(&table_id) {
            if table.unfolded_players().len() <= 1 {
                table.end_without_showdown();
            } else if table.is_betting_round_complete() {
                if table.round_state == RoundState::River {
                    // todo showdown card reveal
                    table.round_state = RoundState::ShowdownReveal;
                    return ();
                    // table.determine_side_pot_winners();
                    // table.determine_main_pot_winner();
                } else {
                    table.advance_to_next_phase();
                    table.turn = Some(table.next_unfolded_player(table.button.unwrap_or(1), 1));
                    table.betting_timeout_start = Some(std::time::Instant::now());
                    for i in 1..=table.max_players {
                        if let Some(Some(seat)) = table.seats.get_mut(&i) {
                            seat.turn = table.turn == Some(i);
                        }
                    }
                }
            } else {
                let last_turn = table.turn.unwrap_or(1);
                table.turn = Some(table.next_unfolded_player(last_turn, 1));
                table.betting_timeout_start = Some(std::time::Instant::now());
                for i in 1..=table.max_players {
                    if let Some(Some(seat)) = table.seats.get_mut(&i) {
                        seat.turn = table.turn == Some(i);
                    }
                }
            }
            Some(())
        } else { None }
    };
    if result.is_some() {
        broadcast_to_table(io, state, table_id, None).await;
    }
}

async fn process_action(io: &SocketIo, state: &Arc<SocketState>, table_id: u32, req: ActionRequest) {
    let result = {
        let mut gs = state.state.write().unwrap();
        if let Some(table) = gs.tables.get_mut(&table_id) {
            for seat_opt in table.seats.values_mut() {
                if let Some(seat) = seat_opt {
                    if seat.player.as_ref().map_or(false, |p| p.socket_id == req.socket_id) {
                        seat.sitting_out = false;
                    }
                }
            }
            match req.action.as_str() {
                "fold" => table.handle_fold(&req.socket_id),
                "check" => table.handle_check(&req.socket_id),
                "call" => table.handle_call(&req.socket_id),
                "raise" => table.handle_raise(&req.socket_id, req.amount.unwrap_or(0)),
                _ => None,
            }
        } else { None }
    };
    if let Some(res) = result {
        broadcast_to_table(io, state, table_id, Some(&res.message)).await;
        handle_turn_advance(io, state, table_id).await;
    }
}

async fn clear_for_one_player(io: &SocketIo, state: Arc<SocketState>, table_id: u32) {
    {
        let mut gs = state.state.write().unwrap();
        if let Some(table) = gs.tables.get_mut(&table_id) {
            table.clear_win_messages();
        }
    }

    let io_c = io.clone();
    let state_c = state;

    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        {
            let mut gs = state_c.state.write().unwrap();
            if let Some(table) = gs.tables.get_mut(&table_id) {
                table.clear_seat_hands();
                table.reset_board_and_pot();
            }
        }

        broadcast_to_table(&io_c, &state_c, table_id, Some("Waiting for more players")).await;
    });
}


pub fn register_handlers(io: &SocketIo) {
    io.ns("/", async move |socket: SocketRef, io: SocketIo, State(state): State<Arc<SocketState>>| {
        on_connect(socket, io, state);
    });
}

fn on_connect(socket: SocketRef, _io: SocketIo, _state: Arc<SocketState>) {
    socket.on(actions::FETCH_LOBBY_INFO, async move |s: SocketRef, Data::<String>(token), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let claims = match auth::verify_token(&token, &state.config.jwt_secret) {
            Ok(c) => c,
            Err(_) => return,
        };
        tracing::info!("on_connect FETCH_LOBBY_INFO: {}", claims.user.id.clone());
        let new_socket_id = s.id.to_string();
        let user_id = claims.user.id.clone();

        let old_sid = {
            let gs = state.state.read().unwrap();
            gs.tables.values().find_map(|t| t.find_disconnected_socket_by_user_id(&user_id))
        };
        tracing::info!("on_connect FETCH_LOBBY_INFO: {} old_sid={:?}", claims.user.id.clone(), old_sid.clone());

        // 这个替换seat里面的player
        let (table_ids_to_broadcast, is_reconnect) = if let Some(old) = old_sid {
            tracing::info!("[RECONNECT] user {} found disconnected seat, old_sid={}, new_sid={}", user_id, old, new_socket_id);
            {
                let mut gs = state.state.write().unwrap();
                if let Some(cancel_tx) = gs.disconnect_cancellers.remove(&old) {
                    let _ = cancel_tx.send(true);
                }
            }
            let reconnected_table_ids = {
                let mut gs = state.state.write().unwrap();
                let mut ids = Vec::new();
                for table in gs.tables.values_mut() {
                    if table.reconnect_player(&old, &new_socket_id) {
                        ids.push(table.id);
                    }
                }
                ids
            };

            let db_user = state.db.find_user_by_id(&user_id).await;
            if let Some(user) = db_user {
                let mut gs = state.state.write().unwrap();
                gs.players.insert(new_socket_id.clone(), Player {
                    socket_id: new_socket_id.clone(),
                    id: user.id,
                    name: user.name,
                    bankroll: user.chips_amount,
                    pk_hex: user.pk_hex,
                    readable_hands: Vec::new(),
                });
                gs.players.remove(&old);
            }

            (reconnected_table_ids, true)
        }else{
            (Vec::new(), false)
        }; 

        // 这个替换players里面的player
        {
            let old_sid_from_players = {
                let gs = state.state.read().unwrap();
                gs.players.values().find(|p| p.id == user_id).map(|p| p.socket_id.clone())
            };
            tracing::info!("on_connect FETCH_LOBBY_INFO: {} old_sid_from_players={:?}", claims.user.id.clone(), old_sid_from_players.clone());

            if let Some(ref old) = old_sid_from_players {
                tracing::info!("[RECONNECT] user {} found active session in players, replacing old_sid={}", user_id, old);
                let mut gs = state.state.write().unwrap();
                if let Some(cancel_tx) = gs.disconnect_cancellers.remove(old) {
                    let _ = cancel_tx.send(true);
                }
                gs.players.remove(old);
                for table in gs.tables.values_mut() {
                    table.reconnect_player(old, &new_socket_id);
                }
                (Vec::<u32>::new(), true)
            } else {
                (Vec::<u32>::new(), false)
            }
        };
        tracing::info!("on_connect FETCH_LOBBY_INFO: {}", claims.user.id.clone());


        for tid in &table_ids_to_broadcast {
            broadcast_to_table(&io, &state, *tid, None).await;
        }

        if !is_reconnect {
            let db_user = state.db.find_user_by_id(&claims.user.id).await;
            if let Some(user) = db_user {
                tracing::info!("on_connect FETCH_LOBBY_INFO: {} user={:?}", claims.user.id.clone(), user);
                state.state.write().unwrap().players.insert(s.id.to_string(), Player {
                    socket_id: s.id.to_string(),
                    id: user.id,
                    name: user.name,
                    pk_hex: user.pk_hex,
                    bankroll: user.chips_amount,
                    readable_hands: Vec::new(),
                });
            }
        }

        let lobby = LobbyInfo {
            tables: state.get_current_tables(),
            players: state.get_current_players(),
            socket_id: s.id.to_string(),
        };
        let _ = s.emit(actions::RECEIVE_LOBBY_INFO, &lobby);
        let players_info = state.get_current_players();
        let _ = io.emit(actions::PLAYERS_UPDATED, &players_info).await;
    });

    socket.on(actions::JOIN_TABLE, async move |s: SocketRef, Data::<u32>(table_id), io: SocketIo, State(state): State<Arc<SocketState>>| {
        s.join(table_room_name(table_id));
        let socket_id = s.id.to_string();
        let join_msg = {
            let mut gs = state.state.write().unwrap();

            let player_data = gs.players.get(&socket_id).map(|p| (p.clone(), p.name.clone()));

            if let Some(table) = gs.tables.get_mut(&table_id) {
                if let Some((player_clone, player_name)) = player_data {
                    table.add_player(player_clone);
                    tracing::info!("add_player: {}", socket_id);
                    Some(format!("{} joined the table.", player_name))
                } else { None }
            } else { None }
        };

        let tables_info = state.get_current_tables();
        {
            let gs = state.state.read().unwrap();
            if let Some(table) = gs.tables.get(&table_id) {
                let table_view = hide_opponent_cards(table, &socket_id);
                let _ = s.emit(actions::TABLE_JOINED, &TableUpdatePayload {
                    table: table_view,
                    message: join_msg.clone(),
                    from: None,
                });
            }
        }
        let _ = io.emit(actions::TABLES_UPDATED, &tables_info).await;
        if let Some(msg) = join_msg {
            broadcast_to_table(&io, &state, table_id, Some(&msg)).await;
        }
    });

    socket.on(actions::LEAVE_TABLE, async move |s: SocketRef, Data::<u32>(table_id), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let socket_id = s.id.to_string();

        let (is_playing, player_name) = {
            let gs = state.state.read().unwrap();
            if let Some(table) = gs.tables.get(&table_id) {
                let name = table.find_player_by_socket_id(&socket_id)
                    .and_then(|_| gs.players.get(&socket_id).map(|p| p.name.clone()));
                (table.is_playing(), name)
            } else { (false, None) }
        };

        if is_playing {
            tracing::info!("[LEAVE_TABLE] Table {}: {} is leaving while hand is in progress, marking sitting_out", table_id, socket_id);
            {
                let mut gs = state.state.write().unwrap();
                if let Some(table) = gs.tables.get_mut(&table_id) {
                    for seat_opt in table.seats.values_mut() {
                        if let Some(seat) = seat_opt {
                            if seat.player.as_ref().map_or(false, |p| p.socket_id == socket_id) {
                                seat.sitting_out = true;
                            }
                        }
                    }
                }
            }
            let msg = player_name.map(|n| format!("{} is sitting out.", n));
            broadcast_to_table(&io, &state, table_id, msg.as_deref()).await;
            return;
        }
        s.leave(table_room_name(table_id));

        let chips_update = {
            let gs = state.state.read().unwrap();
            if let Some(table) = gs.tables.get(&table_id) {
                table.find_player_by_socket_id(&socket_id)
                    .and_then(|seat| {
                        gs.players.get(&socket_id).map(|p| (p.id.clone(), seat.stack))
                    })
            } else { None }
        };

        if let Some((pid, stack)) = chips_update {
            let _ = state.db.update_chips(&pid, stack as i64).await;
        }

        let (leave_msg, need_clear) = {
            let mut guard = state.state.write().unwrap();
            let gs = &mut *guard;
            let name = gs.players.get(&socket_id).map(|p| p.name.clone());
            if let Some(table) = gs.tables.get_mut(&table_id) {
                tracing::info!("remove_player: {}", socket_id);
                table.remove_player(&socket_id);
                let msg = name.map(|n| format!("{} left the table.", n));
                let clear = table.active_players().len() == 1;
                (msg, clear)
            } else { (None, false) }
        };

        let tables_info = state.get_current_tables();
        let _ = io.emit(actions::TABLES_UPDATED, &tables_info).await;
        let _ = s.emit(actions::TABLE_LEFT, &TableLeftPayload { tables: tables_info, table_id });

        if let Some(msg) = &leave_msg {
            broadcast_to_table(&io, &state, table_id, Some(msg)).await;
        }

        if need_clear {
            state.stop_game_loop(table_id).await;
            clear_for_one_player(&io, state.clone(), table_id).await;
        }
    });

    socket.on(actions::FOLD, async move |s: SocketRef, Data::<u32>(table_id), _io: SocketIo, State(state): State<Arc<SocketState>>| {
        let socket_id = s.id.to_string();
        if let Some(sender) = state.get_action_sender(table_id).await {
            let _ = sender.send(ActionRequest { socket_id, action: "fold".to_string(), amount: None }).await;
        }
    });

    socket.on(actions::CHECK, async move |s: SocketRef, Data::<u32>(table_id), _io: SocketIo, State(state): State<Arc<SocketState>>| {
        let socket_id = s.id.to_string();
        tracing::info!("Action CHECK: {}", table_id);
        if let Some(sender) = state.get_action_sender(table_id).await {
            let _ = sender.send(ActionRequest { socket_id, action: "check".to_string(), amount: None }).await;
        }
    });

    socket.on(actions::CALL, async move |s: SocketRef, Data::<u32>(table_id), _io: SocketIo, State(state): State<Arc<SocketState>>| {
        let socket_id = s.id.to_string();
        if let Some(sender) = state.get_action_sender(table_id).await {
            let _ = sender.send(ActionRequest { socket_id, action: "call".to_string(), amount: None }).await;
        }
    });

    socket.on(actions::RAISE, async move |s: SocketRef, Data::<RaisePayload>(payload), _io: SocketIo, State(state): State<Arc<SocketState>>| {
        let socket_id = s.id.to_string();
        if let Some(sender) = state.get_action_sender(payload.table_id).await {
            let _ = sender.send(ActionRequest { socket_id, action: "raise".to_string(), amount: Some(payload.amount) }).await;
        }
    });

    socket.on(actions::TABLE_MESSAGE, async move |_s: SocketRef, Data::<TableMessagePayload>(payload), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let socket_ids = {
            let gs = state.state.read().unwrap();
            gs.tables.get(&payload.table_id).map(|t| {
                t.players.iter().map(|p| p.socket_id.clone()).collect::<Vec<_>>()
            })
        };

        if let Some(sids) = socket_ids {
            for sid_str in sids {
                let table_view = {
                    let gs = state.state.read().unwrap();
                    gs.tables.get(&payload.table_id).map(|t| hide_opponent_cards(t, &sid_str))
                };
                if let Some(table_view) = table_view {
                    let update = TableUpdatePayload {
                        table: table_view,
                        message: Some(payload.message.clone()),
                        from: Some(payload.from.clone()),
                    };
                    if let Ok(sid) = sid_str.parse::<socketioxide::socket::Sid>() {
                        if let Some(socket) = io.get_socket(sid) {
                            let _ = socket.emit(actions::TABLE_UPDATED, &update);
                        }
                    }
                }
            }
        }
    });

    socket.on(actions::SIT_DOWN, async move |s: SocketRef, Data::<SitDownPayload>(payload), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let socket_id = s.id.to_string();
        tracing::info!("sit down msg getinfo: {:?}", payload);

        let (should_start, chips_deduct, sit_msg) = {
            let mut guard = state.state.write().unwrap();
            let gs = &mut *guard;

            let player_data = gs.players.get(&socket_id).map(|p| (p.clone(), p.name.clone(), p.id.clone()));

            if let Some(table) = gs.tables.get_mut(&payload.table_id) {
                if let Some((player_clone, player_name, player_id)) = player_data {
                    table.add_player(player_clone.clone());
                    table.sit_player(player_clone, payload.seat_id, payload.amount);

                    let msg = format!("{} sat down in Seat {}", player_name, payload.seat_id);

                    (table.active_players().len() == 2, Some((player_id, payload.amount)), Some(msg))
                } else { (false, None, None) }
            } else { (false, None, None) }
        };
        tracing::info!("sit down msg before: {:?}", sit_msg);
        if let Some((pid, amount)) = chips_deduct {
            let _ = state.db.update_chips(&pid, -(amount as i64)).await;
        }
        tracing::info!("sit down msg after: {:?}", sit_msg);
        if let Some(msg) = &sit_msg {
            tracing::info!("sit down msg: {}", msg);
            broadcast_to_table(&io, &state, payload.table_id, Some(msg)).await;
        }

        if should_start {
            state.start_game_loop(io, state.clone(), payload.table_id).await;
        }
    });

    socket.on(actions::SIT_DOWN_V2, async move |s: SocketRef, Data::<SitDownV2Payload>(payload), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let socket_id = s.id.to_string();
        tracing::info!("[SIT_DOWN_V2] Received from {}: table_id={}, seat_id={}, amount={}, pk_hex={}", 
            socket_id, payload.table_id, payload.seat_id, payload.amount, payload.pk_hex);

        let player_pk = match crate::pokergame::game_state::hex_to_ecpoint(&payload.pk_hex) {
            Ok(pk) => pk,
            Err(e) => {
                tracing::warn!("[SIT_DOWN_V2] Invalid pk_hex: {}", e);
                return;
            }
        };

        let player = {
            let gs = state.state.read().unwrap();
            gs.players.get(&socket_id).cloned()
        };

        let player = match player {
            Some(p) => p,
            None => {
                tracing::warn!("[SIT_DOWN_V2] Player not found for socket_id: {}", socket_id);
                return;
            }
        };

        let player_for_join = Player {
            socket_id: socket_id.clone(),
            id: payload.pk_hex.clone(),
            name: player.name.clone(),
            bankroll: payload.amount as i64,
            pk_hex: payload.pk_hex.clone(),
            readable_hands: Vec::new(),
        };

        let result = state.join_player_and_shuffle(
            payload.table_id,
            player_for_join,
            player_pk,
            payload.pk_proof,
            payload.mask_and_shuffle_round,
            payload.seat_id,
            payload.amount,
        );

        match result {
            Ok((all_complete, join_result)) => {
                let _ = state.db.update_chips(&player.id, -(payload.amount as i64)).await;
                
                let msg = match join_result {
                    JoinResult::JoinedAndShuffled => format!("{} sat down in Seat {} and shuffled", player.name, payload.seat_id),
                    JoinResult::JoinedWaiting => format!("{} sat down in Seat {}, waiting for next hand", player.name, payload.seat_id),
                };
                broadcast_to_table(&io, &state, payload.table_id, Some(&msg)).await;

                if all_complete {
                    tracing::info!("[SIT_DOWN_V2] All players shuffled, starting game loop for table {}", payload.table_id);
                    state.start_game_loop(io, state.clone(), payload.table_id).await;
                }
            }
            Err(e) => {
                tracing::warn!("[SIT_DOWN_V2] Failed to join and shuffle: {}", e);
            }
        }
    });

    socket.on(actions::REBUY, async move |s: SocketRef, Data::<RebuyPayload>(payload), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let socket_id = s.id.to_string();
        let chips_deduct = {
            let mut gs = state.state.write().unwrap();

            if let Some(table) = gs.tables.get_mut(&payload.table_id) {
                table.rebuy_player(payload.seat_id, payload.amount);
                gs.players.get(&socket_id).map(|p| p.id.clone())
            } else { None }
        };

        if let Some(pid) = chips_deduct {
            let _ = state.db.update_chips(&pid, -(payload.amount as i64)).await;
        }

        broadcast_to_table(&io, &state, payload.table_id, None).await;
    });

    socket.on(actions::STAND_UP, async move |s: SocketRef, Data::<u32>(table_id), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let socket_id = s.id.to_string();

        let (is_playing, player_name) = {
            let gs = state.state.read().unwrap();
            if let Some(table) = gs.tables.get(&table_id) {
                (table.is_playing(), table.find_player_by_socket_id(&socket_id)
                    .and_then(|seat| seat.player.as_ref().map(|p| p.name.clone())))
            } else { (false, None) }
        };

        if is_playing {
            tracing::info!("[STAND_UP] Table {}: {} standing up while hand in progress, marking sitting_out", table_id, socket_id);
            {
                let mut gs = state.state.write().unwrap();
                if let Some(table) = gs.tables.get_mut(&table_id) {
                    for seat_opt in table.seats.values_mut() {
                        if let Some(seat) = seat_opt {
                            if seat.player.as_ref().map_or(false, |p| p.socket_id == socket_id) {
                                seat.sitting_out = true;
                            }
                        }
                    }
                }
            }
            broadcast_to_table(&io, &state, table_id, player_name.map(|n| format!("{} is sitting out.", n)).as_deref()).await;
            return;
        }

        let chips_return = {
            let gs = state.state.read().unwrap();
            if let Some(table) = gs.tables.get(&table_id) {
                table.find_player_by_socket_id(&socket_id)
                    .and_then(|seat| {
                        gs.players.get(&socket_id).map(|p| (p.id.clone(), seat.stack))
                    })
            } else { None }
        };

        if let Some((pid, stack)) = chips_return {
            let _ = state.db.update_chips(&pid, stack as i64).await;
        }

        let (stand_msg, need_clear) = {
            let mut gs = state.state.write().unwrap();
            if let Some(table) = gs.tables.get_mut(&table_id) {
                let msg = table.find_player_by_socket_id(&socket_id)
                    .and_then(|seat| {
                        seat.player.as_ref().map(|p| format!("{} left the table", p.name))
                    });
                tracing::info!("stand up stand_player: {}", socket_id);
                table.stand_player(&socket_id);
                let clear = table.active_players().len() == 1;
                (msg, clear)
            } else { (None, false) }
        };

        broadcast_to_table(&io, &state, table_id, stand_msg.as_deref()).await;

        if need_clear {
            state.stop_game_loop(table_id).await;
            clear_for_one_player(&io, state, table_id).await;
        }
    });

    socket.on(actions::SITTING_OUT, async move |_s: SocketRef, Data::<SittingPayload>(payload), io: SocketIo, State(state): State<Arc<SocketState>>| {
        {
            let mut gs = state.state.write().unwrap();
            if let Some(table) = gs.tables.get_mut(&payload.table_id) {
                if let Some(Some(seat)) = table.seats.get_mut(&payload.seat_id) {
                    seat.sitting_out = true;
                }
            }
        }
        broadcast_to_table(&io, &state, payload.table_id, None).await;
    });

    socket.on(actions::SITTING_IN, async move |_s: SocketRef, Data::<SittingPayload>(payload), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let should_start = {
            let mut gs = state.state.write().unwrap();
            if let Some(table) = gs.tables.get_mut(&payload.table_id) {
                if let Some(Some(seat)) = table.seats.get_mut(&payload.seat_id) {
                    seat.sitting_out = false;
                }
                table.hand_over && table.active_players().len() == 2
            } else { false }
        };

        broadcast_to_table(&io, &state, payload.table_id, None).await;

        if should_start {
            state.start_game_loop(io, state.clone(), payload.table_id).await;
        }
    });

    socket.on(actions::SHUFFLE_SUBMIT, async move |s: SocketRef, Data::<serde_json::Value>(data), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let socket_id = s.id.to_string();
        let payload: Result<ShuffleSubmitPayload, _> = serde_json::from_value(data.clone());
        match payload {
            Ok(payload) => {
                let socket_id = s.id.to_string();
                tracing::debug!("[SHUFFLE_SUBMIT] request received, pk_hex={}, table_id={}", payload.pk_hex, payload.table_id);

                let player = {
                    let gs = state.state.read().unwrap();
                    gs.players.get(&socket_id).cloned()
                };

                let player = match player {
                    Some(p) => p,
                    None => {
                        tracing::warn!("[SIT_DOWN_V2] Player not found for socket_id: {}", socket_id);
                        return;
                    }
                };
                
                let result = state.submit_verified_shuffle_for_pk(payload.table_id, &payload.pk_hex,player, payload.output_cards.clone(), payload.shuffle_proof.clone());

                match result {
                    Ok(()) => {
                        tracing::debug!("[SHUFFLE_SUBMIT] shuffle submitted and verified, pk_hex={}, table_id={}", payload.pk_hex, payload.table_id);
                        let is_active_and_next_player = {
                            let gs = state.state.read().unwrap();
                            if let Some(table) = gs.tables.get(&payload.table_id) {
                                if table.shuffle_state.is_active {
                                    let current_pk = table.shuffle_state.current_player_pk.clone();
                                    let socket_id = current_pk.and_then(|pk| {
                                        gs.players.values().find(|p| p.pk_hex == pk).map(|p| p.socket_id.clone())
                                    });
                                    socket_id.map(|sid| (table.get_shuffle_public_state(), sid))
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        };
                        
                        if let Some((Some(shuffle_state), socket_id)) = is_active_and_next_player {
                            if let Ok(sid) = socket_id.parse::<socketioxide::socket::Sid>() {
                                if let Some(socket) = io.get_socket(sid) {
                                    let notice = ShuffleNoticePayload { 
                                        table_id: payload.table_id, 
                                        shuffle_state: Some(shuffle_state) 
                                    };
                                    let _ = socket.emit(actions::SHUFFLE_NOTICE, &notice);
                                }
                            }
                        }
                        
                        broadcast_to_table(&io, &state, payload.table_id, None).await;
                    }
                    Err(e) => {
                        tracing::warn!("[SHUFFLE_SUBMIT] shuffle verification failed, pk_hex={}, table_id={}, error={}", payload.pk_hex, payload.table_id, e);
                    }
                }
            }
            Err(e) => {
                tracing::error!("[SHUFFLE_SUBMIT] Failed to parse payload: {}, raw: {:?}", e, data);
            }
        }
    });

    

    socket.on(actions::REVEAL_SUBMIT, async move |s: SocketRef, Data::<RevealSubmitPayload>(payload), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let socket_id = s.id.to_string();
        let result = {
            let mut gs = state.state.write().unwrap();
            let player = gs.players.get(&socket_id).cloned();
            if let Some(player) = gs.players.get(&socket_id){
                Some(player.pk_hex.clone())
            } else {
                None
            }
        };
        if result.is_none() {
            tracing::warn!("[REVEAL_SUBMIT] Player {} not found", socket_id);
            return;
        }
        let pk_hex = result.unwrap();
        let all_complete = {
            let mut gs = state.state.write().unwrap();
            if let Some(table) = gs.tables.get_mut(&payload.table_id) {
                table.mark_player_reveal_complete(pk_hex.as_str())
            } else {
                false
            }
        };
        if all_complete {
            tracing::info!("[REVEAL_SUBMIT] All players completed reveal for table {}", payload.table_id);
        }
        broadcast_to_table(&io, &state, payload.table_id, None).await;
    });

    socket.on(actions::EXPEL_INITIATE, async move |s: SocketRef, Data::<ExpelInitiatePayload>(payload), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let socket_id = s.id.to_string();
        let result = {
            let mut gs = state.state.write().unwrap();
            if let Some(table) = gs.tables.get_mut(&payload.table_id) {
                table.start_expel()
            } else {
                Err("Table not found".to_string())
            }
        };

        match result {
            Ok(()) => {
                let expel_payload = {
                    let gs = state.state.read().unwrap();
                    gs.tables.get(&payload.table_id).map(|t| ExpelResultPayload {
                        table_id: payload.table_id,
                        phase: t.expel_state.phase,
                        completed_players: t.expel_state.completed_players.clone(),
                        expelled: false,
                    })
                };
                if let Some(p) = expel_payload {
                    let _ = io.to(table_room_name(payload.table_id)).emit(actions::EXPEL_RESULT, &p).await;
                }
                broadcast_to_table(&io, &state, payload.table_id, Some("Expel vote initiated")).await;
            }
            Err(e) => {
                tracing::warn!("[EXPEL_INITIATE] Failed: {}", e);
            }
        }
    });

    socket.on(actions::EXPEL_VOTE, async move |s: SocketRef, Data::<ExpelVotePayload>(payload), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let socket_id = s.id.to_string();
        let result = {
            let mut gs = state.state.write().unwrap();
            if let Some(table) = gs.tables.get_mut(&payload.table_id) {
                table.vote_expel(&socket_id, payload.vote)
            } else {
                Err("Table not found".to_string())
            }
        };

        match result {
            Ok(phase) => {
                let expel_payload = {
                    let gs = state.state.read().unwrap();
                    gs.tables.get(&payload.table_id).map(|t| ExpelResultPayload {
                        table_id: payload.table_id,
                        phase,
                        completed_players: t.expel_state.completed_players.clone(),
                        expelled: phase == ExpelPhase::Completed,
                    })
                };
                if let Some(p) = expel_payload {
                    let _ = io.to(table_room_name(payload.table_id)).emit(actions::EXPEL_RESULT, &p).await;
                }
                broadcast_to_table(&io, &state, payload.table_id, None).await;
            }
            Err(e) => {
                tracing::warn!("[EXPEL_VOTE] Failed: {}", e);
            }
        }
    });

    socket.on(actions::EXPEL_FORCE, async move |_s: SocketRef, Data::<ExpelForcePayload>(payload), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let result = {
            let mut gs = state.state.write().unwrap();
            if let Some(table) = gs.tables.get_mut(&payload.table_id) {
                table.force_expel(&payload.target_socket_id)
            } else {
                Err("Table not found".to_string())
            }
        };

        match result {
            Ok(()) => {
                let expel_payload = ExpelResultPayload {
                    table_id: payload.table_id,
                    phase: ExpelPhase::Forced,
                    completed_players: vec![],
                    expelled: true,
                };
                let _ = io.to(table_room_name(payload.table_id)).emit(actions::EXPEL_RESULT, &expel_payload).await;
                broadcast_to_table(&io, &state, payload.table_id, Some("Player forcefully expelled")).await;
            }
            Err(e) => {
                tracing::warn!("[EXPEL_FORCE] Failed: {}", e);
            }
        }
    });

    socket.on_disconnect(async move |s: SocketRef, io: SocketIo, State(state): State<Arc<SocketState>>| {
        let socket_id = s.id.to_string();
        let (auto_fold_table_ids, user_id, affected_table_ids, need_cleanup): (Vec<u32>, Option<String>, Vec<u32>, bool) = {
            let mut gs = state.state.write().unwrap();

            let uid = gs.players.get(&socket_id).map(|p| p.id.clone());
            let mut fold_tables = Vec::new();
            let mut affected = Vec::new();
            let mut should_cleanup = false;

            for (table_id, table) in gs.tables.iter_mut() {
                if table.find_player_by_socket_id(&socket_id).is_none() {
                    continue;
                }
                if table.is_playing() {
                    tracing::info!("[DISCONNECT] Table {}: {} disconnecting while hand in progress, marking sitting_out", table_id, socket_id);
                    for seat_opt in table.seats.values_mut() {
                        if let Some(seat) = seat_opt {
                            if seat.player.as_ref().map_or(false, |p| p.socket_id == socket_id) {
                                seat.sitting_out = true;
                            }
                        }
                    }
                    affected.push(*table_id);
                } else {
                    if table.mark_player_disconnected(&socket_id).is_some() {
                        fold_tables.push(*table_id);
                    }
                    if table.is_player_disconnected(&socket_id) {
                        affected.push(*table_id);
                    }
                    should_cleanup = true;
                }
            }

            (fold_tables, uid, affected, should_cleanup)
        };

        for table_id in &auto_fold_table_ids {
            broadcast_to_table(&io, &state, *table_id, Some("auto-folds (disconnected)")).await;
            handle_turn_advance(&io, &state, *table_id).await;
        }

        for tid in &affected_table_ids {
            broadcast_to_table(&io, &state, *tid, None).await;
        }

        let tables_info = state.get_current_tables();
        let players_info = state.get_current_players();
        let _ = io.emit(actions::TABLES_UPDATED, &tables_info).await;
        let _ = io.emit(actions::PLAYERS_UPDATED, &players_info).await;

        // if need_cleanup {
        //     if let Some(ref uid) = user_id {
        //         schedule_disconnect_cleanup(io, state, uid.clone(), socket_id);
        //     }
        // }
    });
}
