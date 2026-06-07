use futures_util::FutureExt;
use parking_lot::RwLock;
use rust_socketio::asynchronous::Client;
use rust_socketio::{asynchronous::ClientBuilder, Payload};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

const SERVER_URL: &str = "http://localhost:9001";
const CONNECT_TIMEOUT_SECS: u64 = 10;
const MAX_RECONNECT_ATTEMPTS: u32 = 3;
const RECONNECT_DELAY_SECS: u64 = 2;

pub mod actions {
    pub const FETCH_LOBBY_INFO: &str = "FETCH_LOBBY_INFO";
    pub const RECEIVE_LOBBY_INFO: &str = "RECEIVE_LOBBY_INFO";
    pub const PLAYERS_UPDATED: &str = "PLAYERS_UPDATED";
    pub const JOIN_TABLE: &str = "JOIN_TABLE";
    pub const TABLE_JOINED: &str = "TABLE_JOINED";
    pub const LEAVE_TABLE: &str = "LEAVE_TABLE";
    pub const TABLE_LEFT: &str = "TABLE_LEFT";
    pub const TABLES_UPDATED: &str = "TABLES_UPDATED";
    pub const TABLE_UPDATED: &str = "TABLE_UPDATED";
    pub const TABLE_MESSAGE: &str = "TABLE_MESSAGE";
    pub const FOLD: &str = "FOLD";
    pub const CHECK: &str = "CHECK";
    pub const CALL: &str = "CALL";
    pub const RAISE: &str = "RAISE";
    pub const SIT_DOWN: &str = "SIT_DOWN";
    pub const REBUY: &str = "REBUY";
    pub const SITTING_OUT: &str = "SITTING_OUT";
    pub const SITTING_IN: &str = "SITTING_IN";
    pub const SHUFFLE_SUBMIT: &str = "SHUFFLE_SUBMIT";
    pub const SHUFFLE_NOTICE: &str = "SHUFFLE_NOTICE";
    pub const REVEAL_SUBMIT: &str = "REVEAL_SUBMIT";
    pub const REVEAL_NOTICE: &str = "REVEAL_NOTICE";
    pub const EXPEL_INITIATE: &str = "EXPEL_INITIATE";
    pub const EXPEL_VOTE: &str = "EXPEL_VOTE";
    pub const EXPEL_FORCE: &str = "EXPEL_FORCE";
    pub const EXPEL_RESULT: &str = "EXPEL_RESULT";
    pub const HAND_REVEAL_RESULT: &str = "HAND_REVEAL_RESULT";
    pub const COMMUNITY_REVEAL_RESULT: &str = "COMMUNITY_REVEAL_RESULT";
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ClientTable {
    pub id: u32,
    pub name: String,
    pub limit: u64,
    pub max_players: u32,
    pub players: Vec<PlayerInfo>,
    pub seats: std::collections::HashMap<u32, Option<ClientSeat>>,
    pub board: Vec<CardInfo>,
    pub deck: Option<EncryptedDeckInfo>,
    pub button: Option<u32>,
    pub turn: Option<u32>,
    pub pot: u64,
    pub main_pot: u64,
    pub call_amount: Option<u64>,
    pub min_bet: u64,
    pub min_raise: u64,
    pub small_blind: Option<u32>,
    pub big_blind: Option<u32>,
    pub hand_over: bool,
    pub win_messages: Vec<String>,
    pub went_to_showdown: bool,
    pub side_pots: Vec<SidePotInfo>,
    pub history: Vec<serde_json::Value>,
    pub round_state: String,
    pub shuffle_state: Option<ShufflePublicStateInfo>,
    pub reveal_token_state: Option<RevealTokenPublicStateInfo>,
    pub expel_state: Option<ExpelPublicStateInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlayerInfo {
    pub socket_id: String,
    pub id: String,
    pub name: String,
    pub pk_hex: Option<String>,
    pub bankroll: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientSeat {
    pub id: u32,
    pub player: Option<PlayerInfo>,
    pub buyin: u64,
    pub stack: u64,
    pub hand: Vec<CardInfo>,
    pub bet: u64,
    pub turn: bool,
    pub checked: bool,
    pub folded: bool,
    pub last_action: Option<String>,
    pub sitting_out: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CardInfo {
    pub suit: String,
    pub rank: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedDeckInfo {
    pub cards: Vec<ElGamalCiphertextInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElGamalCiphertextInfo {
    pub c1_hex: String,
    pub c2_hex: String,
}

impl ElGamalCiphertextInfo {
    pub fn to_ciphertext(&self) -> Result<poker_protocol::crypto::ElGamalCiphertext, String> {
        Ok(poker_protocol::crypto::ElGamalCiphertext {
            c1: hex_to_ecpoint(&self.c1_hex)?,
            c2: hex_to_ecpoint(&self.c2_hex)?,
        })
    }
}

fn hex_to_ecpoint(hex_str: &str) -> Result<poker_protocol::crypto::EcPoint, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("Hex decode error: {}", e))?;
    curve25519_dalek::ristretto::CompressedRistretto::from_slice(&bytes)
        .map_err(|e| format!("Invalid compressed point: {}", e))?
        .decompress()
        .ok_or("Invalid EC point".to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SidePotInfo {
    pub amount: u64,
    pub eligible_players: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShufflePublicStateInfo {
    pub is_active: bool,
    pub current_player_pk: Option<String>,
    pub completed_players: Vec<String>,
    pub pending_players: Vec<String>,
    pub deck_encrypted: Vec<ElGamalCiphertextInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevealTokenPublicStateInfo {
    pub is_active: bool,
    pub phase: String,
    pub completed_players: Vec<String>,
    pub pending_players: Vec<String>,
    pub player_assignments: std::collections::HashMap<String, PlayerRevealAssignmentInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlayerRevealAssignmentInfo {
    pub hand_card: Vec<ElGamalCiphertextInfo>,
    pub community_card: Vec<ElGamalCiphertextInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExpelPublicStateInfo {
    pub is_active: bool,
    pub phase: String,
    pub target_player_pk: Option<String>,
    pub initiator_pk: Option<String>,
    pub voted_players: Vec<String>,
    pub required_votes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TableUpdatePayload {
    pub table: ClientTable,
    pub message: Option<String>,
    pub from: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShuffleNoticePayload {
    pub table_id: u32,
    pub shuffle_state: Option<ShufflePublicStateInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevealNoticePayload {
    pub table_id: u32,
    pub phase: String,
    pub pending_players: Vec<String>,
    pub completed_players: Vec<String>,
    pub player_assignments: std::collections::HashMap<String, PlayerRevealAssignmentInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HandRevealResultPayload {
    pub table_id: u32,
    pub player_pk: String,
    pub readable_cards: Vec<ElGamalCiphertextInfo>,
    pub deck_plaintext: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExpelResultPayload {
    pub table_id: u32,
    pub target_socket_id: Option<String>,
    pub phase: String,
    pub voted_players: Vec<String>,
    pub required_votes: usize,
    pub expelled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TableSummaryInfo {
    pub id: u32,
    pub name: String,
    pub limit: u64,
    pub max_players: u32,
    pub current_number_players: usize,
    pub small_blind: u64,
    pub big_blind: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LobbyInfoPayload {
    pub tables: Vec<TableSummaryInfo>,
    pub players: Vec<PlayerInfo>,
    pub socket_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SitDownPayload {
    pub table_id: u32,
    pub seat_id: u32,
    pub amount: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RaisePayload {
    pub table_id: u32,
    pub amount: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShuffleSubmitPayload {
    pub table_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevealSubmitPayload {
    pub table_id: u32,
}

#[derive(Debug, Clone)]
pub struct SocketEvent {
    pub event_type: SocketEventType,
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SocketEventType {
    TableUpdated,
    ShuffleNotice,
    RevealNotice,
    HandRevealResult,
    ExpelResult,
    LobbyInfo,
    TablesUpdated,
    PlayersUpdated,
    TableJoined,
    TableLeft,
    Connect,
    Disconnect,
    Error,
}

pub struct SocketClient {
    client: Option<Client>,
    event_rx: tokio::sync::mpsc::UnboundedReceiver<SocketEvent>,
    event_tx: tokio::sync::mpsc::UnboundedSender<SocketEvent>,
    latest_tables: Arc<RwLock<Vec<TableSummaryInfo>>>,
    latest_players: Arc<RwLock<Vec<PlayerInfo>>>,
    socket_id: Arc<RwLock<Option<String>>>,
}

impl SocketClient {
    pub fn new() -> Self {
        let (event_tx, event_rx) = tokio::sync::mpsc::unbounded_channel();
        Self {
            client: None,
            event_rx,
            event_tx,
            latest_tables: Arc::new(RwLock::new(Vec::new())),
            latest_players: Arc::new(RwLock::new(Vec::new())),
            socket_id: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn connect(&mut self, token: &str) -> Result<(), String> {
        let event_tx = self.event_tx.clone();
        let latest_tables = self.latest_tables.clone();
        let latest_players = self.latest_players.clone();
        let socket_id_arc = self.socket_id.clone();

        tracing::info!("[SocketClient] Attempting to connect to {}", SERVER_URL);

        let mut last_err: String;
        let mut attempt = 0u32;

        let client = loop {
            attempt += 1;
            tracing::info!("[SocketClient] Connection attempt {}/{}", attempt, MAX_RECONNECT_ATTEMPTS);

            let event_tx_clone = event_tx.clone();
            let latest_tables_clone = latest_tables.clone();
            let latest_players_clone = latest_players.clone();
            let socket_id_clone = socket_id_arc.clone();

            let callback_table_updated = {
                let tx = event_tx_clone.clone();
                move |payload: Payload, _: Client| {
                    let tx = tx.clone();
                    async move {
                        if let Payload::Text(values) = payload {
                            for v in values {
                                let _ = tx.send(SocketEvent {
                                    event_type: SocketEventType::TableUpdated,
                                    data: v,
                                });
                            }
                        }
                    }
                    .boxed()
                }
            };

            let callback_shuffle_notice = {
                let tx = event_tx_clone.clone();
                move |payload: Payload, _: Client| {
                    let tx = tx.clone();
                    async move {
                        if let Payload::Text(values) = payload {
                            for v in values {
                                let _ = tx.send(SocketEvent {
                                    event_type: SocketEventType::ShuffleNotice,
                                    data: v,
                                });
                            }
                        }
                    }
                    .boxed()
                }
            };

            let callback_reveal_notice = {
                let tx = event_tx_clone.clone();

                move |payload: Payload, _: Client| {
                    let tx = tx.clone();
                    async move {
                        if let Payload::Text(values) = payload {
                            for v in values {
                                let _ = tx.send(SocketEvent {
                                    event_type: SocketEventType::RevealNotice,
                                    data: v,
                                });
                            }
                        }
                    }
                    .boxed()
                }
            };

            let callback_expel_result = {
                let tx = event_tx_clone.clone();
                move |payload: Payload, _: Client| {
                    let tx = tx.clone();
                    async move {
                        if let Payload::Text(values) = payload {
                            for v in values {
                                let _ = tx.send(SocketEvent {
                                    event_type: SocketEventType::ExpelResult,
                                    data: v,
                                });
                            }
                        }
                    }
                    .boxed()
                }
            };

            let callback_lobby_info = {
                let tx = event_tx_clone.clone();
                let sid = socket_id_clone.clone();
                move |payload: Payload, _: Client| {
                    let tx = tx.clone();
                    let sid = sid.clone();
                    async move {
                        if let Payload::Text(values) = payload {
                            for v in values {
                                if let Ok(lobby) = serde_json::from_value::<LobbyInfoPayload>(v.clone()) {
                                    *sid.write() = Some(lobby.socket_id.clone());
                                }
                                let _ = tx.send(SocketEvent {
                                    event_type: SocketEventType::LobbyInfo,
                                    data: v,
                                });
                            }
                        }
                    }
                    .boxed()
                }
            };

            let callback_tables_updated = {
                let tx = event_tx_clone.clone();
                let tables = latest_tables_clone.clone();
                move |payload: Payload, _: Client| {
                    let tx = tx.clone();
                    let tables = tables.clone();
                    async move {
                        if let Payload::Text(values) = payload {
                            for v in values {
                                if let Ok(t) = serde_json::from_value::<Vec<TableSummaryInfo>>(v.clone()) {
                                    *tables.write() = t;
                                }
                                let _ = tx.send(SocketEvent {
                                    event_type: SocketEventType::TablesUpdated,
                                    data: v,
                                });
                            }
                        }
                    }
                    .boxed()
                }
            };

            let callback_hand_reveal_result = {
                let tx = event_tx_clone.clone();
                let players = latest_players_clone.clone();
                move |payload: Payload, _: Client| {
                    let tx = tx.clone();
                    // let players = players.clone();
                    async move {
                        if let Payload::Text(values) = payload {
                            println!("Hand reveal result received: {:?}", values);
                            for value in values {
                                let _ = tx.send(SocketEvent {
                                    event_type: SocketEventType::HandRevealResult,
                                    data: value,
                                });
                            }
                        }
                    }
                    .boxed()
                }
            };

            let callback_community_reveal_result = {
                let tx = event_tx_clone.clone();
                let tables = latest_tables_clone.clone();
                move |payload: Payload, _: Client| {
                    let tx = tx.clone();
                    let tables = tables.clone();
                    async move {
                        if let Payload::Text(values) = payload {
                            println!("Community reveal result received: {:?}", values);
                        }
                    }
                    .boxed()
                }
            };

            let callback_players_updated = {
                let tx = event_tx_clone.clone();
                let players = latest_players_clone.clone();
                move |payload: Payload, _: Client| {
                    let tx = tx.clone();
                    let players = players.clone();
                    async move {
                        if let Payload::Text(values) = payload {
                            for v in values {
                                if let Ok(p) = serde_json::from_value::<Vec<PlayerInfo>>(v.clone()) {
                                    *players.write() = p;
                                }
                                let _ = tx.send(SocketEvent {
                                    event_type: SocketEventType::PlayersUpdated,
                                    data: v,
                                });
                            }
                        }
                    }
                    .boxed()
                }
            };

            let callback_connect = {
                let tx = event_tx_clone.clone();
                move |_payload: Payload, _: Client| {
                    let tx = tx.clone();
                    async move {
                        tracing::info!("[SocketClient] Connected to server");
                        let _ = tx.send(SocketEvent {
                            event_type: SocketEventType::Connect,
                            data: serde_json::Value::Null,
                        });
                    }
                    .boxed()
                }
            };

            let callback_disconnect = move |_payload: Payload, _: Client| {
                async move {
                    tracing::error!("[SocketClient] Disconnected from server");
                }
                .boxed()
            };

            let callback_error = {
                let tx = event_tx_clone.clone();
                move |err: Payload, _: Client| {
                    let tx = tx.clone();
                    async move {
                        tracing::error!("[SocketClient] Error: {:?}", err);
                        let _ = tx.send(SocketEvent {
                            event_type: SocketEventType::Error,
                            data: serde_json::json!({"error": format!("{:?}", err)}),
                        });
                    }
                    .boxed()
                }
            };

            let connect_future = ClientBuilder::new(SERVER_URL)
                .namespace("/")
                .on(actions::TABLE_UPDATED, callback_table_updated)
                .on(actions::SHUFFLE_NOTICE, callback_shuffle_notice)
                .on(actions::REVEAL_NOTICE, callback_reveal_notice)
                .on(actions::EXPEL_RESULT, callback_expel_result)
                .on(actions::RECEIVE_LOBBY_INFO, callback_lobby_info)
                .on(actions::TABLES_UPDATED, callback_tables_updated)
                .on(actions::PLAYERS_UPDATED, callback_players_updated)
                .on(actions::HAND_REVEAL_RESULT, callback_hand_reveal_result)
                .on(actions::COMMUNITY_REVEAL_RESULT, callback_community_reveal_result)
                .on("connect", callback_connect)
                .on("connect_error", callback_error.clone())
                .on("disconnect", callback_disconnect)
                .on("error", callback_error)
                .connect();

            match tokio::time::timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS), connect_future).await {
                Ok(Ok(client)) => {
                    tracing::info!("[SocketClient] Successfully connected on attempt {}", attempt);
                    break client;
                }
                Ok(Err(e)) => {
                    last_err = format!("Socket.IO connection failed: {:?}", e);
                    tracing::warn!("[SocketClient] Connection error on attempt {}: {}", attempt, last_err);
                }
                Err(_) => {
                    last_err = format!("Connection timed out after {}s on attempt {}", CONNECT_TIMEOUT_SECS, attempt);
                    tracing::warn!("[SocketClient] {}", last_err);
                }
            }

            if attempt >= MAX_RECONNECT_ATTEMPTS {
                return Err(format!(
                    "Failed to connect after {} attempts. Last error: {}",
                    MAX_RECONNECT_ATTEMPTS, last_err
                ));
            }

            tracing::info!("[SocketClient] Retrying in {}s...", RECONNECT_DELAY_SECS);
            tokio::time::sleep(Duration::from_secs(RECONNECT_DELAY_SECS)).await;
        };

        tracing::info!("[SocketClient] Connected before sent FETCH_LOBBY_INFO");

        client
            .emit(actions::FETCH_LOBBY_INFO, token.to_string())
            .await
            .map_err(|e| format!("Failed to emit FETCH_LOBBY_INFO: {:?}", e))?;

        tracing::info!("[SocketClient] Connected and sent FETCH_LOBBY_INFO");

        self.client = Some(client);
        Ok(())
    }

    pub async fn emit(&self, event: &str, data: serde_json::Value) -> Result<(), String> {
        if let Some(client) = &self.client {
            client
                .emit(event, data)
                .await
                .map_err(|e| format!("Emit failed: {:?}", e))
        } else {
            Err("Not connected".to_string())
        }
    }

    pub fn recv_event(&mut self) -> Option<SocketEvent> {
        self.event_rx.try_recv().ok()
    }

    pub async fn next_event(&mut self) -> Option<SocketEvent> {
        self.event_rx.recv().await
    }

    pub fn get_socket_id(&self) -> Option<String> {
        self.socket_id.read().clone()
    }

    pub fn get_latest_tables(&self) -> Vec<TableSummaryInfo> {
        self.latest_tables.read().clone()
    }

    pub fn get_latest_players(&self) -> Vec<PlayerInfo> {
        self.latest_players.read().clone()
    }

    pub async fn join_table(&self, table_id: u32) -> Result<(), String> {
        self.emit(actions::JOIN_TABLE, serde_json::json!(table_id)).await
    }

    pub async fn leave_table(&self, table_id: u32) -> Result<(), String> {
        self.emit(actions::LEAVE_TABLE, serde_json::json!(table_id)).await
    }

    pub async fn sit_down(&self, table_id: u32, seat_id: u32, amount: u64) -> Result<(), String> {
        let payload = SitDownPayload { table_id, seat_id, amount };
        self.emit(actions::SIT_DOWN, serde_json::to_value(payload).unwrap()).await
    }

    pub async fn fold(&self, table_id: u32) -> Result<(), String> {
        self.emit(actions::FOLD, serde_json::json!(table_id)).await
    }

    pub async fn check(&self, table_id: u32) -> Result<(), String> {
        self.emit(actions::CHECK, serde_json::json!(table_id)).await
    }

    pub async fn call(&self, table_id: u32) -> Result<(), String> {
        self.emit(actions::CALL, serde_json::json!(table_id)).await
    }

    pub async fn raise(&self, table_id: u32, amount: u64) -> Result<(), String> {
        let payload = RaisePayload { table_id, amount };
        self.emit(actions::RAISE, serde_json::to_value(payload).unwrap()).await
    }

    pub async fn submit_shuffle(&self, table_id: u32) -> Result<(), String> {
        let payload = ShuffleSubmitPayload { table_id };
        self.emit(actions::SHUFFLE_SUBMIT, serde_json::to_value(payload).unwrap()).await
    }

    pub async fn submit_reveal(&self, table_id: u32) -> Result<(), String> {
        let payload = RevealSubmitPayload { table_id };
        self.emit(actions::REVEAL_SUBMIT, serde_json::to_value(payload).unwrap()).await
    }

    pub async fn disconnect(&mut self) {
        if let Some(client) = self.client.take() {
            let _ = client.disconnect().await;
        }
    }
}
