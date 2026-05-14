use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use socketioxide::{
    extract::{Data, SocketRef, State},
    SocketIo,
};
use tokio::sync::Mutex;

use crate::auth;
use crate::config::Config;
use crate::models::Database;
use crate::pokergame::actions;
use crate::pokergame::deck::Card;
use crate::pokergame::player::Player;
use crate::pokergame::table::{ActionResult, Table};

#[derive(Debug, Clone, Serialize)]
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
struct PlayerInfo {
    socket_id: String,
    id: String,
    name: String,
}

#[derive(Debug, Clone, Serialize)]
struct TableJoinedPayload {
    tables: Vec<TableSummary>,
    table_id: u32,
}

#[derive(Debug, Clone, Serialize)]
struct TableLeftPayload {
    tables: Vec<TableSummary>,
    table_id: u32,
}

#[derive(Debug, Clone, Serialize)]
struct TableUpdatePayload {
    table: Table,
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

pub struct SocketState {
    pub db: Database,
    pub tables: Mutex<HashMap<u32, Table>>,
    pub players: Mutex<HashMap<String, Player>>,
    pub config: Config,
}

impl SocketState {
    pub fn new(db: Database, tables: HashMap<u32, Table>, config: Config) -> Self {
        Self {
            db,
            tables: Mutex::new(tables),
            players: Mutex::new(HashMap::new()),
            config,
        }
    }

    async fn get_current_tables(&self) -> Vec<TableSummary> {
        let tables = self.tables.lock().await;
        tables
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

    async fn get_current_players(&self) -> Vec<PlayerInfo> {
        let players = self.players.lock().await;
        players
            .values()
            .map(|p| PlayerInfo {
                socket_id: p.socket_id.clone(),
                id: p.id.clone(),
                name: p.name.clone(),
            })
            .collect()
    }
}

fn hide_opponent_cards(table: &Table, socket_id: &str) -> Table {
    let mut copy = table.clone();
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
    let (table, socket_ids) = {
        let tables = state.tables.lock().await;
        let Some(table) = tables.get(&table_id) else { return };
        let table = table.clone();
        let socket_ids: Vec<String> = table.players.iter().map(|p| p.socket_id.clone()).collect();
        (table, socket_ids)
    };

    for sid_str in socket_ids {
        let table_view = hide_opponent_cards(&table, &sid_str);
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

fn change_turn_and_broadcast(io: &SocketIo, state: Arc<SocketState>, table_id: u32, seat_id: u32) {
    let io_c = io.clone();
    let state_c = state;

    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let hand_over = {
            let mut tables = state_c.tables.lock().await;
            if let Some(table) = tables.get_mut(&table_id) {
                table.change_turn(seat_id);
                table.hand_over
            } else {
                return;
            }
        };

        broadcast_to_table(&io_c, &state_c, table_id, None).await;

        if hand_over {
            init_new_hand(&io_c, state_c, table_id).await;
            return;
        }

        let auto_fold = {
            let tables = state_c.tables.lock().await;
            if let Some(table) = tables.get(&table_id) {
                if let Some(turn_id) = table.turn {
                    table.seats.get(&turn_id)
                        .and_then(|s| s.as_ref())
                        .and_then(|seat| {
                            if seat.disconnected && !seat.folded {
                                seat.player.as_ref().map(|p| (p.socket_id.clone(), seat.id))
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

        if let Some((socket_id, fold_seat_id)) = auto_fold {
            let fold_result = {
                let mut tables = state_c.tables.lock().await;
                if let Some(table) = tables.get_mut(&table_id) {
                    table.handle_fold(&socket_id)
                } else {
                    None
                }
            };
            if let Some(res) = fold_result {
                broadcast_to_table(&io_c, &state_c, table_id, Some(&res.message)).await;
                change_turn_and_broadcast(&io_c, state_c, table_id, fold_seat_id);
            }
        }
    });
}

async fn init_new_hand(io: &SocketIo, state: Arc<SocketState>, table_id: u32) {
    let should_start = {
        let tables = state.tables.lock().await;
        tables.get(&table_id).map_or(0, |t| t.active_players().len())
    };

    if should_start > 1 {
        let io_c = io.clone();
        let state_c = state.clone();
        tokio::spawn(async move {
            broadcast_to_table(&io_c, &state_c, table_id, Some("---New hand starting in 5 seconds---")).await;
        });
    }

    let io_c = io.clone();
    let state_c = state;

    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        {
            let mut tables = state_c.tables.lock().await;
            if let Some(table) = tables.get_mut(&table_id) {
                table.clear_win_messages();
                table.start_hand();
            }
        }

        broadcast_to_table(&io_c, &state_c, table_id, Some("--- New hand started ---")).await;
    });
}

async fn clear_for_one_player(io: &SocketIo, state: Arc<SocketState>, table_id: u32) {
    {
        let mut tables = state.tables.lock().await;
        if let Some(table) = tables.get_mut(&table_id) {
            table.clear_win_messages();
        }
    }

    let io_c = io.clone();
    let state_c = state;

    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        {
            let mut tables = state_c.tables.lock().await;
            if let Some(table) = tables.get_mut(&table_id) {
                table.clear_seat_hands();
                table.reset_board_and_pot();
            }
        }

        broadcast_to_table(&io_c, &state_c, table_id, Some("Waiting for more players")).await;
    });
}

fn schedule_disconnect_cleanup(io: SocketIo, state: Arc<SocketState>, user_id: String, socket_id: String) {
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let (chips_returns, affected_table_ids): (Vec<(String, i64)>, Vec<u32>) = {
            let mut players = state.players.lock().await;
            let mut tables = state.tables.lock().await;

            let mut updates = Vec::new();
            let mut affected = Vec::new();
            for (table_id, table) in tables.iter_mut() {
                let should_remove = table.seats.values()
                    .filter_map(|s| s.as_ref())
                    .any(|s| {
                        s.player.as_ref().map_or(false, |p| p.socket_id == socket_id)
                            && s.disconnected
                            && s.disconnected_at.map_or(true, |t| now - t >= 60)
                    });

                if should_remove {
                    if let Some(seat) = table.find_player_by_socket_id(&socket_id) {
                        if let Some(player) = players.get(&socket_id) {
                            updates.push((player.id.clone(), seat.stack as i64));
                        }
                    }
                    table.remove_player(&socket_id);
                    affected.push(*table_id);
                }
            }

            if !updates.is_empty() {
                players.remove(&socket_id);
            }

            (updates, affected)
        };

        for (pid, stack) in chips_returns {
            let _ = state.db.update_chips(&pid, stack).await;
        }

        for tid in &affected_table_ids {
            broadcast_to_table(&io, &state, *tid, None).await;
        }

        if !affected_table_ids.is_empty() {
            let tables_info = state.get_current_tables().await;
            let players_info = state.get_current_players().await;
            let _ = io.emit(actions::TABLES_UPDATED, &tables_info).await;
            let _ = io.emit(actions::PLAYERS_UPDATED, &players_info).await;
        }

        let _ = user_id;
    });
}

pub fn register_handlers(io: &SocketIo) {
    io.ns("/", async move |socket: SocketRef, io: SocketIo, State(state): State<Arc<SocketState>>| {
        tracing::info!("Socket connected: {}", socket.id);
        on_connect(socket, io, state);
    });
}

fn on_connect(socket: SocketRef, _io: SocketIo, _state: Arc<SocketState>) {
    tracing::info!("Socket connected: {}", socket.id);

    socket.on(actions::FETCH_LOBBY_INFO, async move |s: SocketRef, Data::<String>(token), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let claims = match auth::verify_token(&token, &state.config.jwt_secret) {
            Ok(c) => c,
            Err(_) => return,
        };

        let old_sid = {
            let players = state.players.lock().await;
            players.values().find(|p| p.id == claims.user.id).map(|p| p.socket_id.clone())
        };

        let (table_ids_to_broadcast, is_reconnect) = if let Some(ref old) = old_sid {
            let is_disconnected = {
                let tables = state.tables.lock().await;
                tables.values().any(|t| t.is_player_disconnected(old))
            };

            if is_disconnected {
                let new_socket_id = s.id.to_string();
                let mut tables = state.tables.lock().await;
                let mut reconnected_table_ids = Vec::new();
                for table in tables.values_mut() {
                    if table.reconnect_player(old, &new_socket_id) {
                        reconnected_table_ids.push(table.id);
                    }
                }
                let mut players = state.players.lock().await;
                if let Some(old_player) = players.remove(old) {
                    players.insert(new_socket_id.clone(), Player {
                        socket_id: new_socket_id,
                        id: old_player.id,
                        name: old_player.name,
                        bankroll: old_player.bankroll,
                    });
                }
                (reconnected_table_ids, true)
            } else {
                state.players.lock().await.remove(old);
                let mut tables = state.tables.lock().await;
                for table in tables.values_mut() {
                    table.remove_player(old);
                }
                let ids: Vec<u32> = tables.keys().cloned().collect();
                drop(tables);
                (ids, false)
            }
        } else {
            (Vec::new(), false)
        };

        for tid in &table_ids_to_broadcast {
            broadcast_to_table(&io, &state, *tid, None).await;
        }

        if !is_reconnect {
            let db_user = state.db.find_user_by_id(&claims.user.id).await;
            if let Some(user) = db_user {
                state.players.lock().await.insert(s.id.to_string(), Player {
                    socket_id: s.id.to_string(),
                    id: user.id,
                    name: user.name,
                    bankroll: user.chips_amount,
                });
            }
        }

        let lobby = LobbyInfo {
            tables: state.get_current_tables().await,
            players: state.get_current_players().await,
            socket_id: s.id.to_string(),
        };
        let _ = s.emit(actions::RECEIVE_LOBBY_INFO, &lobby);
        let players_info = state.get_current_players().await;
        let _ = io.emit(actions::PLAYERS_UPDATED, &players_info).await;
    });

    socket.on(actions::JOIN_TABLE, async move |s: SocketRef, Data::<u32>(table_id), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let socket_id = s.id.to_string();
        let join_msg = {
            let players = state.players.lock().await;
            let mut tables = state.tables.lock().await;

            if let Some(table) = tables.get_mut(&table_id) {
                if let Some(player) = players.get(&socket_id) {
                    let player_clone = player.clone();
                    let player_name = player.name.clone();
                    table.add_player(player_clone);
                    Some(format!("{} joined the table.", player_name))
                } else { None }
            } else { None }
        };

        let tables_info = state.get_current_tables().await;
        let _ = s.emit(actions::TABLE_JOINED, &TableJoinedPayload { tables: tables_info.clone(), table_id });
        let _ = io.emit(actions::TABLES_UPDATED, &tables_info).await;
        if let Some(msg) = join_msg {
            broadcast_to_table(&io, &state, table_id, Some(&msg)).await;
        }
    });

    socket.on(actions::LEAVE_TABLE, async move |s: SocketRef, Data::<u32>(table_id), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let socket_id = s.id.to_string();

        let chips_update = {
            let players = state.players.lock().await;
            let tables = state.tables.lock().await;
            if let Some(table) = tables.get(&table_id) {
                table.find_player_by_socket_id(&socket_id)
                    .and_then(|seat| {
                        players.get(&socket_id).map(|p| (p.id.clone(), seat.stack))
                    })
            } else { None }
        };

        if let Some((player_id, stack)) = chips_update {
            let _ = state.db.update_chips(&player_id, stack as i64).await;
        }

        let (leave_msg, need_clear) = {
            let players = state.players.lock().await;
            let mut tables = state.tables.lock().await;
            if let Some(table) = tables.get_mut(&table_id) {
                let player_name = players.get(&socket_id).map(|p| p.name.clone());
                // table.remove_player(&socket_id);
                let has_players = !table.players.is_empty();
                let msg = if has_players {
                    player_name.map(|name| format!("{} left the table.", name))
                } else { None };
                let clear = table.active_players().len() == 1;
                (msg, clear)
            } else { (None, false) }
        };

        let tables_info = state.get_current_tables().await;
        let _ = io.emit(actions::TABLES_UPDATED, &tables_info).await;
        let _ = s.emit(actions::TABLE_LEFT, &TableLeftPayload { tables: tables_info, table_id });

        if let Some(msg) = &leave_msg {
            broadcast_to_table(&io, &state, table_id, Some(msg)).await;
        }

        if need_clear {
            clear_for_one_player(&io, state.clone(), table_id).await;
        }
    });

    socket.on(actions::FOLD, async move |s: SocketRef, Data::<u32>(table_id), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let socket_id = s.id.to_string();
        let result = {
            let mut tables = state.tables.lock().await;
            if let Some(table) = tables.get_mut(&table_id) {
                table.handle_fold(&socket_id)
            } else { None }
        };
        if let Some(res) = result {
            broadcast_to_table(&io, &state, table_id, Some(&res.message)).await;
            change_turn_and_broadcast(&io, state, table_id, res.seat_id);
        }
    });

    socket.on(actions::CHECK, async move |s: SocketRef, Data::<u32>(table_id), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let socket_id = s.id.to_string();
        let result = {
            let mut tables = state.tables.lock().await;
            if let Some(table) = tables.get_mut(&table_id) {
                table.handle_check(&socket_id)
            } else { None }
        };
        tracing::debug!("{:?}", result);
        if let Some(res) = result {
            broadcast_to_table(&io, &state, table_id, Some(&res.message)).await;
            change_turn_and_broadcast(&io, state, table_id, res.seat_id);
        }
    });

    socket.on(actions::CALL, async move |s: SocketRef, Data::<u32>(table_id), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let socket_id = s.id.to_string();
        let result = {
            let mut tables = state.tables.lock().await;
            if let Some(table) = tables.get_mut(&table_id) {
                table.handle_call(&socket_id)
            } else { None }
        };
        if let Some(res) = result {
            broadcast_to_table(&io, &state, table_id, Some(&res.message)).await;
            change_turn_and_broadcast(&io, state, table_id, res.seat_id);
        }
    });

    socket.on(actions::RAISE, async move |s: SocketRef, Data::<RaisePayload>(payload), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let socket_id = s.id.to_string();
        let result = {
            let mut tables = state.tables.lock().await;
            if let Some(table) = tables.get_mut(&payload.table_id) {
                table.handle_raise(&socket_id, payload.amount)
            } else { None }
        };
        if let Some(res) = result {
            broadcast_to_table(&io, &state, payload.table_id, Some(&res.message)).await;
            change_turn_and_broadcast(&io, state, payload.table_id, res.seat_id);
        }
    });

    socket.on(actions::TABLE_MESSAGE, async move |_s: SocketRef, Data::<TableMessagePayload>(payload), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let socket_ids = {
            let tables = state.tables.lock().await;
            tables.get(&payload.table_id).map(|t| {
                t.players.iter().map(|p| p.socket_id.clone()).collect::<Vec<_>>()
            })
        };

        if let Some(sids) = socket_ids {
            for sid_str in sids {
                let table_view = {
                    let tables = state.tables.lock().await;
                    tables.get(&payload.table_id).map(|t| hide_opponent_cards(t, &sid_str))
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
            let players = state.players.lock().await;
            let mut tables = state.tables.lock().await;

            if let Some(table) = tables.get_mut(&payload.table_id) {
                if let Some(player) = players.get(&socket_id) {
                    let player_clone = player.clone();
                    let player_name = player.name.clone();
                    let player_id = player.id.clone();

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
            init_new_hand(&io, state, payload.table_id).await;
        }
    });

    socket.on(actions::REBUY, async move |s: SocketRef, Data::<RebuyPayload>(payload), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let socket_id = s.id.to_string();
        let chips_deduct = {
            let players = state.players.lock().await;
            let mut tables = state.tables.lock().await;

            if let Some(table) = tables.get_mut(&payload.table_id) {
                table.rebuy_player(payload.seat_id, payload.amount);
                players.get(&socket_id).map(|p| p.id.clone())
            } else { None }
        };

        if let Some(pid) = chips_deduct {
            let _ = state.db.update_chips(&pid, -(payload.amount as i64)).await;
        }

        broadcast_to_table(&io, &state, payload.table_id, None).await;
    });

    socket.on(actions::STAND_UP, async move |s: SocketRef, Data::<u32>(table_id), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let socket_id = s.id.to_string();

        let chips_return = {
            let players = state.players.lock().await;
            let tables = state.tables.lock().await;
            if let Some(table) = tables.get(&table_id) {
                table.find_player_by_socket_id(&socket_id)
                    .and_then(|seat| {
                        players.get(&socket_id).map(|p| (p.id.clone(), seat.stack))
                    })
            } else { None }
        };

        if let Some((pid, stack)) = chips_return {
            let _ = state.db.update_chips(&pid, stack as i64).await;
        }

        let (stand_msg, need_clear) = {
            let mut tables = state.tables.lock().await;
            if let Some(table) = tables.get_mut(&table_id) {
                let msg = table.find_player_by_socket_id(&socket_id)
                    .and_then(|seat| {
                        seat.player.as_ref().map(|p| format!("{} left the table", p.name))
                    });
                table.stand_player(&socket_id);
                let clear = table.active_players().len() == 1;
                (msg, clear)
            } else { (None, false) }
        };

        broadcast_to_table(&io, &state, table_id, stand_msg.as_deref()).await;

        if need_clear {
            clear_for_one_player(&io, state, table_id).await;
        }
    });

    socket.on(actions::SITTING_OUT, async move |_s: SocketRef, Data::<SittingPayload>(payload), io: SocketIo, State(state): State<Arc<SocketState>>| {
        {
            let mut tables = state.tables.lock().await;
            if let Some(table) = tables.get_mut(&payload.table_id) {
                if let Some(Some(seat)) = table.seats.get_mut(&payload.seat_id) {
                    seat.sitting_out = true;
                }
            }
        }
        broadcast_to_table(&io, &state, payload.table_id, None).await;
    });

    socket.on(actions::SITTING_IN, async move |_s: SocketRef, Data::<SittingPayload>(payload), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let should_start = {
            let mut tables = state.tables.lock().await;
            if let Some(table) = tables.get_mut(&payload.table_id) {
                if let Some(Some(seat)) = table.seats.get_mut(&payload.seat_id) {
                    seat.sitting_out = false;
                }
                table.hand_over && table.active_players().len() == 2
            } else { false }
        };

        broadcast_to_table(&io, &state, payload.table_id, None).await;

        if should_start {
            init_new_hand(&io, state, payload.table_id).await;
        }
    });

    socket.on_disconnect(async move |s: SocketRef, io: SocketIo, State(state): State<Arc<SocketState>>| {
        let socket_id = s.id.to_string();
        let (auto_fold_actions, user_id, table_ids): (Vec<(u32, ActionResult)>, Option<String>, Vec<u32>) = {
            let players = state.players.lock().await;
            let mut tables = state.tables.lock().await;

            let uid = players.get(&socket_id).map(|p| p.id.clone());
            let mut fold_actions = Vec::new();
            let mut affected_tables = Vec::new();

            for (table_id, table) in tables.iter_mut() {
                if let Some(action_result) = table.mark_player_disconnected(&socket_id) {
                    fold_actions.push((*table_id, action_result));
                }
                if table.is_player_disconnected(&socket_id) {
                    affected_tables.push(*table_id);
                }
            }

            (fold_actions, uid, affected_tables)
        };

        for (table_id, res) in &auto_fold_actions {
            broadcast_to_table(&io, &state, *table_id, Some(&res.message)).await;
            change_turn_and_broadcast(&io, state.clone(), *table_id, res.seat_id);
        }

        for table_id in &table_ids {
            broadcast_to_table(&io, &state, *table_id, None).await;
        }

        let tables_info = state.get_current_tables().await;
        let players_info = state.get_current_players().await;
        let _ = io.emit(actions::TABLES_UPDATED, &tables_info).await;
        let _ = io.emit(actions::PLAYERS_UPDATED, &players_info).await;

        if let Some(uid) = user_id {
            schedule_disconnect_cleanup(io, state, uid, socket_id);
        }
    });
}
