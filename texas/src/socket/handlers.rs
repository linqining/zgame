use std::sync::Arc;

use socketioxide::{
    extract::{Data, SocketRef, State},
    SocketIo,
};

use crate::auth;
use crate::config::Config;
use crate::pokergame::player::truncate_name;
use super::*;

/// 为用户操作构建 PTB 并序列化为 tx_kind_b64。
///
/// 根据 `action` 类型选择对应的 PTB 构建器（fold/check/call/raise），
/// 使用 `config.sui_package_id` 作为包 ID，`chain_table_id` 作为链上 Table Object ID，
/// 然后通过 `ptb::serialize_tx_kind` 序列化为可供前端钱包签名的 base64 字符串。
fn build_action_ptb_for_user(
    config: &Config,
    chain_table_id: &str,
    seat_index: u64,
    action: &str,
    amount: Option<u64>,
) -> Result<String, String> {
    use crate::relayer::ptb;
    let pt = match action {
        "fold" => ptb::build_fold_ptb(&config.sui_package_id, chain_table_id, seat_index)?,
        "check" => ptb::build_check_ptb(&config.sui_package_id, chain_table_id, seat_index)?,
        "call" => ptb::build_call_ptb(&config.sui_package_id, chain_table_id, seat_index)?,
        "raise" => ptb::build_raise_ptb(
            &config.sui_package_id,
            chain_table_id,
            seat_index,
            amount.unwrap_or(0),
        )?,
        _ => return Err(format!("unknown action: {}", action)),
    };
    ptb::serialize_tx_kind(pt)
}

/// 尝试以 on-chain 模式处理用户操作。
///
/// 返回 `true` 表示已通过 on-chain 流程处理（或已拒绝），调用方应跳过本地处理；
/// 返回 `false` 表示未处理，调用方应执行本地处理。
///
/// 行为：
/// - 当 `config.sui_on_chain_enabled` 为 `false` 时直接返回 `false`（保持本地模式）。
/// - 当 `sui_on_chain_enabled` 为 `true` 时，**始终返回 `true`**（不修改本地内存）：
///   - 若能解析 `pk_hex` / `seat_index` / `chain_table_id`：构建 PTB，emit
///     `action_signing_request` 给前端签名上链，等待 relayer 事件同步回本地。
///   - 若任何步骤失败：emit `error` 事件告知前端，**不回退本地处理**。
async fn try_on_chain_action(
    socket: &SocketRef,
    state: &Arc<SocketState>,
    table_id: u32,
    action: &str,
    amount: Option<u64>,
) -> bool {
    if !state.config.sui_on_chain_enabled {
        return false;
    }

    let socket_id = socket.id.to_string();

    // 1. 查找 pk_hex 和 seat_index
    let (pk_hex, seat_index, chain_table_id) = {
        let gs = state.state.read().await;
        let player = gs.players.get(&socket_id);
        let table = gs.tables.get(&table_id);
        let pk_hex = player.and_then(|p| {
            table.and_then(|t| t.get_pk_hex_by_wallet_address(&p.wallet_address.0))
        });
        let seat_index = pk_hex
            .as_ref()
            .and_then(|pk| table.and_then(|t| t.pk_to_seat.get(pk).copied()));
        let chain_table_id = table.and_then(|t| t.chain_table_id.clone());
        match (pk_hex, seat_index, chain_table_id) {
            (Some(pk), Some(seat), Some(cid)) => (pk, seat, cid),
            _ => {
                tracing::warn!(
                    "[on_chain_action] cannot resolve pk_hex/seat_index/chain_table_id for socket_id={}, table_id={}, action={}",
                    socket_id,
                    table_id,
                    action
                );
                let _ = socket.emit(
                    "error",
                    &serde_json::json!({
                        "msg": format!("on-chain mode: cannot resolve player seat or chain table id for action {}", action),
                        "action": action,
                        "table_id": table_id,
                    }),
                );
                // 上链模式下不回退本地处理，直接返回 true（不修改本地内存）
                return true;
            }
        }
    };

    // 2. 构建 PTB 并序列化
    let tx_kind_b64 = match build_action_ptb_for_user(
        &state.config,
        &chain_table_id,
        seat_index as u64,
        action,
        amount,
    ) {
        Ok(b64) => b64,
        Err(e) => {
            tracing::warn!(
                "[on_chain_action] failed to build PTB for action={}, table_id={}, error={}",
                action,
                table_id,
                e
            );
            let _ = socket.emit(
                "error",
                &serde_json::json!({
                    "msg": format!("on-chain mode: failed to build PTB: {}", e),
                    "action": action,
                    "table_id": table_id,
                }),
            );
            // 上链模式下不回退本地处理
            return true;
        }
    };

    // 3. emit action_signing_request 给前端，由前端钱包签名后回传签名提交赞助交易
    let payload = serde_json::json!({
        "action": action,
        "table_id": table_id,
        "seat_index": seat_index,
        "tx_kind_b64": tx_kind_b64,
        "amount": amount,
        "pk_hex": pk_hex.0,
    });
    tracing::info!(
        "[on_chain_action] emit action_signing_request: action={}, table_id={}, seat_index={}",
        action,
        table_id,
        seat_index
    );
    let _ = socket.emit("action_signing_request", &payload);
    true
}

/// A3 修复：验证 socket 发送者拥有所声称的 pk_hex。
///
/// 通过 socket_id 查找 player 的 wallet_address，再通过 table 查找该 wallet_address 对应的 pk_hex，
/// 与请求中声称的 pk_hex 比较。验证失败时 emit error 事件并返回 false。
async fn verify_socket_sender(
    socket: &SocketRef,
    state: &Arc<SocketState>,
    table_id: u32,
    claimed_pk_hex: &GamePkHex,
) -> bool {
    let socket_id = socket.id.to_string();
    let expected_pk = {
        let gs = state.state.read().await;
        let wallet = gs.players.get(&socket_id).map(|p| p.wallet_address.clone());
        wallet.and_then(|wa| {
            gs.tables.get(&table_id).and_then(|t| t.get_pk_hex_by_wallet_address(&wa.0))
        })
    };
    match expected_pk {
        Some(pk) if &pk == claimed_pk_hex => true,
        Some(pk) => {
            tracing::warn!(
                "[verify_socket_sender] pk_hex mismatch: socket_id={}, table_id={}, expected={}, claimed={}",
                socket_id, table_id, pk, claimed_pk_hex
            );
            let _ = socket.emit("error", &serde_json::json!({"msg": "pk_hex does not belong to sender"}));
            false
        }
        None => {
            tracing::warn!(
                "[verify_socket_sender] cannot resolve pk_hex for socket_id={}, table_id={}",
                socket_id, table_id
            );
            let _ = socket.emit("error", &serde_json::json!({"msg": "Cannot verify sender identity"}));
            false
        }
    }
}

/// A3 修复：验证 socket 发送者拥有所声称的 seat_id。
///
/// 用于 REBUY 等不带 pk_hex 的事件：通过 socket_id 查找 player 的 wallet_address，
/// 再验证 table 中 seat_id 的 player.wallet_address 与之一致。
async fn verify_socket_sender_seat(
    socket: &SocketRef,
    state: &Arc<SocketState>,
    table_id: u32,
    seat_id: u32,
) -> bool {
    let socket_id = socket.id.to_string();
    let wallet_match = {
        let gs = state.state.read().await;
        let wallet = gs.players.get(&socket_id).map(|p| p.wallet_address.clone());
        match wallet {
            Some(wa) => {
                gs.tables.get(&table_id)
                    .and_then(|t| t.seats.get(&seat_id))
                    .and_then(|seat| seat.player.as_ref())
                    .map_or(false, |gp| gp.wallet_address.0 == wa.0)
            }
            None => false,
        }
    };
    if !wallet_match {
        tracing::warn!(
            "[verify_socket_sender_seat] seat ownership mismatch: socket_id={}, table_id={}, seat_id={}",
            socket_id, table_id, seat_id
        );
        let _ = socket.emit("error", &serde_json::json!({"msg": "Seat does not belong to sender"}));
        false
    } else {
        true
    }
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

        let old_player = {
            let gs = state.state.read().await;
            gs.players.values().find(|t| t.id == user_id).cloned()
        };
        tracing::info!("on_connect FETCH_LOBBY_INFO: {} old_sid={:?}", claims.user.id.clone(), old_player.as_ref().map(|p| p.socket_id.clone()));

        // 这个替换seat里面的player
        let (table_ids_to_broadcast, is_reconnect) = if let Some(old_player) = old_player {
            tracing::info!("[RECONNECT] user {} found disconnected seat, old_sid={}, new_sid={}", user_id, old_player.socket_id.clone(), new_socket_id);
            {
                let mut gs = state.state.write().await;
                if let Some(cancel_tx) = gs.disconnect_cancellers.remove(&old_player.socket_id) {
                    let _ = cancel_tx.send(true);
                }
            }
            let reconnected_table_ids = {
                let mut gs = state.state.write().await;
                let mut ids = Vec::new();
                for table in gs.tables.values_mut() {
                    if table.reconnect_player(&old_player.wallet_address.0) {
                        ids.push(table.id);
                    }
                }
                ids
            };

            let db_user = state.db.find_user_by_id(&user_id).await;
            if let Some(user) = db_user {
                let mut gs = state.state.write().await;
                gs.players.insert(new_socket_id.clone(), Player {
                    socket_id: new_socket_id.clone(),
                    id: user.id,
                    name: user.name,
                    bankroll: user.chips_amount,
                    wallet_address: WalletAddress::new(user.address.clone()),
                });
                gs.players.remove(&old_player.socket_id);
            }

            (reconnected_table_ids, true)
        }else{
            (Vec::new(), false)
        };

        // 这个替换players里面的player
        {
            let old_player = {
                let gs = state.state.read().await;
                gs.players.values().find(|p| p.id == user_id).cloned()
            };
            tracing::info!("on_connect FETCH_LOBBY_INFO: {} old_sid={:?}", claims.user.id.clone(), old_player.as_ref().map(|p| p.socket_id.clone()));

            if let Some(ref old_player) = old_player {
                tracing::info!("[RECONNECT] user {} found active session in players, replacing old_sid={}", user_id, old_player.socket_id.clone());
                let mut gs = state.state.write().await;
                if let Some(cancel_tx) = gs.disconnect_cancellers.remove(&old_player.socket_id) {
                    let _ = cancel_tx.send(true);
                }
                gs.players.remove(&old_player.socket_id);
                gs.players.insert(new_socket_id.clone(), Player {
                    socket_id: new_socket_id.clone(),
                    id: old_player.id.clone(),
                    name: old_player.name.clone(),
                    wallet_address: old_player.wallet_address.clone(),
                    bankroll: old_player.bankroll,
                });
                for table in gs.tables.values_mut() {
                    table.reconnect_player(&old_player.wallet_address.0);
                }
            }
        };
        tracing::info!("on_connect FETCH_LOBBY_INFO: {}", claims.user.id.clone());


        for tid in &table_ids_to_broadcast {
            broadcast::broadcast_to_table(&io, &state, *tid, None).await;
        }

        if !is_reconnect {
            let db_user = state.db.find_user_by_id(&claims.user.id).await;
            if let Some(user) = db_user {
                tracing::info!("on_connect FETCH_LOBBY_INFO: {} user={:?}", claims.user.id.clone(), user);
                state.state.write().await.players.insert(s.id.to_string(), Player {
                    socket_id: s.id.to_string(),
                    id: user.id,
                    name: user.name,
                    wallet_address: WalletAddress::new(user.address.clone()),
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

    socket.on(actions::JOIN_TABLE, async move |s: SocketRef, Data::<JoinTablePayload>(payload), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let table_id = payload.table_id;
        s.join(table_room_name(table_id));
        tracing::info!("join_table: {} {}", payload.pk_hex, table_id);
        let socket_id = s.id.to_string();
        // let join_msg = {
        //     let mut gs = state.state.write().await;

        //     let player_data = gs.players.get(&socket_id).map(|p| (p.clone(), truncate_name(&p.name, 12)));

        //     if let Some(table) = gs.tables.get_mut(&table_id) {
        //         if let Some((player_clone, player_name)) = player_data {
        //             table.add_player(payload.pk_hex.clone(), player_clone.wallet_address.clone());
        //             tracing::info!("add_player: {}", socket_id);
        //             Some(format!("{} joined the table.", player_name))
        //         } else { None }
        //     } else { None }
        // };

        // let tables_info = state.get_current_tables().await;
        // {
        //     let gs = state.state.read().await;
        //     if let Some(table) = gs.tables.get(&table_id) {
        //         let wallet_addr = gs.players.get(&socket_id).map(|p| p.wallet_address.clone());
        //         let table_view = wallet_addr.map(|wa| hide_opponent_cards(&table.to_client(), &wa));
        //         if let Some(table_view) = table_view {
        //             let _ = s.emit(actions::TABLE_JOINED, &TableUpdatePayload {
        //                 table: table_view,
        //                 message: join_msg.clone(),
        //                 from: None,
        //             });
        //         }
        //     }
        // }
        // let _ = io.emit(actions::TABLES_UPDATED, &tables_info).await;

        let wallet = {
            let mut gs = state.state.write().await;
            gs.players.get(&socket_id).map(|p| p.wallet_address.clone()).unwrap_or_else(|| WalletAddress::new("".to_string()))
        };


        broadcast::join_table_push(&io, &state, table_id,wallet).await;
        // if let Some(msg) = join_msg {
        //     broadcast::broadcast_to_table(&io, &state, table_id, Some(&msg)).await;
        // }
    });

    socket.on(actions::LEAVE_TABLE, async move |s: SocketRef, Data::<LeaveTablePayload>(payload), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let socket_id = s.id.to_string();
        let table_id = payload.table_id;
        let wallet_address = { state.state.read().await.players.get(&socket_id).map(|p| p.wallet_address.clone()) };
        tracing::info!("leave_table: {} {} {:?}", payload.pk_hex, table_id, wallet_address);
        // Derive pk_hex: prefer client-provided value, fallback to wallet_address lookup
        let pk_hex: Option<GamePkHex> = {
            let gs = state.state.read().await;
            if payload.pk_hex.0.is_empty() {
                // Client didn't provide pk_hex, lookup from table.players
                wallet_address.as_ref().and_then(|wa| {
                    gs.tables.get(&table_id).and_then(|t| t.get_pk_hex_by_wallet_address(&wa.0))
                })
            } else {
                // Verify client-provided pk_hex matches wallet_address
                if let Some(ref wa) = wallet_address {
                    if let Some(table) = gs.tables.get(&table_id) {
                        if let Some(looked_up) = table.get_pk_hex_by_wallet_address(&wa.0) {
                            if looked_up != payload.pk_hex {
                                tracing::warn!("[LEAVE_TABLE] pk_hex mismatch: client={}, server={}", payload.pk_hex, looked_up);
                            }
                        }
                    }
                }
                Some(payload.pk_hex.clone())
            }
        };

        let (is_playing, player_name) = {
            let gs = state.state.read().await;
            if let Some(table) = gs.tables.get(&table_id) {
                let name = wallet_address.as_ref().and_then(|wa| table.find_player_by_wallet(wa))
                    .and_then(|_| gs.players.get(&socket_id).map(|p| truncate_name(&p.name, 12)));
                (table.is_playing(), name)
            } else { (false, None) }
        };

        if is_playing {
            tracing::info!("[LEAVE_TABLE] Table {}: {} is leaving while hand in progress, marking sitting_out", table_id, socket_id);
            if let Some(ref wallet_address) = wallet_address {
                state.mark_player_sitting_out(table_id, wallet_address).await;
            }
            let msg = player_name.map(|n| format!("{} is sitting out.", n));
            broadcast::broadcast_to_table(&io, &state, table_id, msg.as_deref()).await;
            return;
        }
        s.leave(table_room_name(table_id));

        let chips_update = {
            let gs = state.state.read().await;
            if let Some(table) = gs.tables.get(&table_id) {
                pk_hex.as_ref().and_then(|pk| table.find_player_by_pk(pk))
                    .and_then(|seat| {
                        gs.players.get(&socket_id).map(|p| (p.id.clone(), seat.stack))
                    })
            } else { None }
        };

        if let Some((pid, stack)) = chips_update {
            let _ = state.db.update_chips(&pid, stack as i64).await;
        }

        let (leave_msg, need_clear) = {
            let mut guard = state.state.write().await;
            let gs = &mut *guard;
            let name = gs.players.get(&socket_id).map(|p| p.name.clone());
            if let Some(table) = gs.tables.get_mut(&table_id) {
                if let Some(ref pk) = pk_hex {
                    tracing::info!("remove_player_by_pk: {}", pk);
                    table.leave_talbe_and_clear_shuffle(pk);
                } else {
                    tracing::warn!("[LEAVE_TABLE] No pk_hex found for socket_id={}, cannot remove player", socket_id);
                }
                let msg = name.map(|n| format!("{} left the table.", n));
                let clear = table.active_players().len() == 1;
                (msg, clear)
            } else { (None, false) }
        };

        let tables_info = state.get_current_tables().await;
        let players_info = state.get_current_players().await;
        let _ = io.emit(actions::TABLES_UPDATED, &tables_info).await;
        let _ = io.emit(actions::PLAYERS_UPDATED, &players_info).await;
        let _ = s.emit(actions::TABLE_LEFT, &TableLeftPayload { tables: tables_info, table_id });

        if let Some(msg) = &leave_msg {
            broadcast::broadcast_to_table(&io, &state, table_id, Some(msg)).await;
        }

        if need_clear {
            state.stop_game_loop(table_id).await;
            game_loop::clear_for_one_player(&io, state.clone(), table_id).await;
        }
    });

    socket.on(actions::FOLD, async move |s: SocketRef, Data::<u32>(table_id), _io: SocketIo, State(state): State<Arc<SocketState>>| {
        if !try_on_chain_action(&s, &state, table_id, "fold", None).await {
            send_simple_action(&s, &state, table_id, "fold").await;
        }
    });

    socket.on(actions::CHECK, async move |s: SocketRef, Data::<u32>(table_id), _io: SocketIo, State(state): State<Arc<SocketState>>| {
        if !try_on_chain_action(&s, &state, table_id, "check", None).await {
            send_simple_action(&s, &state, table_id, "check").await;
        }
    });

    socket.on(actions::CALL, async move |s: SocketRef, Data::<u32>(table_id), _io: SocketIo, State(state): State<Arc<SocketState>>| {
        if !try_on_chain_action(&s, &state, table_id, "call", None).await {
            send_simple_action(&s, &state, table_id, "call").await;
        }
    });

    socket.on(actions::RAISE, async move |s: SocketRef, Data::<RaisePayload>(payload), _io: SocketIo, State(state): State<Arc<SocketState>>| {
        if !try_on_chain_action(&s, &state, payload.table_id, "raise", Some(payload.amount)).await {
            let socket_id = s.id.to_string();
            let pk_hex = {
                let gs = state.state.read().await;
                gs.players.get(&socket_id)
                    .and_then(|p| gs.tables.get(&payload.table_id).and_then(|t| t.get_pk_hex_by_wallet_address(&p.wallet_address.0)))
            };
            if let (Some(pk_hex), Some(sender)) = (pk_hex, state.get_action_sender(payload.table_id).await) {
                let _ = sender.send(ActionRequest { pk_hex, action: "raise".to_string(), amount: Some(payload.amount) }).await;
            }
        }
    });

    socket.on(actions::TABLE_MESSAGE, async move |_s: SocketRef, Data::<TableMessagePayload>(payload), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let socket_ids = {
            let gs = state.state.read().await;
            gs.tables.get(&payload.table_id).map(|t| {
                t.players.iter()
                    .filter_map(|(_game_pk, wallet_addr)| {
                        gs.players.values()
                            .find(|p| p.wallet_address.0 == wallet_addr.0)
                            .map(|p| p.socket_id.clone())
                    })
                    .collect::<Vec<_>>()
            })
        };

        if let Some(sids) = socket_ids {
            for sid_str in sids {
                let table_view = {
                    let gs = state.state.read().await;
                    let wallet_addr = gs.players.get(&sid_str).map(|p| p.wallet_address.clone());
                    gs.tables.get(&payload.table_id).and_then(|t| wallet_addr.map(|wa| hide_opponent_cards(&t.to_client(), &wa)))
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

    socket.on(actions::SIT_DOWN, async move |s: SocketRef, Data::<SitDownPayload>(payload), _io: SocketIo, _state: State<Arc<SocketState>>| {
        let socket_id = s.id.to_string();
        tracing::warn!("[SIT_DOWN] Deprecated SIT_DOWN action received from {}, please use SIT_DOWN_V2. table_id={}, seat_id={}", socket_id, payload.table_id, payload.seat_id);
        let _ = s.emit("error", &serde_json::json!({"msg": "SIT_DOWN is deprecated, please use SIT_DOWN_V2"}));
    });

    socket.on(actions::SIT_DOWN_V2, async move |s: SocketRef, Data::<SitDownV2Payload>(payload), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let socket_id = s.id.to_string();

        let claims = match auth::verify_token(&payload.token, &state.config.jwt_secret) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("[SIT_DOWN_V2] Token verification failed for socket_id: {}, error: {}", socket_id, e);
                let _ = s.emit("error", &serde_json::json!({"msg": "Authentication failed, please reconnect your wallet"}));
                return;
            }
        };
        let user_id = claims.user.id.clone();
        tracing::info!("[SIT_DOWN_V2] Received from {}: table_id={}, seat_id={}, amount={}, pk_hex={}, user_id={}",
            socket_id, payload.table_id, payload.seat_id, payload.amount, payload.pk_hex, user_id);

        // E3 修复：校验 amount > 0，避免 0 或负值导致的逻辑错误
        if payload.amount == 0 {
            tracing::warn!("[SIT_DOWN_V2] Invalid amount=0 from socket_id={}", socket_id);
            let _ = s.emit("error", &serde_json::json!({"msg": "Amount must be positive"}));
            return;
        }

        // E3 修复：使用 i64::try_from 避免 u64 -> i64 转换溢出
        let deduct = match i64::try_from(payload.amount) {
            Ok(v) => -v,
            Err(_) => {
                tracing::warn!("[SIT_DOWN_V2] Amount too large for i64: {}", payload.amount);
                let _ = s.emit("error", &serde_json::json!({"msg": "Amount too large"}));
                return;
            }
        };

        let player_pk = match hex_to_ecpoint(&**payload.pk_hex) {
            Ok(pk) => pk,
            Err(e) => {
                tracing::warn!("[SIT_DOWN_V2] Invalid pk_hex: {}", e);
                return;
            }
        };

        let player = {
            let gs = state.state.read().await;
            gs.players.get(&socket_id).cloned()
        };

        let player = match player {
            Some(p) if p.id == user_id => p,
            Some(p) => {
                tracing::warn!("[SIT_DOWN_V2] Player id mismatch: socket_id={}, token_user_id={}, player_id={}", socket_id, user_id, p.id);
                return;
            }
            None => {
                let db_user = state.db.find_user_by_id(&user_id).await;
                match db_user {
                    Some(user) => {
                        let mut gs = state.state.write().await;
                        let p = Player {
                            socket_id: socket_id.clone(),
                            id: user.id,
                            name: user.name,
                            bankroll: user.chips_amount,
                            wallet_address: WalletAddress::new(user.address.clone()),
                        };
                        gs.players.insert(socket_id.clone(), p.clone());
                        p
                    }
                    None => {
                        tracing::warn!("[SIT_DOWN_V2] User not found in DB for user_id: {}", user_id);
                        return;
                    }
                }
            }
        };

        let player_id = player.id.clone();
        let player_name = truncate_name(&player.name, 12);

        // E3 修复：检查用户余额是否足够
        let db_user = state.db.find_user_by_id(&player_id).await;
        if let Some(ref user) = db_user {
            if user.chips_amount < payload.amount as i64 {
                tracing::warn!(
                    "[SIT_DOWN_V2] Insufficient chips: user_id={}, balance={}, required={}",
                    player_id,
                    user.chips_amount,
                    payload.amount
                );
                let _ = s.emit("error", &serde_json::json!({"msg": "Insufficient chips"}));
                return;
            }
        }

        let result = state.join_player_and_shuffle(
            payload.table_id,
            player,
            player_pk,
            payload.pk_proof,
            payload.mask_and_shuffle_round,
            payload.seat_id,
            payload.amount,
        ).await;

        match result {
            Ok((all_complete, join_result)) => {
                // E3 修复：使用预先校验过的 deduct 值，避免溢出
                let _ = state.db.update_chips(&player_id, deduct).await;

                let msg = match join_result {
                    JoinResult::JoinedAndShuffled => format!("{} sat down in Seat {} and shuffled", player_name, payload.seat_id),
                    JoinResult::JoinedWaiting => format!("{} sat down in Seat {}, waiting for next hand", player_name, payload.seat_id),
                };
                broadcast::broadcast_to_table(&io, &state, payload.table_id, Some(&msg)).await;

                // ZK 可视化：remask 证明验证成功（join_and_shuffle 中 remask_proof 已验证）
                state.broadcast_crypto_event(
                    payload.table_id,
                    broadcast::CryptoEventType::Remask,
                    payload.pk_hex.to_string(),
                    None,
                    true,
                    Some("remask proof verified".to_string()),
                ).await;

                if all_complete {
                    tracing::info!("[SIT_DOWN_V2] All players shuffled, starting game loop for table {}", payload.table_id);
                    state.start_game_loop(io, state.clone(), payload.table_id).await;
                }
            }
            Err(e) => {
                tracing::warn!("[SIT_DOWN_V2] Failed to join and shuffle: {}", e);
                // ZK 可视化：remask 证明验证失败
                state.broadcast_crypto_event(
                    payload.table_id,
                    broadcast::CryptoEventType::Remask,
                    payload.pk_hex.to_string(),
                    None,
                    false,
                    Some(format!("remask proof verification failed: {}", e)),
                ).await;
            }
        }
    });

    socket.on(actions::REBUY, async move |s: SocketRef, Data::<RebuyPayload>(payload), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let socket_id = s.id.to_string();

        // E3 修复：校验 amount > 0
        if payload.amount == 0 {
            tracing::warn!("[REBUY] Invalid amount=0 from socket_id={}", socket_id);
            let _ = s.emit("error", &serde_json::json!({"msg": "Amount must be positive"}));
            return;
        }

        // E3 修复：使用 i64::try_from 避免 u64 -> i64 转换溢出
        let deduct = match i64::try_from(payload.amount) {
            Ok(v) => -v,
            Err(_) => {
                tracing::warn!("[REBUY] Amount too large for i64: {}", payload.amount);
                let _ = s.emit("error", &serde_json::json!({"msg": "Amount too large"}));
                return;
            }
        };

        // A3 修复：验证发送者拥有该 seat_id
        if !verify_socket_sender_seat(&s, &state, payload.table_id, payload.seat_id).await {
            return;
        }

        let chips_deduct = {
            let mut gs = state.state.write().await;

            if let Some(table) = gs.tables.get_mut(&payload.table_id) {
                table.rebuy_player(payload.seat_id, payload.amount);
                gs.players.get(&socket_id).map(|p| p.id.clone())
            } else { None }
        };

        if let Some(pid) = chips_deduct {
            // E3 修复：检查余额
            let db_user = state.db.find_user_by_id(&pid).await;
            if let Some(ref user) = db_user {
                if user.chips_amount < payload.amount as i64 {
                    tracing::warn!(
                        "[REBUY] Insufficient chips: user_id={}, balance={}, required={}",
                        pid,
                        user.chips_amount,
                        payload.amount
                    );
                    let _ = s.emit("error", &serde_json::json!({"msg": "Insufficient chips"}));
                    // 余额不足，回滚 rebuy_player 的座位状态变更
                    let mut gs = state.state.write().await;
                    if let Some(table) = gs.tables.get_mut(&payload.table_id) {
                        // 简单回滚：从 seat stack 中减去刚加的 amount
                        if let Some(seat) = table.seats.get_mut(&payload.seat_id) {
                            seat.stack = seat.stack.saturating_sub(payload.amount);
                        }
                    }
                    broadcast::broadcast_to_table(&io, &state, payload.table_id, None).await;
                    return;
                }
            }
            // E3 修复：使用预先校验过的 deduct 值
            let _ = state.db.update_chips(&pid, deduct).await;
        }

        broadcast::broadcast_to_table(&io, &state, payload.table_id, None).await;
    });

    socket.on(actions::STAND_UP, async move |s: SocketRef, Data::<StandUpPayload>(payload), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let socket_id = s.id.to_string();
        let table_id = payload.table_id;
        let pk_hex = GamePkHex::new(payload.pk_hex.to_lowercase());
        tracing::info!("[STAND_UP] Received from {}: table_id={}, pk_hex={}", socket_id, table_id, pk_hex);

        // A3 修复：验证发送者拥有所声称的 pk_hex
        if !verify_socket_sender(&s, &state, table_id, &pk_hex).await {
            return;
        }

        let player_pk = match hex_to_ecpoint(&**pk_hex) {
            Ok(pk) => pk,
            Err(e) => {
                tracing::warn!("[STAND_UP] Invalid pk_hex: {}", e);
                return;
            }
        };

        let (is_playing, player_name) = {
            let gs = state.state.read().await;
            if let Some(table) = gs.tables.get(&table_id) {
                (table.is_playing(), table.find_player_by_pk(&pk_hex)
                    .and_then(|seat| seat.player.as_ref().map(|p| truncate_name(&p.name, 12))))
            } else { (false, None) }
        };

        if is_playing {
            tracing::info!("[STAND_UP] Table {}: {} standing up while hand in progress, marking sitting_out", table_id, socket_id);
            {
                let wallet_addr = {
                    let gs = state.state.read().await;
                    gs.players.get(&socket_id).map(|p| p.wallet_address.clone())
                };
                if let Some(wa) = wallet_addr {
                    state.mark_player_sitting_out(table_id, &wa).await;
                }
            }
            broadcast::broadcast_to_table(&io, &state, table_id, player_name.map(|n| format!("{} is sitting out.", n)).as_deref()).await;
            return;
        }

        // Verify LeaveProof and remove player
        let player_id = {
            let gs = state.state.read().await;
            gs.players.get(&socket_id).map(|p| p.id.clone())
        };

        let (stand_msg, need_clear, leave_proof_verified) = {
            let mut gs = state.state.write().await;
            if let Some(table) = gs.tables.get_mut(&table_id) {
                let msg = table.find_player_by_pk(&pk_hex)
                    .and_then(|seat| {
                        seat.player.as_ref().map(|p| format!("{} left the table", p.name))
                    });

                // Return chips before removing
                if let Some(seat) = table.find_player_by_pk(&pk_hex) {
                    if let Some(ref pid) = player_id {
                        let _ = state.db.update_chips(pid, seat.stack as i64).await;
                    }
                }

                // Verify leave proof and remove player
                let verified = match table.leave_player_with_proof(&pk_hex, &player_pk, &payload.leave_round) {
                    Ok(()) => {
                        tracing::info!("[STAND_UP] Leave proof verified, player {} removed", pk_hex);
                        true
                    }
                    Err(e) => {
                        tracing::warn!("[STAND_UP] Leave proof verification failed: {}, falling back to remove_player_by_pk", e);
                        table.remove_player_by_pk(&pk_hex);
                        false
                    }
                };

                let clear = table.active_players().len() == 1;
                (msg, clear, verified)
            } else { (None, false, false) }
        };

        broadcast::broadcast_to_table(&io, &state, table_id, stand_msg.as_deref()).await;

        // ZK 可视化：leave 证明验证结果
        state.broadcast_crypto_event(
            table_id,
            broadcast::CryptoEventType::Leave,
            pk_hex.0.clone(),
            None,
            leave_proof_verified,
            Some(if leave_proof_verified {
                "leave proof verified".to_string()
            } else {
                "leave proof verification failed".to_string()
            }),
        ).await;

        let tables_info = state.get_current_tables().await;
        let players_info = state.get_current_players().await;
        let _ = io.emit(actions::TABLES_UPDATED, &tables_info).await;
        let _ = io.emit(actions::PLAYERS_UPDATED, &players_info).await;

        if need_clear {
            state.stop_game_loop(table_id).await;
            game_loop::clear_for_one_player(&io, state, table_id).await;
        }
    });

    socket.on(actions::SITTING_OUT, async move |_s: SocketRef, Data::<SittingPayload>(payload), io: SocketIo, State(state): State<Arc<SocketState>>| {
        {
            let mut gs = state.state.write().await;
            if let Some(table) = gs.tables.get_mut(&payload.table_id) {
                if let Some(seat) = table.seats.get_mut(&payload.seat_id) {
                    seat.sitting_out = true;
                }
            }
        }
        broadcast::broadcast_to_table(&io, &state, payload.table_id, None).await;
    });

    socket.on(actions::SITTING_IN, async move |_s: SocketRef, Data::<SittingPayload>(payload), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let should_start = {
            let mut gs = state.state.write().await;
            if let Some(table) = gs.tables.get_mut(&payload.table_id) {
                if let Some(seat) = table.seats.get_mut(&payload.seat_id) {
                    seat.sitting_out = false;
                }
                table.hand_over && table.active_players().len() == MIN_START_NUM as usize
            } else { false }
        };

        broadcast::broadcast_to_table(&io, &state, payload.table_id, None).await;

        if should_start {
            state.start_game_loop(io, state.clone(), payload.table_id).await;
        }
    });

    socket.on(actions::SHUFFLE_SUBMIT, async move |s: SocketRef, Data::<serde_json::Value>(data), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let payload: Result<ShuffleSubmitPayload, _> = serde_json::from_value(data.clone());
        match payload {
            Ok(payload) => {
                let socket_id = s.id.to_string();
                tracing::info!("[SHUFFLE_SUBMIT] request received, pk_hex={}, table_id={}", payload.pk_hex, payload.table_id);
                let pk_hex = GamePkHex::new(payload.pk_hex.to_lowercase());

                // A3 修复：验证发送者拥有所声称的 pk_hex
                if !verify_socket_sender(&s, &state, payload.table_id, &pk_hex).await {
                    return;
                }

                let player = {
                    let gs = state.state.read().await;
                    gs.players.get(&socket_id).cloned()
                };

                let player = match player {
                    Some(p) => p,
                    None => {
                        tracing::warn!("[SHUFFLE_SUBMIT] Player not found for socket_id: {}", socket_id);
                        return;
                    }
                };

                let result = state.submit_verified_shuffle_for_pk(payload.table_id, &pk_hex, player, payload.output_cards.clone(), payload.shuffle_proof.clone()).await;

                match result {
                    Ok(()) => {
                        tracing::debug!("[SHUFFLE_SUBMIT] shuffle submitted and verified, pk_hex={}, table_id={}", pk_hex, payload.table_id);
                        state.send_shuffle_notice(payload.table_id).await;
                        broadcast::broadcast_to_table(&io, &state, payload.table_id, None).await;
                        // ZK 可视化：shuffle 证明验证成功
                        state.broadcast_crypto_event(
                            payload.table_id,
                            broadcast::CryptoEventType::Shuffle,
                            pk_hex.0.clone(),
                            None,
                            true,
                            Some("shuffle proof verified".to_string()),
                        ).await;
                    }
                    Err(e) => {
                        tracing::warn!("[SHUFFLE_SUBMIT] shuffle verification failed, pk_hex={}, table_id={}, error={}", pk_hex, payload.table_id, e);
                        // ZK 可视化：shuffle 证明验证失败
                        state.broadcast_crypto_event(
                            payload.table_id,
                            broadcast::CryptoEventType::Shuffle,
                            pk_hex.0.clone(),
                            None,
                            false,
                            Some(format!("shuffle proof verification failed: {}", e)),
                        ).await;
                    }
                }
            }
            Err(e) => {
                tracing::error!("[SHUFFLE_SUBMIT] Failed to parse payload: {}, raw: {:?}", e, data);
            }
        }
    });



    socket.on(actions::RECONSTRUCT_SUBMIT, async move |s: SocketRef, Data::<ReconstructSubmitPayload>(payload), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let socket_id = s.id.to_string();
        let pk_hex = GamePkHex::new(payload.pk_hex.to_lowercase());
        tracing::info!("[RECONSTRUCT_SUBMIT] request received, pk_hex={}, table_id={}", pk_hex, payload.table_id);

        // A3 修复：验证发送者拥有所声称的 pk_hex
        if !verify_socket_sender(&s, &state, payload.table_id, &pk_hex).await {
            return;
        }

        let _wallet_address = {
            let gs = state.state.read().await;
            gs.players.get(&socket_id).map(|p| p.wallet_address.to_string())
        }.unwrap_or_default();


        let (all_complete, reconstruct_payload, proof_verified) = {
            let mut gs = state.state.write().await;
            if let Some(table) = gs.tables.get_mut(&payload.table_id) {

                let (is_complete, verified) = match table.submit_reconstruct_deck(&pk_hex, payload.output_cards.clone(), payload.swap_cards.clone(), payload.proof) {
                    Ok(complete) => (complete, true),
                    Err(e) => {
                        tracing::error!("[RECONSTRUCT_SUBMIT] Error: {}", e);
                        (false, false)
                    }
                };
                if is_complete {
                    let reconstruct_payload = ReconstructResultPayload {
                        table_id: payload.table_id,
                        completed_players: table.reconstruct_state.completed_players.clone(),
                        reconstructed: true,
                    };
                    let _ = table.start_shuffle();
                    (is_complete, Some(reconstruct_payload), verified)
                } else {
                    (is_complete, None, verified)
                }
            } else {
                (false, None, false)
            }
        };

        if let Some(reconstruct_payload) = reconstruct_payload {
            let _ = io.to(table_room_name(payload.table_id)).emit(actions::RECONSTRUCT_RESULT, &reconstruct_payload).await;
        }
        state.send_shuffle_notice(payload.table_id).await;
        if all_complete {
            tracing::info!("[RECONSTRUCT_SUBMIT] All players completed reconstruct for table {}", payload.table_id);
        }
        broadcast::broadcast_to_table(&io, &state, payload.table_id, None).await;

        // ZK 可视化：reconstruct 证明验证结果
        state.broadcast_crypto_event(
            payload.table_id,
            broadcast::CryptoEventType::Reconstruct,
            pk_hex.0.clone(),
            None,
            proof_verified,
            Some(if proof_verified {
                "reconstruct proof verified".to_string()
            } else {
                "reconstruct proof verification failed".to_string()
            }),
        ).await;
    });

    socket.on(actions::REVEAL_SUBMIT, async move |s: SocketRef, Data::<RevealSubmitPayload>(payload), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let socket_id = s.id.to_string();
        let wallet_address = {
            let gs = state.state.read().await;
            gs.players.get(&socket_id).map(|p| p.wallet_address.to_string())
        };
        let wallet_address = match wallet_address {
            Some(w) => w,
            None => {
                tracing::warn!("[REVEAL_SUBMIT] Player {} not found", socket_id);
                return;
            }
        };
        let all_complete = {
            let mut gs = state.state.write().await;
            if let Some(table) = gs.tables.get_mut(&payload.table_id) {
                let pk_hex = table.get_pk_hex_by_wallet_address(&wallet_address);
                pk_hex.map_or(false, |pk| table.mark_player_reveal_complete(&pk))
            } else {
                false
            }
        };
        if all_complete {
            tracing::info!("[REVEAL_SUBMIT] All players completed reveal for table {}", payload.table_id);
        }
        broadcast::broadcast_to_table(&io, &state, payload.table_id, None).await;
    });

    socket.on(actions::REDEAL_REQUEST, async move |s: SocketRef, Data::<RedealRequestPayload>(payload), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let player_pk = GamePkHex::new(payload.player_pk.to_lowercase());
        tracing::info!("[REDEAL_REQUEST] Player {} requests redeal for {} failed cards on table {}",
            player_pk, payload.failed_card_indices.len(), payload.table_id);

        // A3 修复：验证发送者拥有所声称的 player_pk
        if !verify_socket_sender(&s, &state, payload.table_id, &player_pk).await {
            return;
        }

        // 执行 redeal
        let redealt_indices = {
            let mut gs = state.state.write().await;
            if let Some(table) = gs.tables.get_mut(&payload.table_id) {
                match table.redeal_cards_for_player(&player_pk, payload.failed_card_indices.clone()) {
                    Ok(indices) => indices,
                    Err(e) => {
                        tracing::error!("[REDEAL_REQUEST] Redeal failed: {}", e);
                        vec![]
                    }
                }
            } else {
                vec![]
            }
        };

        if !redealt_indices.is_empty() {
            // 启动 redeal reveal 阶段
            {
                let mut gs = state.state.write().await;
                if let Some(table) = gs.tables.get_mut(&payload.table_id) {
                    table.start_redeal_reveal_phase(&player_pk, redealt_indices);
                }
            }

            // 广播 redeal notice 给所有玩家
            state.broadcast_redeal_notice(payload.table_id).await;
            broadcast::broadcast_to_table(&io, &state, payload.table_id, Some("Redeal requested, new cards being dealt")).await;
        }
    });

    socket.on(actions::RECONSTRUCT_INITIATE, async move |_s: SocketRef, Data::<ReconstructInitiatePayload>(payload), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let result = {
            let mut gs = state.state.write().await;
            if let Some(table) = gs.tables.get_mut(&payload.table_id) {
                table.start_reconstruct()
            } else {
                Err("Table not found".to_string())
            }
        };

        match result {
            Ok(()) => {
                let reconstruct_payload = {
                    let gs = state.state.read().await;
                    gs.tables.get(&payload.table_id).map(|t| ReconstructResultPayload {
                        table_id: payload.table_id,
                        completed_players: t.reconstruct_state.completed_players.clone(),
                        reconstructed: false,
                    })
                };
                if let Some(p) = reconstruct_payload {
                    let _ = io.to(table_room_name(payload.table_id)).emit(actions::RECONSTRUCT_RESULT, &p).await;
                }
                broadcast::broadcast_to_table(&io, &state, payload.table_id, Some("Reconstruct vote initiated")).await;
            }
            Err(e) => {
                tracing::warn!("[RECONSTRUCT_INITIATE] Failed: {}", e);
            }
        }
    });

    socket.on_disconnect(async move |s: SocketRef, io: SocketIo, State(state): State<Arc<SocketState>>| {
        let socket_id = s.id.to_string();
        let wallet_address_str = {
            let gs = state.state.read().await;
            gs.players.get(&socket_id).map(|p| p.wallet_address.clone())
        };
        let (auto_fold_table_ids, _user_id, affected_table_ids, _need_cleanup, sitting_out_table_ids): (Vec<u32>, Option<String>, Vec<u32>, bool, Vec<u32>) = {
            let mut gs = state.state.write().await;

            let uid = gs.players.get(&socket_id).map(|p| p.id.clone());
            let wallet_address = gs.players.get(&socket_id).map(|p| p.wallet_address.to_string());
            let mut fold_tables = Vec::new();
            let mut affected = Vec::new();
            let mut should_cleanup = false;
            let mut sitting_out_tables = Vec::new();

            for (table_id, table) in gs.tables.iter_mut() {
                if wallet_address.as_ref().map_or(true, |wallet_address| table.find_player_by_wallet(wallet_address).is_none()) {
                    continue;
                }
                let pk = wallet_address.as_ref().and_then(|wa| table.get_pk_hex_by_wallet_address(wa));
                if table.is_playing() {
                    tracing::info!("[DISCONNECT] Table {}: {} disconnecting while hand in progress, marking sitting_out", table_id, socket_id);
                    affected.push(*table_id);
                    sitting_out_tables.push(*table_id);
                } else {
                    if let Some(ref pk_str) = pk {
                        if table.mark_player_disconnected(pk_str).is_some() {
                            fold_tables.push(*table_id);
                        }
                        if table.is_player_disconnected_by_pk(pk_str) {
                            affected.push(*table_id);
                        }
                    }
                    should_cleanup = true;
                }
            }

            (fold_tables, uid, affected, should_cleanup, sitting_out_tables)
        };

        if let Some(ref wa) = wallet_address_str {
            for tid in &sitting_out_table_ids {
                state.mark_player_sitting_out(*tid, wa).await;
            }
        }

        for table_id in &auto_fold_table_ids {
            broadcast::broadcast_to_table(&io, &state, *table_id, Some("auto-folds (disconnected)")).await;
            game_loop::handle_turn_advance(&io, &state, *table_id).await;
        }

        for tid in &affected_table_ids {
            broadcast::broadcast_to_table(&io, &state, *tid, None).await;
        }

        let tables_info = state.get_current_tables().await;
        let players_info = state.get_current_players().await;
        let _ = io.emit(actions::TABLES_UPDATED, &tables_info).await;
        let _ = io.emit(actions::PLAYERS_UPDATED, &players_info).await;

        // if need_cleanup {
        //     if let Some(ref uid) = user_id {
        //         schedule_disconnect_cleanup(io, state, uid.clone(), socket_id);
        //     }
        // }
    });
}
