use std::sync::Arc;

use super::*;
pub(crate) use crate::pokergame::table::events::CryptoEventType;

pub(crate) async fn broadcast_to_table(io: &SocketIo, state: &Arc<SocketState>, table_id: u32, message: Option<&str>) {
    let table_views = {
        let gs = state.state.read().await;
        let Some(table) = gs.tables.get(&table_id) else { return };
        let base_client_table = table.to_client();
        table.players().iter()
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
    // G18 修复：原实现使用 io.emit 广播给所有 socket，但 table_view 是为该 wallet
    // 定制的（hide_opponent_cards 隐藏对手手牌），广播会导致其他玩家看到错误的 view。
    // 改为只 emit 给加入的 socket。
    tracing::info!("[join_table_push] enter, table_id={}, wallet={}", table_id, wallet.0);

    // 从链上同步玩家/座位状态，确保内存 table 包含最新的链上玩家数据。
    // on-chain 模式下 SIT_DOWN_V2 不直接更新内存，玩家数据由 relayer 异步同步。
    // 如果 relayer 尚未处理 PlayerJoined 事件，内存中会缺少新玩家，
    // 导致 join_table_push 发送的 table view 不包含新玩家，刷新也看不到。
    crate::relayer::sync_single_table_seats_from_chain(state, table_id).await;

    let (socket_id_opt, table_view) = {
        let gs = state.state.read().await;
        let Some(table) = gs.tables.get(&table_id) else { return };
        let base_client_table = table.to_client();
        let view = hide_opponent_cards(&base_client_table, &wallet);
        // 找到该 wallet 对应的 socket_id
        let sid = gs.players.values()
            .find(|p| p.wallet_address.0 == wallet.0)
            .map(|p| p.socket_id.clone());
        (sid, view)
    };

    let payload = TableUpdatePayload {
        table: table_view,
        message: Some("".to_string()),
        from: None,
    };

    let Some(sid_str) = socket_id_opt else {
        tracing::debug!("[join_table_push] socket not found for wallet {}", wallet.0);
        return;
    };
    if let Ok(sid) = sid_str.parse::<socketioxide::socket::Sid>() {
        if let Some(socket) = io.get_socket(sid) {
            if let Err(e) = socket.emit(actions::TABLE_UPDATED, &payload) {
                tracing::warn!("[join_table_push] emit failed for {}: {:?}", sid_str, e);
            }
        } else {
            tracing::debug!("[join_table_push] socket {} not found", sid_str);
        }
    }
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
            let socket_id_map: std::collections::HashMap<String, String> = table.players().iter()
            .filter_map(|(game_pk, wallet_addr)| {
                gs.players.values()
                    .find(|p| p.wallet_address.0 == wallet_addr.0)
                    .map(|player| (game_pk.0.clone(), player.socket_id.clone()))
            })
            .collect();
            let deck_plaintext = table.deck_plaintext()
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

    /// 从链上 `decrypted_cards_info` 构造 `HandRevealResultPayload` 并广播给每个活跃玩家。
    ///
    /// 链上模式下 `mental_poker_game` 无玩家数据，且 `readable_cards` 需要部分解密密文
    /// （c2 - sum(reveal_tokens)），不能直接用原始 `deck_encrypted`。
    ///
    /// 解决方案：调用 Move `decrypted_cards_info` 获取链上已部分解密的 `ciphertext_bytes`
    /// （96 bytes: c1+c2），直接作为 `readable_cards` 发给对应 `owner_seat_index` 的玩家。
    /// 前端用私钥解密 readable_card 后在 `deck_plaintext` 中查找明文牌。
    pub async fn broadcast_player_reveal_result_from_summary(
        &self,
        table_id: u32,
        action: &str,
        summary: &crate::sui_events::TableSummaryV2,
    ) {
        let io = match get_socket_io() {
            Some(io) => io,
            None => return,
        };
        tracing::info!(
            "broadcast_player_reveal_result_from_summary: table_id={} action={}",
            table_id,
            action
        );

        use poker_protocol::crypto::curve::CurvePoint;
        use poker_protocol::crypto::DefaultCurve;
        type P = <DefaultCurve as poker_protocol::crypto::curve::Curve>::Point;

        // 1. 获取 chain_table_id + socket_id 映射
        let (chain_table_id, socket_id_map): (Option<String>, std::collections::HashMap<String, String>) = {
            let gs = self.state.read().await;
            let Some(table) = gs.tables.get(&table_id) else {
                return;
            };
            let map = table.players().iter()
                .filter_map(|(game_pk, wallet_addr)| {
                    gs.players.values()
                        .find(|p| p.wallet_address.0 == wallet_addr.0)
                        .map(|player| (game_pk.0.clone(), player.socket_id.clone()))
                })
                .collect();
            (table.chain_table_id.clone(), map)
        };

        let chain_table_id = match chain_table_id {
            Some(id) => id,
            None => {
                tracing::warn!(
                    "[reveal_result_from_summary] chain_table_id is None, table_id={}",
                    table_id
                );
                return;
            }
        };

        // 2. 从链上获取 decrypted_cards_info（部分解密密文）
        let decrypted_cards = match crate::sui_query::fetch_decrypted_cards_info(
            &self.config.fullnode_url,
            &self.config.sui_package_id,
            &self.config.sui_origin_package_id,
            &chain_table_id,
        )
        .await
        {
            Ok(cards) => cards,
            Err(e) => {
                tracing::warn!(
                    "[reveal_result_from_summary] fetch_decrypted_cards_info failed, table_id={}: {}",
                    table_id,
                    e
                );
                return;
            }
        };

        if decrypted_cards.is_empty() {
            tracing::warn!(
                "[reveal_result_from_summary] decrypted_cards is empty, table_id={}",
                table_id
            );
            return;
        }

        // 3. 构造 deck_plaintext hex 列表（compressed G1 → EcPoint → hex）
        let deck_plaintext: Vec<String> = summary.state.deck_plaintext.iter()
            .filter_map(|bytes| {
                <P as CurvePoint>::from_compressed(bytes).map(|pt| ecpoint_to_hex(&pt))
            })
            .collect();

        // 4. 构建 seat_index → GamePkHex 映射
        let seat_pk_map: std::collections::HashMap<u64, GamePkHex> = summary.crypto.seat_pks.iter()
            .enumerate()
            .filter_map(|(i, pk_bytes)| {
                if pk_bytes.is_empty() {
                    return None;
                }
                <P as CurvePoint>::from_compressed(pk_bytes)
                    .map(|pt| (i as u64, GamePkHex::new(ecpoint_to_hex(&pt))))
            })
            .collect();

        // 5. 按 owner_seat_index 分组，每个玩家的 readable_cards
        //    ciphertext_bytes = 96 bytes (c1 || c2)，即部分解密后的 readable_card
        let mut cards_by_seat: std::collections::HashMap<u64, Vec<ElGamalCiphertextJson>> =
            std::collections::HashMap::new();
        for card in &decrypted_cards {
            if card.ciphertext_bytes.len() != 96 {
                // ciphertext_bytes 为空表示已完全解密（公共牌场景），跳过
                continue;
            }
            let readable = ElGamalCiphertextJson {
                c1_hex: hex::encode(&card.ciphertext_bytes[..48]),
                c2_hex: hex::encode(&card.ciphertext_bytes[48..]),
            };
            cards_by_seat
                .entry(card.owner_seat_index)
                .or_default()
                .push(readable);
        }

        // 6. 为每个玩家构造 payload 并发送
        for (seat_idx, readable_cards) in cards_by_seat {
            if readable_cards.is_empty() {
                continue;
            }
            let pk = match seat_pk_map.get(&seat_idx) {
                Some(pk) => pk.clone(),
                None => {
                    tracing::warn!(
                        "[reveal_result_from_summary] no pk for seat_idx={}, table_id={}",
                        seat_idx,
                        table_id
                    );
                    continue;
                }
            };

            let socket_id = match socket_id_map.get(&pk.0) {
                Some(s) => s.clone(),
                None => continue,
            };

            let payload = HandRevealResultPayload {
                table_id,
                player_pk: pk,
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

    /// 链上模式：从 `TableSummaryV2` 广播 `HAND_REVEAL_RESULT`。
    pub async fn broadcast_hand_reveal_result_from_summary(
        &self,
        table_id: u32,
        summary: &crate::sui_events::TableSummaryV2,
    ) {
        self.broadcast_player_reveal_result_from_summary(
            table_id,
            actions::HAND_REVEAL_RESULT,
            summary,
        )
        .await;
    }

    /// 链上模式：从 `TableSummaryV2` 广播 `REDEAL_RESULT`。
    pub async fn broadcast_redeal_result_from_summary(
        &self,
        table_id: u32,
        summary: &crate::sui_events::TableSummaryV2,
    ) {
        self.broadcast_player_reveal_result_from_summary(
            table_id,
            actions::REDEAL_RESULT,
            summary,
        )
        .await;
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

                for seat in table.local_seats.values_mut() {
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

// ---------------------------------------------------------------------------
// ZK 密码学事件广播（crypto_event）
// ---------------------------------------------------------------------------

/// ZK 密码学事件载荷，对应前端约定的 `crypto_event` WS 消息格式。
///
/// 顶层 `type` 字段固定为 `"crypto_event"`，便于前端区分此事件与现有 GameState 广播。
#[derive(Debug, Clone, Serialize)]
pub(crate) struct CryptoEventPayload {
    /// 固定为 `"crypto_event"`，前端据此区分消息类型
    #[serde(rename = "type")]
    pub msg_type: &'static str,
    /// 事件子类型：shuffle / remask / reveal_token / leave / reconstruct
    pub event_type: &'static str,
    /// 提交证明的玩家公钥（hex）
    pub player_pk: String,
    /// 卡片索引，仅 reveal_token 类事件可能携带；其他类型为 null
    pub card_index: Option<u32>,
    /// 链上交易 digest，若验证在链下完成则为 null（前端显示 "pending onchain"）
    pub tx_digest: Option<String>,
    /// 链上/链下验证是否通过
    pub verified: bool,
    /// 事件时间戳（Unix 秒）
    pub timestamp: u64,
    /// 可选的人话描述
    pub message: Option<String>,
}

impl SocketState {
    /// 广播一条 `crypto_event` 消息给该桌所有 WS 客户端。
    ///
    /// 这是"观察者"事件：广播失败只记日志，不传播错误，绝不阻塞游戏主流程。
    /// `tx_digest` 为链上交易 digest（链下验证场景传 None，前端显示 "pending onchain"）。
    pub async fn broadcast_crypto_event(
        &self,
        table_id: u32,
        event_type: CryptoEventType,
        player_pk: String,
        card_index: Option<u32>,
        verified: bool,
        message: Option<String>,
        tx_digest: Option<String>,
    ) {
        let io = match get_socket_io() {
            Some(io) => io,
            None => {
                tracing::debug!(
                    "[crypto_event] socket.io 未初始化，跳过广播: table_id={}, event_type={}",
                    table_id,
                    event_type.as_str()
                );
                return;
            }
        };

        let payload = CryptoEventPayload {
            msg_type: actions::CRYPTO_EVENT,
            event_type: event_type.as_str(),
            player_pk,
            card_index,
            tx_digest,
            verified,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            message,
        };

        // 复用现有 room emit 机制（与 broadcast_redeal_notice 相同），
        // crypto_event 载荷对所有客户端一致，无需 per-player 定制。
        if let Err(e) = io
            .to(table_room_name(table_id))
            .emit(actions::CRYPTO_EVENT, &payload)
            .await
        {
            tracing::warn!(
                "[crypto_event] 广播失败: table_id={}, event_type={}, error={:?}",
                table_id,
                event_type.as_str(),
                e
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 玩家变更事件广播（player_update）
// ---------------------------------------------------------------------------

/// 玩家变更事件载荷，对应前端约定的 `player_update` WS 消息格式。
///
/// 顶层 `type` 字段固定为 `"player_update"`，用于同步链上玩家加入/离开/踢出/退款事件。
#[derive(Debug, Clone, Serialize)]
pub struct PlayerUpdatePayload {
    #[serde(rename = "type")]
    pub event_type: String,
    pub action: String,
    pub table_id: u64,
    pub seat_index: u64,
    pub pk_hex: String,
    pub wallet: String,
    pub buy_in: u64,
    pub reason: u64,
    pub message: String,
}

/// 广播一条 `player_update` 消息给该桌所有 WS 客户端。
///
/// 这是"观察者"事件：广播失败只记日志，不传播错误，绝不阻塞游戏主流程。
pub async fn broadcast_player_update(
    io: &SocketIo,
    table_id: u64,
    action: &str,
    seat_index: u64,
    pk_hex: String,
    wallet: String,
    buy_in: u64,
    reason: u64,
    message: String,
) {
    let payload = PlayerUpdatePayload {
        event_type: actions::PLAYER_UPDATE.to_string(),
        action: action.to_string(),
        table_id,
        seat_index,
        pk_hex,
        wallet,
        buy_in,
        reason,
        message,
    };
    match io.to(table_room_name(table_id as u32)).emit(actions::PLAYER_UPDATE, &payload).await {
        Ok(_) => {}
        Err(e) => tracing::warn!("broadcast_player_update emit failed: {}", e),
    }
}
