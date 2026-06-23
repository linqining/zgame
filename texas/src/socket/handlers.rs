use std::sync::Arc;

use socketioxide::{
    extract::{Data, SocketRef, State},
    SocketIo,
};

use crate::auth;
use crate::config::Config;
use crate::models::chips_from_mist;
use crate::pokergame::game_state::RevealPhase;
use crate::pokergame::player::truncate_name;
use super::*;

/// 获取用户可用筹码（SUI 余额 * 10000 - locked_chips）。
/// 如果 SUI 余额查询失败，返回 locked_chips 的负值（即 0 可用）。
async fn get_available_chips(state: &Arc<SocketState>, user: &crate::models::User) -> i64 {
    match crate::sui_query::fetch_sui_balance(&state.config.fullnode_url, &user.address).await {
        Ok(balance) => chips_from_mist(balance) - user.locked_chips,
        Err(e) => {
            tracing::warn!("[get_available_chips] failed to fetch SUI balance for {}: {}", user.address, e);
            0
        }
    }
}

/// 为用户操作构建 PTB 并序列化为 tx_kind_b64。
///
/// 根据 `action` 类型选择对应的 PTB 构建器（fold/check/call/raise），
/// 使用 `config.sui_package_id` 作为包 ID，`chain_table_id` 作为链上 Table Object ID，
/// 然后通过 `ptb::serialize_tx_kind` 序列化为可供前端钱包签名的 base64 字符串。
///
/// 会调用 `resolve_shared_object_versions` 解析共享对象的 `initial_shared_version`，
/// 以兼容 Shinami Gas Station（不会自动解析 version 0）。
async fn build_action_ptb_for_user(
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
    let http = crate::sponsor::shared_http_client();
    let pt = ptb::resolve_shared_object_versions(http, &config.fullnode_url, pt).await?;
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

    // 1b. 本地 turn 预检：避免基于过期 turn 构建 PTB 导致 Shinami sponsor 阶段
    //     MoveAbort(ENotPlayerTurn) 502。CurrentTurnChanged 事件会实时同步本地 turn，
    //     此处读取本地 turn 作为快速预判，不命中时直接告知前端刷新状态。
    {
        let gs = state.state.read().await;
        if let Some(table) = gs.tables.get(&table_id) {
            let current_turn = table.turn();
            if current_turn != Some(seat_index) {
                tracing::warn!(
                    "[on_chain_action] not player's turn: table_id={}, seat_index={}, current_turn={:?}, action={}",
                    table_id,
                    seat_index,
                    current_turn,
                    action
                );
                let _ = socket.emit(
                    "error",
                    &serde_json::json!({
                        "msg": format!("Not your turn (current_turn={:?}, your_seat={})", current_turn, seat_index),
                        "action": action,
                        "table_id": table_id,
                        "current_turn": current_turn,
                        "your_seat": seat_index,
                    }),
                );
                return true;
            }
        }
    }

    // 2. 构建 PTB 并序列化
    let tx_kind_b64 = match build_action_ptb_for_user(
        &state.config,
        &chain_table_id,
        seat_index as u64,
        action,
        amount,
    )
    .await
    {
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

/// Type-safe parameters for crypto action PTB construction.
///
/// Each variant carries exactly the fields required by the corresponding
/// `ptb::build_*` builder, replacing the previous 16 `Option<...>` parameters
/// that needed runtime `ok_or_else` validation.
enum CryptoActionParams {
    Shuffle {
        output_cards: Vec<u8>,
        shuffle_proof: Vec<u8>,
    },
    Reconstruct {
        output_cards: Vec<u8>,
        swap_cards: Vec<u8>,
        user_readable_cards: Vec<u8>,
        proof: Vec<u8>,
    },
    Reveal {
        assignment_indices: Vec<u64>,
        reveal_tokens: Vec<Vec<u8>>,
        proof_list: Vec<Vec<u8>>,
    },
    JoinAndShuffle {
        coin_id: String,
        amount_mist: u64,
        pk: Vec<u8>,
        pk_ownership_proof: Vec<u8>,
        mask_cards: Vec<u8>,
        output_cards: Vec<u8>,
        remask_proof: Vec<u8>,
        shuffle_proof: Vec<u8>,
    },
    LeaveWithProof {
        output_cards: Vec<u8>,
        leave_proof: Vec<u8>,
    },
}

/// Build PTB for crypto actions (shuffle/reconstruct/reveal/join_and_shuffle_verified/leave_with_proof_verified)
/// using pre-serialized proof bytes.
///
/// 根据 `params` 的变体选择对应的 PTB 构建器，调用 `ptb::serialize_tx_kind` 序列化为
/// 可供前端钱包签名的 base64 字符串。各 action 仅需提供对应字段，由 `CryptoActionParams`
/// 变体在编译期保证字段完整性。
///
/// 会调用 `resolve_shared_object_versions` 解析共享对象的 `initial_shared_version`，
/// 以兼容 Shinami Gas Station（不会自动解析 version 0）。
async fn build_crypto_action_ptb(
    config: &Config,
    chain_table_id: &str,
    seat_index: u64,
    params: CryptoActionParams,
) -> Result<String, String> {
    use crate::relayer::ptb;
    let package_id = &config.sui_package_id;
    let pt = match params {
        CryptoActionParams::Shuffle {
            output_cards,
            shuffle_proof,
        } => ptb::build_submit_shuffle_ptb(package_id, chain_table_id, output_cards, shuffle_proof)?,
        CryptoActionParams::Reconstruct {
            output_cards,
            swap_cards,
            user_readable_cards,
            proof,
        } => ptb::build_submit_reconstruct_deck_ptb(
            package_id,
            chain_table_id,
            output_cards,
            swap_cards,
            user_readable_cards,
            proof,
        )?,
        CryptoActionParams::Reveal {
            assignment_indices,
            reveal_tokens,
            proof_list,
        } => ptb::build_submit_reveal_tokens_ptb(
            package_id,
            chain_table_id,
            assignment_indices,
            reveal_tokens,
            proof_list,
        )?,
        CryptoActionParams::JoinAndShuffle {
            coin_id,
            amount_mist,
            pk,
            pk_ownership_proof,
            mask_cards,
            output_cards,
            remask_proof,
            shuffle_proof,
        } => ptb::build_join_and_shuffle_ptb(
            package_id,
            chain_table_id,
            seat_index,
            &coin_id,
            amount_mist,
            pk,
            pk_ownership_proof,
            mask_cards,
            output_cards,
            remask_proof,
            shuffle_proof,
        )?,
        CryptoActionParams::LeaveWithProof {
            output_cards,
            leave_proof,
        } => ptb::build_leave_with_proof_ptb(
            package_id,
            chain_table_id,
            seat_index,
            output_cards,
            leave_proof,
        )?,
    };
    let http = crate::sponsor::shared_http_client();
    let pt = ptb::resolve_shared_object_versions(http, &config.fullnode_url, pt).await?;
    ptb::serialize_tx_kind(pt)
}

/// Try on-chain mode for crypto actions (shuffle/reconstruct/reveal/join_and_shuffle_verified).
/// Returns `true` if handled (on-chain mode), `false` if local mode should proceed.
///
/// 行为与 `try_on_chain_action` 一致：当 `sui_on_chain_enabled` 为 `false` 时返回 `false`；
/// 为 `true` 时始终返回 `true`，并 emit `action_signing_request` 给前端签名上链。
async fn try_on_chain_crypto_action(
    socket: &SocketRef,
    state: &Arc<SocketState>,
    table_id: u32,
    action: &str,
    tx_kind_b64: String,
    gas_budget: Option<u64>,
) -> bool {
    if !state.config.sui_on_chain_enabled {
        return false;
    }

    let socket_id = socket.id.to_string();

    // 1. 查找 pk_hex 和 seat_index（与 try_on_chain_action 一致）
    let (pk_hex, seat_index, _chain_table_id) = {
        let gs = state.state.read().await;
        let player = gs.players.get(&socket_id);
        let table = gs.tables.get(&table_id);
        let pk_hex = player.and_then(|p| {
            table.and_then(|t| t.get_pk_hex_by_wallet_address(&p.wallet_address.0))
        });
        let seat_index = pk_hex
            .as_ref()
            .and_then(|pk| table.and_then(|t| t.pk_to_seat.get(pk).copied()));
        match pk_hex {
            Some(pk) => (pk, seat_index, table.and_then(|t| t.chain_table_id.clone())),
            None => {
                tracing::warn!(
                    "[on_chain_crypto_action] cannot resolve pk_hex for socket_id={}, table_id={}, action={}",
                    socket_id,
                    table_id,
                    action
                );
                let _ = socket.emit(
                    "error",
                    &serde_json::json!({
                        "msg": format!("on-chain mode: cannot resolve player pk for action {}", action),
                        "action": action,
                        "table_id": table_id,
                    }),
                );
                return true;
            }
        }
    };

    // 2. emit action_signing_request 给前端
    let mut payload = serde_json::json!({
        "action": action,
        "table_id": table_id,
        "seat_index": seat_index.unwrap_or(0),
        "tx_kind_b64": tx_kind_b64,
        "pk_hex": pk_hex.0,
    });
    if let Some(budget) = gas_budget {
        payload["gas_budget"] = serde_json::Value::Number(serde_json::Number::from(budget));
    }
    tracing::info!(
        "[on_chain_crypto_action] emit action_signing_request: action={}, table_id={}, seat_index={:?}",
        action,
        table_id,
        seat_index
    );
    let _ = socket.emit("action_signing_request", &payload);
    true
}

// ============================================================================
// Crypto proof serialization helpers (JSON → bytes)
// ============================================================================

use crate::pokergame::game_state::{
    ElGamalCiphertextJson, ReconstructProofJson, ShuffleProofJson, SubmitRevealTokenJson,
};
use crate::relayer::proof_bytes;

/// 将 `Vec<ElGamalCiphertextJson>` 序列化为 flat bytes（每个密文 96 字节）。
fn serialize_ciphertexts_from_json(
    cards: &[ElGamalCiphertextJson],
) -> Result<Vec<u8>, String> {
    let cts: Vec<poker_protocol::crypto::ElGamalCiphertext> = cards
        .iter()
        .map(|c| c.to_ciphertext())
        .collect::<Result<Vec<_>, _>>()?;
    Ok(proof_bytes::ciphertexts_to_bytes(&cts))
}

/// 将 `ShuffleProofJson` 序列化为 Move 合约期望的字节格式。
fn serialize_shuffle_proof_from_json(proof: &ShuffleProofJson) -> Result<Vec<u8>, String> {
    let p = proof.to_proof()?;
    Ok(proof_bytes::serialize_shuffle_proof(&p))
}

/// 将 `ReconstructProofJson` 序列化为 Move 合约期望的字节格式。
fn serialize_reconstruct_proof_from_json(proof: &ReconstructProofJson) -> Result<Vec<u8>, String> {
    let p = proof.to_proof()?;
    Ok(proof_bytes::serialize_reconstruct_proof(&p))
}

/// 将单个 `SubmitRevealTokenJson` 的 `reveal_token_hex` 转换为 48 字节 G1 compressed bytes。
fn serialize_reveal_token_bytes(token: &SubmitRevealTokenJson) -> Result<Vec<u8>, String> {
    let pt = poker_protocol::z_poker::convert::hex_to_ecpoint(&token.reveal_token_hex)?;
    Ok(proof_bytes::g1_to_bytes(&pt))
}

/// 将 `SubmitRevealTokenJson` 的 `reveal_token_proof` 序列化为 Move 合约期望的字节格式。
fn serialize_reveal_token_proof_bytes(
    token: &SubmitRevealTokenJson,
) -> Result<Vec<u8>, String> {
    let p = token.reveal_token_proof.to_proof()?;
    Ok(proof_bytes::serialize_reveal_token_proof(&p))
}

/// 从链上 TableSummaryV2.crypto 同步最新加密状态到 `table.summary.crypto`。
///
/// 解决问题：客户端本地缓存的 deck_encrypted 可能与链上不同步（例如其他玩家已提交 shuffle），
/// 直接用本地 deck 生成 remask/leave proof 会导致链上验证失败（ERemaskProofFailed）。
///
/// 同步逻辑与 `relayer/mod.rs::sync_table_state` 中的 crypto 同步一致：
/// 将链上 `TableSummaryV2.crypto` 整体克隆到本地 table 状态，由 `Table::deck_encrypted()`
/// 访问器在读取时负责反序列化。
///
/// 返回 `true` 表示同步成功（或链上 deck 为空时跳过），`false` 表示同步失败。
pub async fn sync_deck_from_chain(
    state: &SocketState,
    table_id: u32,
    chain_table_id: &str,
) -> bool {
    let summary = match crate::sui_query::fetch_table_summary(
        &state.config.fullnode_url,
        &state.config.sui_package_id,
        chain_table_id,
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                "[sync_deck_from_chain] table {} fetch_table_summary failed: {}",
                table_id,
                e
            );
            return false;
        }
    };

    if summary.crypto.deck_encrypted.is_empty() {
        tracing::debug!(
            "[sync_deck_from_chain] table {} on-chain deck_encrypted is empty, skip sync",
            table_id
        );
        return true;
    }

    let mut gs = state.state.write().await;
    if let Some(table) = gs.tables.get_mut(&table_id) {
        // 1. 更新 table.summary.crypto（上链模式权威数据源，供 deck_encrypted() 访问器使用）
        if table.summary.crypto != summary.crypto {
            tracing::info!(
                "[sync_deck_from_chain] table {} crypto synced from chain ({} cards)",
                table_id,
                summary.crypto.deck_encrypted.len()
            );
            table.summary.crypto = summary.crypto.clone();
        }

        // 2. 同时反序列化并更新 mental_poker_game.deck_encrypted（作为访问器反序列化失败时的回退数据源）
        //    这确保 deck_encrypted() accessor 的 fallback 路径也有最新的链上 deck 数据。
        use poker_protocol::crypto::curve::CurvePoint;
        use poker_protocol::crypto::{DefaultCurve, ElGamalCiphertext};
        type P = <DefaultCurve as poker_protocol::crypto::curve::Curve>::Point;

        let mut synced_deck: Vec<ElGamalCiphertext> =
            Vec::with_capacity(summary.crypto.deck_encrypted.len());
        let mut all_ok = true;
        for ct_bytes in &summary.crypto.deck_encrypted {
            if ct_bytes.len() != 96 {
                all_ok = false;
                break;
            }
            let (c1_bytes, c2_bytes) = ct_bytes.split_at(48);
            match (
                <P as CurvePoint>::from_compressed(c1_bytes),
                <P as CurvePoint>::from_compressed(c2_bytes),
            ) {
                (Some(c1), Some(c2)) => synced_deck.push(ElGamalCiphertext { c1, c2 }),
                _ => {
                    all_ok = false;
                    break;
                }
            }
        }
        if all_ok && table.mental_poker_game.deck_encrypted != synced_deck {
            tracing::info!(
                "[sync_deck_from_chain] table {} mental_poker_game.deck_encrypted synced from chain ({} cards)",
                table_id,
                synced_deck.len()
            );
            table.mental_poker_game.deck_encrypted = synced_deck;
        }

        // 3. 同步 aggregated_pk 到 key_manager（作为 aggregated_pk() 访问器的回退数据源）
        if !summary.crypto.aggregated_pk.is_empty() {
            if let Some(pk) = <P as CurvePoint>::from_compressed(&summary.crypto.aggregated_pk) {
                let current_pk = table.mental_poker_game.key_manager.get_aggregated_pk();
                if current_pk != pk {
                    table.mental_poker_game.key_manager.set_aggregated_pk(pk);
                }
            }
        }
    }
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
                    .map_or(false, |t| {
                        t.seats().get(&seat_id)
                            .and_then(|seat| seat.player.as_ref())
                            .map_or(false, |gp| gp.wallet_address.0 == wa.0)
                    })
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

// ============================================================================
// SIT_DOWN_V2 helpers
// ============================================================================

/// Validates SIT_DOWN_V2 request: auth, amount, pk, player, balance.
/// Returns `Some((player, player_pk))` if valid, `None` if error already emitted.
async fn validate_sit_down_request(
    s: &SocketRef,
    state: &Arc<SocketState>,
    payload: &SitDownV2Payload,
) -> Option<(Player, EcPoint)> {
    let socket_id = s.id.to_string();

    let claims = match auth::verify_token(&payload.token, &state.config.jwt_secret) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("[SIT_DOWN_V2] Token verification failed for socket_id: {}, error: {}", socket_id, e);
            let _ = s.emit("error", &serde_json::json!({"msg": "Authentication failed, please reconnect your wallet"}));
            return None;
        }
    };
    let user_id = claims.user.id.clone();
    tracing::info!("[SIT_DOWN_V2] Received from {}: table_id={}, seat_id={}, amount={}, pk_hex={}, user_id={}",
        socket_id, payload.table_id, payload.seat_id, payload.amount, payload.pk_hex, user_id);

    // E3 修复：校验 amount > 0，避免 0 或负值导致的逻辑错误
    if payload.amount == 0 {
        tracing::warn!("[SIT_DOWN_V2] Invalid amount=0 from socket_id={}", socket_id);
        let _ = s.emit("error", &serde_json::json!({"msg": "Amount must be positive"}));
        return None;
    }

    // E3 修复：使用 i64::try_from 避免 u64 -> i64 转换溢出
    let deduct = match i64::try_from(payload.amount) {
        Ok(v) => -v,
        Err(_) => {
            tracing::warn!("[SIT_DOWN_V2] Amount too large for i64: {}", payload.amount);
            let _ = s.emit("error", &serde_json::json!({"msg": "Amount too large"}));
            return None;
        }
    };

    let player_pk = match hex_to_ecpoint(&**payload.pk_hex) {
        Ok(pk) => pk,
        Err(e) => {
            tracing::warn!("[SIT_DOWN_V2] Invalid pk_hex: {}", e);
            return None;
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
            return None;
        }
        None => {
            let db_user = state.db.find_user_by_id(&user_id).await;
            match db_user {
                Some(user) => {
                    let bankroll = get_available_chips(&state, &user).await;
                    let mut gs = state.state.write().await;
                    let p = Player {
                        socket_id: socket_id.clone(),
                        id: user.id,
                        name: user.name,
                        bankroll,
                        wallet_address: WalletAddress::new(user.address.clone()),
                    };
                    gs.players.insert(socket_id.clone(), p.clone());
                    p
                }
                None => {
                    tracing::warn!("[SIT_DOWN_V2] User not found in DB for user_id: {}", user_id);
                    return None;
                }
            }
        }
    };

    let player_id = player.id.clone();

    // E3 修复：检查用户余额是否足够（SUI 余额 * 10000 - locked_chips）
    let db_user = state.db.find_user_by_id(&player_id).await;
    if let Some(ref user) = db_user {
        let available = get_available_chips(&state, user).await;
        if available < payload.amount as i64 {
            tracing::warn!(
                "[SIT_DOWN_V2] Insufficient chips: user_id={}, available={}, required={}",
                player_id,
                available,
                payload.amount
            );
            let _ = s.emit("error", &serde_json::json!({"msg": "Insufficient chips"}));
            return None;
        }
    }

    let _ = deduct; // suppress unused warning (preserved from original)
    Some((player, player_pk))
}

/// Builds the join_and_shuffle_verified PTB for on-chain mode and emits signing request.
/// Returns `true` if on-chain mode was handled (PTB emitted or error emitted), `false` if not on-chain mode.
async fn build_sit_down_ptb(
    s: &SocketRef,
    state: &Arc<SocketState>,
    payload: &SitDownV2Payload,
    player_pk: &EcPoint,
) -> bool {
    // Task 6: on-chain 模式下构建 join_and_shuffle_verified PTB + emit 签名请求，跳过本地 join
    if !state.config.sui_on_chain_enabled {
        return false;
    }

    // 解析 chain_table_id（seat_index 直接使用 payload.seat_id）
    let chain_table_id = {
        let gs = state.state.read().await;
        gs.tables.get(&payload.table_id)
            .and_then(|t| t.chain_table_id.clone())
    };
    let chain_table_id = match chain_table_id {
        Some(cid) => cid,
        None => {
            tracing::warn!(
                "[SIT_DOWN_V2] on-chain mode: cannot resolve chain_table_id, table_id={}",
                payload.table_id
            );
            let _ = s.emit("error", &serde_json::json!({
                "msg": "on-chain mode: cannot resolve chain_table_id for join_and_shuffle_verified",
                "action": "join_and_shuffle_verified",
                "table_id": payload.table_id,
            }));
            return true;
        }
    };

    // SIT_DOWN_V2 是关键路径：必须用阻塞式 RPC 拉最新链上 deck，
    // 确保后续 remask proof 验证使用的是链上 deck（与合约 verify_remask_with_transcript_or_abort 一致）。
    // relayer 缓存可能滞后，本地验证通过但上链仍会失败。
    if !sync_deck_from_chain(&state, payload.table_id, &chain_table_id).await {
        tracing::warn!(
            "[SIT_DOWN_V2] on-chain mode: sync_deck_from_chain failed, table_id={}, pk_hex={}",
            payload.table_id, payload.pk_hex
        );
        let _ = s.emit("error", &serde_json::json!({
            "msg": "on-chain mode: failed to sync deck from chain, please retry",
            "action": "join_and_shuffle_verified",
            "table_id": payload.table_id,
        }));
        return true;
    }

    // 使用同步后的链上 deck 验证客户端 remask proof，提前拦截过期 proof，避免上链失败。
    // 兼容 Move 合约 remask_proof::verify：必须使用 FiatShamirTranscript 和协议名 zk_mask_shuffle_proof_v1。
    {
        use poker_protocol::zk_shuffle::transcript_ext::{CryptoTranscript, FiatShamirTranscript};
        let remask_proof = match payload.mask_and_shuffle_round.remask_proof.to_remask_proof() {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("[SIT_DOWN_V2] on-chain mode: remask_proof parse failed: {}", e);
                let _ = s.emit("error", &serde_json::json!({
                    "msg": format!("on-chain mode: remask_proof parse failed: {}", e),
                    "action": "join_and_shuffle_verified",
                    "table_id": payload.table_id,
                }));
                return true;
            }
        };
        let mask_cards = match payload.mask_and_shuffle_round.mask_cards.iter()
            .map(|c| c.to_ciphertext())
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("[SIT_DOWN_V2] on-chain mode: mask_cards parse failed: {}", e);
                let _ = s.emit("error", &serde_json::json!({
                    "msg": format!("on-chain mode: mask_cards parse failed: {}", e),
                    "action": "join_and_shuffle_verified",
                    "table_id": payload.table_id,
                }));
                return true;
            }
        };
        let input_cards = {
            let gs = state.state.read().await;
            gs.tables.get(&payload.table_id)
                .map(|t| t.deck_encrypted())
                .unwrap_or_default()
        };
        // 诊断日志：对比 server 链上 deck (input_cards) 与 client payload deck (mask_cards) 的 c1
        {
            use poker_protocol::crypto::curve::CurvePoint;
            let input_len = input_cards.len();
            let mask_len = mask_cards.len();
            let c1_mismatches: Vec<usize> = (0..input_len.min(mask_len))
                .filter(|&i| input_cards[i].c1 != mask_cards[i].c1)
                .collect();
            tracing::info!(
                "[SIT_DOWN_V2] deck c1 diag: table_id={}, input_cards={}, mask_cards={}, c1_mismatch_count={}, mismatch_indices={:?}",
                payload.table_id, input_len, mask_len, c1_mismatches.len(),
                if c1_mismatches.len() > 10 { &c1_mismatches[..10] } else { &c1_mismatches[..] }
            );
            if !c1_mismatches.is_empty() {
                let i = c1_mismatches[0];
                tracing::warn!(
                    "[SIT_DOWN_V2] first c1 mismatch at index {}: input_c1={}, mask_c1={}",
                    i,
                    hex::encode(input_cards[i].c1.compress().as_ref()),
                    hex::encode(mask_cards[i].c1.compress().as_ref())
                );
            }
        }
        let mut transcript = FiatShamirTranscript::new(b"zk_mask_shuffle_proof_v1");
        if !remask_proof.verify(&input_cards, &mask_cards, player_pk, &mut transcript) {
            tracing::warn!(
                "[SIT_DOWN_V2] on-chain mode: remask_proof verification failed against synced deck, table_id={}, pk_hex={}",
                payload.table_id, payload.pk_hex
            );
            let _ = s.emit("error", &serde_json::json!({
                "msg": "on-chain mode: remask proof verification failed, deck out of sync, please refresh table and retry",
                "action": "join_and_shuffle_verified",
                "table_id": payload.table_id,
            }));
            return true;
        }
        tracing::info!(
            "[SIT_DOWN_V2] on-chain mode: remask_proof verified against synced deck, table_id={}, pk_hex={}",
            payload.table_id, payload.pk_hex
        );
    }

    // 序列化各 proof bytes
    let pk_bytes = proof_bytes::pk_to_bytes(player_pk);
    let pk_ownership_proof_bytes = match payload.pk_proof.to_proof() {
        Ok(p) => proof_bytes::serialize_pk_ownership_proof(&p),
        Err(e) => {
            tracing::warn!("[SIT_DOWN_V2] on-chain mode: pk_proof serialize failed: {}", e);
            let _ = s.emit("error", &serde_json::json!({
                "msg": format!("on-chain mode: pk_ownership_proof serialization failed: {}", e),
                "action": "join_and_shuffle_verified",
                "table_id": payload.table_id,
            }));
            return true;
        }
    };
    let output_cards_bytes = serialize_ciphertexts_from_json(&payload.mask_and_shuffle_round.output_cards);
    let output_cards_bytes = match output_cards_bytes {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!("[SIT_DOWN_V2] on-chain mode: output_cards serialize failed: {}", e);
            let _ = s.emit("error", &serde_json::json!({
                "msg": format!("on-chain mode: output_cards serialization failed: {}", e),
                "action": "join_and_shuffle_verified",
                "table_id": payload.table_id,
            }));
            return true;
        }
    };
    let mask_cards_bytes = serialize_ciphertexts_from_json(&payload.mask_and_shuffle_round.mask_cards);
    let mask_cards_bytes = match mask_cards_bytes {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!("[SIT_DOWN_V2] on-chain mode: mask_cards serialize failed: {}", e);
            let _ = s.emit("error", &serde_json::json!({
                "msg": format!("on-chain mode: mask_cards serialization failed: {}", e),
                "action": "join_and_shuffle_verified",
                "table_id": payload.table_id,
            }));
            return true;
        }
    };
    let remask_proof_bytes = match payload.mask_and_shuffle_round.remask_proof.to_remask_proof() {
        Ok(p) => proof_bytes::serialize_dleq_proof(&p),
        Err(e) => {
            tracing::warn!("[SIT_DOWN_V2] on-chain mode: remask_proof serialize failed: {}", e);
            let _ = s.emit("error", &serde_json::json!({
                "msg": format!("on-chain mode: remask_proof serialization failed: {}", e),
                "action": "join_and_shuffle_verified",
                "table_id": payload.table_id,
            }));
            return true;
        }
    };
    let shuffle_proof_bytes = match payload.mask_and_shuffle_round.shuffle_proof.to_proof() {
        Ok(p) => proof_bytes::serialize_shuffle_proof(&p),
        Err(e) => {
            tracing::warn!("[SIT_DOWN_V2] on-chain mode: shuffle_proof serialize failed: {}", e);
            let _ = s.emit("error", &serde_json::json!({
                "msg": format!("on-chain mode: shuffle_proof serialization failed: {}", e),
                "action": "join_and_shuffle_verified",
                "table_id": payload.table_id,
            }));
            return true;
        }
    };

    let params = match payload.coin_object_id.clone() {
        Some(coin_id) => CryptoActionParams::JoinAndShuffle {
            coin_id,
            amount_mist: payload.amount as u64 * 100_000,
            pk: pk_bytes,
            pk_ownership_proof: pk_ownership_proof_bytes,
            mask_cards: mask_cards_bytes,
            output_cards: output_cards_bytes,
            remask_proof: remask_proof_bytes,
            shuffle_proof: shuffle_proof_bytes,
        },
        None => {
            let e = "missing coin_object_id for join_and_shuffle_verified".to_string();
            tracing::warn!(
                "[SIT_DOWN_V2] on-chain mode: failed to build PTB: {}",
                e
            );
            let _ = s.emit("error", &serde_json::json!({
                "msg": format!("on-chain mode: failed to build join_and_shuffle_verified PTB: {}", e),
                "action": "join_and_shuffle_verified",
                "table_id": payload.table_id,
            }));
            return true;
        }
    };

    match build_crypto_action_ptb(
        &state.config,
        &chain_table_id,
        payload.seat_id as u64,
        params,
    )
    .await
    {
        Ok(tx_kind_b64) => {
            // join_and_shuffle_verified 是新玩家入座，此时玩家尚未加入 table.players，
            // 不能走 try_on_chain_crypto_action 的 table 查找逻辑。
            // 直接使用 payload 中的 pk_hex 和 seat_id emit 签名请求。
            let payload_json = serde_json::json!({
                "action": "join_and_shuffle_verified",
                "table_id": payload.table_id,
                "seat_index": payload.seat_id,
                "tx_kind_b64": tx_kind_b64,
                "pk_hex": payload.pk_hex.0,
            });
            tracing::info!(
                "[on_chain_crypto_action] emit action_signing_request: action=join_and_shuffle_verified, table_id={}, seat_index={}",
                payload.table_id, payload.seat_id
            );
            let _ = s.emit("action_signing_request", &payload_json);
            return true;
        }
        Err(e) => {
            tracing::warn!(
                "[SIT_DOWN_V2] on-chain mode: failed to build PTB: {}",
                e
            );
            let _ = s.emit("error", &serde_json::json!({
                "msg": format!("on-chain mode: failed to build join_and_shuffle_verified PTB: {}", e),
                "action": "join_and_shuffle_verified",
                "table_id": payload.table_id,
            }));
            return true;
        }
    }
}

/// Broadcasts the sit down result (success or failure) and starts game loop if all complete.
async fn broadcast_sit_down(
    io: &SocketIo,
    state: &Arc<SocketState>,
    table_id: u32,
    seat_id: u32,
    pk_hex: &GamePkHex,
    amount: u64,
    player_id: &str,
    player_name: &str,
    result: Result<(bool, JoinResult), JoinError>,
) {
    match result {
        Ok((all_complete, join_result)) => {
            // 锁定筹码（入座时扣除可用余额）
            let _ = state.db.lock_chips(player_id, amount as i64).await;

            let msg = match join_result {
                JoinResult::JoinedAndShuffled => format!("{} sat down in Seat {} and shuffled", player_name, seat_id),
                JoinResult::JoinedWaiting => format!("{} sat down in Seat {}, waiting for next hand", player_name, seat_id),
            };
            broadcast::broadcast_to_table(io, state, table_id, Some(&msg)).await;

            // ZK 可视化：shuffle 证明验证成功（join_and_shuffle_verified 中 shuffle 已验证）
            state.broadcast_crypto_event(
                table_id,
                broadcast::CryptoEventType::Shuffle,
                pk_hex.to_string(),
                None,
                true,
                Some("shuffle proof verified".to_string()),
                None,
            ).await;

            if all_complete {
                tracing::info!("[SIT_DOWN_V2] All players shuffled, starting game loop for table {}", table_id);
                state.start_game_loop(io.clone(), state.clone(), table_id).await;
            }
        }
        Err(e) => {
            tracing::warn!("[SIT_DOWN_V2] Failed to join and shuffle: {}", e);
            // ZK 可视化：shuffle 证明验证失败
            state.broadcast_crypto_event(
                table_id,
                broadcast::CryptoEventType::Shuffle,
                pk_hex.to_string(),
                None,
                false,
                Some(format!("shuffle proof verification failed: {}", e)),
                None,
            ).await;
        }
    }
}

// ============================================================================
// STAND_UP helpers
// ============================================================================

/// Handles STAND_UP on-chain mode: builds leave_with_proof_verified PTB + emits signing request.
/// Returns `true` if on-chain mode was handled (handler should return),
/// `false` if not on-chain mode or fell through to local mode (resolved was None).
async fn handle_stand_up_on_chain(
    s: &SocketRef,
    state: &Arc<SocketState>,
    payload: &StandUpPayload,
    pk_hex: &GamePkHex,
    player_pk: &EcPoint,
    table_id: u32,
    socket_id: &str,
) -> bool {
    // on-chain 模式：构建 leave_with_proof_verified PTB + emit 签名请求，跳过本地移除。
    // 玩家移除由 relayer 从 PlayerLeft/PlayerRefund 事件同步回本地。
    // 若无法解析 chain_table_id/seat_index，回退到本地移除逻辑。
    if !state.config.sui_on_chain_enabled {
        return false;
    }

    // 客户端已通过 HTTP API (`/api/sui/action/build`) 直接提交
    // leave_with_proof_verified 交易时，leave_round 为 None。
    // 此时跳过本地 proof 验证和 PTB 构建，仅清理 socket 状态，
    // 等待 relayer 从 PlayerLeft 事件同步。
    let Some(leave_round_ref) = payload.leave_round.as_ref() else {
        tracing::info!(
            "[STAND_UP] on-chain mode: leave_round is None (client already submitted tx via HTTP API), table_id={}, pk_hex={}",
            table_id, pk_hex
        );
        return true;
    };

    // 解析 chain_table_id 和 seat_index
    // 优先用 payload.pk_hex 查找；若 pk_to_seat 中无匹配，
    // 再通过 wallet_address → get_pk_hex_by_wallet_address 查找（对齐 try_on_chain_crypto_action 逻辑）。
    let resolved = {
        let gs = state.state.read().await;
        let table = gs.tables.get(&table_id);
        let cid = table.and_then(|t| t.chain_table_id.clone());
        let sid = table.and_then(|t| t.pk_to_seat.get(pk_hex).copied());
        // pk_to_seat 中未找到时，通过 wallet_address 间接查找
        let sid = match sid {
            Some(s) => Some(s),
            None => {
                let player = gs.players.get(socket_id);
                let resolved_pk = player.and_then(|p| {
                    table.and_then(|t| t.get_pk_hex_by_wallet_address(&p.wallet_address.0))
                });
                resolved_pk.as_ref().and_then(|pk| table.and_then(|t| t.pk_to_seat.get(pk).copied()))
            }
        };
        match (cid, sid) {
            (Some(c), Some(s)) => Some((c, s)),
            (None, _) => {
                tracing::warn!(
                    "[STAND_UP] on-chain mode: chain_table_id is None, table_id={}, pk_hex={}",
                    table_id, pk_hex
                );
                None
            }
            (Some(_), None) => {
                tracing::warn!(
                    "[STAND_UP] on-chain mode: seat_index not found for pk_hex={}, table_id={}, falling back to local remove",
                    pk_hex, table_id
                );
                None
            }
        }
    };

    if let Some((chain_table_id, seat_index)) = resolved {

    // 阻塞式 RPC 拉最新链上 deck，确保 leave proof 验证使用链上 deck
    if !sync_deck_from_chain(&state, table_id, &chain_table_id).await {
        tracing::warn!(
            "[STAND_UP] on-chain mode: sync_deck_from_chain failed, table_id={}, pk_hex={}",
            table_id, pk_hex
        );
        let _ = s.emit("error", &serde_json::json!({
            "msg": "on-chain mode: failed to sync deck from chain, please retry",
            "action": "leave_with_proof_verified",
            "table_id": table_id,
        }));
        return true;
    }

    // 本地验证 leave proof（提前拦截无效 proof，避免上链失败）
    {
        use poker_protocol::zk_shuffle::transcript_ext::{CryptoTranscript, FiatShamirTranscript};
        let leave_round = match leave_round_ref.to_leave_game_round() {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("[STAND_UP] on-chain mode: leave_round parse failed: {}", e);
                let _ = s.emit("error", &serde_json::json!({
                    "msg": format!("on-chain mode: leave_round parse failed: {}", e),
                    "action": "leave_with_proof_verified",
                    "table_id": table_id,
                }));
                return true;
            }
        };
        let current_deck = {
            let gs = state.state.read().await;
            gs.tables.get(&table_id)
                .map(|t| t.deck_encrypted().to_vec())
                .unwrap_or_default()
        };
        if leave_round.input_cards.len() != current_deck.len() {
            tracing::warn!(
                "[STAND_UP] on-chain mode: input_cards length mismatch: {} vs deck {}",
                leave_round.input_cards.len(), current_deck.len()
            );
            let _ = s.emit("error", &serde_json::json!({
                "msg": "on-chain mode: input_cards length mismatch with current deck, deck out of sync, please refresh and retry",
                "action": "leave_with_proof_verified",
                "table_id": table_id,
            }));
            return true;
        }
        for (i, input_ct) in leave_round.input_cards.iter().enumerate() {
            if input_ct.c1 != current_deck[i].c1 || input_ct.c2 != current_deck[i].c2 {
                tracing::warn!(
                    "[STAND_UP] on-chain mode: input card {} does not match current deck",
                    i
                );
                let _ = s.emit("error", &serde_json::json!({
                    "msg": "on-chain mode: input_cards do not match current deck, deck out of sync, please refresh and retry",
                    "action": "leave_with_proof_verified",
                    "table_id": table_id,
                }));
                return true;
            }
        }
        let mut transcript = FiatShamirTranscript::new(b"zk_leave_proof_v1");
        if !leave_round.leave_proof.verify(&leave_round.input_cards, &leave_round.output_cards, player_pk, &mut transcript) {
            tracing::warn!(
                "[STAND_UP] on-chain mode: leave proof verification failed, table_id={}, pk_hex={}",
                table_id, pk_hex
            );
            let _ = s.emit("error", &serde_json::json!({
                "msg": "on-chain mode: leave proof verification failed, please regenerate proof and retry",
                "action": "leave_with_proof_verified",
                "table_id": table_id,
            }));
            return true;
        }
        tracing::info!(
            "[STAND_UP] on-chain mode: leave proof verified against synced deck, table_id={}, pk_hex={}",
            table_id, pk_hex
        );
    }

    // 序列化 output_cards 和 leave_proof bytes
    let output_cards_bytes = match serialize_ciphertexts_from_json(&leave_round_ref.output_cards) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!("[STAND_UP] on-chain mode: output_cards serialize failed: {}", e);
            let _ = s.emit("error", &serde_json::json!({
                "msg": format!("on-chain mode: output_cards serialization failed: {}", e),
                "action": "leave_with_proof_verified",
                "table_id": table_id,
            }));
            return true;
        }
    };
    let leave_proof_bytes = match leave_round_ref.leave_proof.to_leave_proof() {
        Ok(p) => crate::relayer::proof_bytes::serialize_dleq_proof(&p),
        Err(e) => {
            tracing::warn!("[STAND_UP] on-chain mode: leave_proof serialize failed: {}", e);
            let _ = s.emit("error", &serde_json::json!({
                "msg": format!("on-chain mode: leave_proof serialization failed: {}", e),
                "action": "leave_with_proof_verified",
                "table_id": table_id,
            }));
            return true;
        }
    };

    // 构建 PTB + emit 签名请求
    match build_crypto_action_ptb(
        &state.config,
        &chain_table_id,
        seat_index as u64,
        CryptoActionParams::LeaveWithProof {
            output_cards: output_cards_bytes,
            leave_proof: leave_proof_bytes,
        },
    )
    .await
    {
        Ok(tx_kind_b64) => {
            let payload_json = serde_json::json!({
                "action": "leave_with_proof_verified",
                "table_id": table_id,
                "seat_index": seat_index,
                "tx_kind_b64": tx_kind_b64,
                "pk_hex": pk_hex.0.clone(),
            });
            tracing::info!(
                "[STAND_UP] on-chain mode: emit action_signing_request: action=leave_with_proof_verified, table_id={}, seat_index={}",
                table_id, seat_index
            );
            let _ = s.emit("action_signing_request", &payload_json);
            return true;
        }
        Err(e) => {
            tracing::warn!(
                "[STAND_UP] on-chain mode: failed to build leave_with_proof_verified PTB: {}",
                e
            );
            let _ = s.emit("error", &serde_json::json!({
                "msg": format!("on-chain mode: failed to build leave_with_proof_verified PTB: {}", e),
                "action": "leave_with_proof_verified",
                "table_id": table_id,
            }));
            return true;
        }
    }
    } // end if let Some((chain_table_id, seat_index)) = resolved

    false // fall through to local mode
}

/// Handles STAND_UP local mode: verifies leave proof, removes player, broadcasts.
async fn handle_stand_up_local(
    state: &Arc<SocketState>,
    io: &SocketIo,
    payload: &StandUpPayload,
    pk_hex: &GamePkHex,
    player_pk: &EcPoint,
    table_id: u32,
    socket_id: &str,
) {
    // Verify LeaveProof and remove player
    let player_id = {
        let gs = state.state.read().await;
        gs.players.get(socket_id).map(|p| p.id.clone())
    };

    // 幂等检查：若玩家已不在 table.players 和 pk_to_seat 中，说明已被移除
    // （relayer 已同步 PlayerLeft 事件、或 reset_for_next_hand 清理、或重复 STAND_UP）。
    // 直接返回成功，避免 "Player not found" 警告。
    {
        let gs = state.state.read().await;
        if let Some(table) = gs.tables.get(&table_id) {
            if !table.players().contains_key(pk_hex) && !table.pk_to_seat.contains_key(pk_hex) {
                tracing::info!(
                    "[STAND_UP] player {} already removed from table {}, idempotent skip",
                    pk_hex, table_id
                );
                drop(gs);
                // 广播最新状态，让前端同步
                let tables_info = state.get_current_tables().await;
                let players_info = state.get_current_players().await;
                let _ = io.emit(actions::TABLES_UPDATED, &tables_info).await;
                let _ = io.emit(actions::PLAYERS_UPDATED, &players_info).await;
                return;
            }
        } else {
            tracing::warn!("[STAND_UP] table {} not found", table_id);
            return;
        }
    }

    // 注：on-chain 模式已在上方提前 return，以下为 off-chain 模式的本地处理路径。
    let (stand_msg, need_clear, leave_proof_verified) = {
        let mut gs = state.state.write().await;
        if let Some(table) = gs.tables.get_mut(&table_id) {
            let msg = table.find_player_by_pk(pk_hex)
                .and_then(|seat| {
                    seat.player.as_ref().map(|p| format!("{} left the table", p.name))
                });

            // Return chips before removing
            if let Some(seat) = table.find_player_by_pk(pk_hex) {
                if let Some(ref pid) = player_id {
                    let _ = state.db.unlock_chips(pid, seat.stack as i64).await;
                }
            }

            // Verify leave proof and remove player
            // off-chain 模式下 leave_round 可能为 None（例如客户端未生成 proof），
            // 此时直接走 remove_player_by_pk 回退路径。
            let verified = match payload.leave_round.as_ref() {
                Some(lr) => match table.leave_player_with_proof(pk_hex, player_pk, lr) {
                    Ok(()) => {
                        tracing::info!("[STAND_UP] Leave proof verified, player {} removed", pk_hex);
                        true
                    }
                    Err(e) => {
                        tracing::warn!("[STAND_UP] Leave proof verification failed: {}, falling back to remove_player_by_pk", e);
                        table.remove_player_by_pk(pk_hex);
                        false
                    }
                },
                None => {
                    tracing::info!("[STAND_UP] No leave_round provided, removing player {} by pk", pk_hex);
                    table.remove_player_by_pk(pk_hex);
                    false
                }
            };

            let clear = table.active_players().len() == 1;
            (msg, clear, verified)
        } else { (None, false, false) }
    };

    broadcast::broadcast_to_table(io, state, table_id, stand_msg.as_deref()).await;

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
        None,
    ).await;

    let tables_info = state.get_current_tables().await;
    let players_info = state.get_current_players().await;
    let _ = io.emit(actions::TABLES_UPDATED, &tables_info).await;
    let _ = io.emit(actions::PLAYERS_UPDATED, &players_info).await;

    if need_clear {
        state.stop_game_loop(table_id).await;
        game_loop::clear_for_one_player(io, state.clone(), table_id).await;
    }
}

// ============================================================================
// REVEAL_SUBMIT helpers
// ============================================================================

/// Serializes reveal tokens and their proofs to bytes.
/// Returns `Some((reveal_tokens_bytes, reveal_proof_bytes_list))` on success,
/// or `None` if serialization failed (error already emitted).
fn serialize_reveal_proofs(
    s: &SocketRef,
    reveal_tokens: &[SubmitRevealTokenJson],
    table_id: u32,
) -> Option<(Vec<Vec<u8>>, Vec<Vec<u8>>)> {
    let mut reveal_tokens_bytes: Vec<Vec<u8>> = Vec::with_capacity(reveal_tokens.len());
    let mut reveal_proof_bytes_list: Vec<Vec<u8>> = Vec::with_capacity(reveal_tokens.len());
    for (idx, token) in reveal_tokens.iter().enumerate() {
        match serialize_reveal_token_bytes(token) {
            Ok(b) => reveal_tokens_bytes.push(b),
            Err(e) => {
                tracing::warn!("[REVEAL_SUBMIT] on-chain mode: token[{}] reveal_token_hex serialize failed: {}", idx, e);
                let _ = s.emit("error", &serde_json::json!({
                    "msg": format!("on-chain mode: reveal token[{}] serialization failed: {}", idx, e),
                    "action": "reveal",
                    "table_id": table_id,
                }));
                return None;
            }
        }
        match serialize_reveal_token_proof_bytes(token) {
            Ok(b) => reveal_proof_bytes_list.push(b),
            Err(e) => {
                tracing::warn!("[REVEAL_SUBMIT] on-chain mode: token[{}] proof serialize failed: {}", idx, e);
                let _ = s.emit("error", &serde_json::json!({
                    "msg": format!("on-chain mode: reveal token[{}] proof serialization failed: {}", idx, e),
                    "action": "reveal",
                    "table_id": table_id,
                }));
                return None;
            }
        }
    }
    Some((reveal_tokens_bytes, reveal_proof_bytes_list))
}

/// Builds the reveal PTB and emits signing request.
/// Handles assignment_indices fetching, filtering, PTB building, and signing request emission.
/// All paths emit (signing request or error) — caller should return after calling this.
async fn build_reveal_ptb_and_emit_signing_request(
    s: &SocketRef,
    state: &Arc<SocketState>,
    table_id: u32,
    chain_table_id: &str,
    seat_index: u64,
    reveal_tokens: &[SubmitRevealTokenJson],
    reveal_tokens_bytes: Vec<Vec<u8>>,
    reveal_proof_bytes_list: Vec<Vec<u8>>,
    deck_encrypted: &[Vec<u8>],
    reveal_phase: crate::pokergame::game_state::RevealPhase,
) {
    // assignment_indices: 通过链上 reveal_assignments + 本地 deck_encrypted 推导全局索引
    // 修复 0..n 占位导致的 MoveAbort (ENotPendingRevealer)：
    // 链上 assignments 是跨所有玩家的全局 vector，0..n 可能指向属于其他玩家或已解密的 assignment。
    // showdown 阶段 pending_players = [owner]，只匹配属于当前玩家且未解密的 assignment。
    let token_assignment_pairs: Vec<(usize, u64)> = match crate::sui_query::fetch_reveal_assignment_indices(
        &state.config.fullnode_url,
        &state.config.sui_package_id,
        &state.config.sui_origin_package_id,
        chain_table_id,
        reveal_tokens,
        deck_encrypted,
        seat_index,
    )
    .await
    {
        Ok(pairs) => pairs,
        Err(e) => {
            tracing::warn!(
                "[REVEAL_SUBMIT] on-chain mode: failed to derive assignment_indices: {}",
                e
            );
            let _ = s.emit("error", &serde_json::json!({
                "msg": format!("on-chain mode: failed to derive assignment_indices: {}", e),
                "action": "reveal",
                "table_id": table_id,
            }));
            return;
        }
    };

    // 没有匹配到任何属于该玩家的待解密 assignment → 玩家未提交自己手牌的 reveal token
    if token_assignment_pairs.is_empty() {
        tracing::warn!(
            "[REVEAL_SUBMIT] on-chain mode: no pending assignment matched for seat {} (tokens={}, table_id={}); player must submit reveal tokens for their own hand cards",
            seat_index,
            reveal_tokens.len(),
            table_id
        );
        let _ = s.emit("error", &serde_json::json!({
            "msg": "on-chain mode: no pending reveal assignment matched your tokens; please submit reveal tokens for your own hand cards",
            "action": "reveal",
            "table_id": table_id,
        }));
        return;
    }

    // 根据 token_assignment_pairs 过滤 reveal_tokens_bytes 和 reveal_proof_bytes_list
    let assignment_indices: Vec<u64> = token_assignment_pairs.iter().map(|(_, idx)| *idx).collect();
    let reveal_tokens_bytes: Vec<Vec<u8>> = token_assignment_pairs
        .iter()
        .map(|(token_idx, _)| reveal_tokens_bytes[*token_idx].clone())
        .collect();
    let reveal_proof_bytes_list: Vec<Vec<u8>> = token_assignment_pairs
        .iter()
        .map(|(token_idx, _)| reveal_proof_bytes_list[*token_idx].clone())
        .collect();

    match build_crypto_action_ptb(
        &state.config,
        chain_table_id,
        seat_index,
        CryptoActionParams::Reveal {
            assignment_indices,
            reveal_tokens: reveal_tokens_bytes,
            proof_list: reveal_proof_bytes_list,
        },
    )
    .await
    {
        Ok(tx_kind_b64) => {
            // ShowdownReveal 阶段的 reveal 提交可能触发 settle_hand（手牌评估、底池分配等重计算），
            // Shinami 自动估算的 gas 不足以覆盖该路径，因此对 ShowdownReveal 阶段统一使用
            // 更高的 gas budget（sponsor_reveal_gas_budget），避免最后一次 reveal 因 gas 不足失败。
            let gas_budget = if reveal_phase == crate::pokergame::game_state::RevealPhase::ShowdownReveal {
                Some(state.config.sponsor_reveal_gas_budget)
            } else {
                None
            };
            let _ = try_on_chain_crypto_action(s, state, table_id, "reveal", tx_kind_b64, gas_budget).await;
            return;
        }
        Err(e) => {
            tracing::warn!(
                "[REVEAL_SUBMIT] on-chain mode: failed to build PTB: {}",
                e
            );
            let _ = s.emit("error", &serde_json::json!({
                "msg": format!("on-chain mode: failed to build reveal PTB: {}", e),
                "action": "reveal",
                "table_id": table_id,
            }));
            return;
        }
    }
}

/// Advances the reveal phase locally when all players have completed.
/// Calls the appropriate broadcast function based on the reveal phase.
async fn advance_reveal_phase_locally(
    state: &Arc<SocketState>,
    table_id: u32,
    all_complete: bool,
    reveal_phase: RevealPhase,
) {
    if all_complete {
        tracing::info!("[REVEAL_SUBMIT] All players completed reveal for table {}", table_id);
        match reveal_phase {
            RevealPhase::None => {
                tracing::warn!("[REVEAL_SUBMIT] all_complete but reveal_phase is None, table_id={}", table_id);
            }
            RevealPhase::HandReveal => {
                state.broadcast_hand_reveal_result(table_id).await;
            }
            RevealPhase::ShowdownReveal => {
                state.broadcast_showdown_result(table_id).await;
            }
            RevealPhase::CommunityReveal => {
                state.broadcast_community_cards(table_id).await;
            }
            RevealPhase::RedealReveal => {
                state.broadcast_redeal_result(table_id).await;
            }
        }
    }
}

/// Try on-chain mode for SHUFFLE_SUBMIT.
/// Returns `true` if handled (on-chain mode), `false` if local mode should proceed.
async fn handle_shuffle_submit_on_chain(
    s: &SocketRef,
    state: &Arc<SocketState>,
    payload: &ShuffleSubmitPayload,
    pk_hex: &GamePkHex,
) -> bool {
    if !state.config.sui_on_chain_enabled {
        return false;
    }

    // 解析 chain_table_id 与 seat_index
    let (chain_table_id, seat_index) = {
        let gs = state.state.read().await;
        let table = gs.tables.get(&payload.table_id);
        let seat_index = table.and_then(|t| t.pk_to_seat.get(pk_hex).copied());
        let chain_table_id = table.and_then(|t| t.chain_table_id.clone());
        match (chain_table_id, seat_index) {
            (Some(cid), Some(sid)) => (cid, sid),
            _ => {
                tracing::warn!(
                    "[SHUFFLE_SUBMIT] on-chain mode: cannot resolve chain_table_id/seat_index, table_id={}, pk_hex={}",
                    payload.table_id, pk_hex
                );
                let _ = s.emit("error", &serde_json::json!({
                    "msg": "on-chain mode: cannot resolve chain_table_id or seat_index for shuffle",
                    "action": "shuffle",
                    "table_id": payload.table_id,
                }));
                return true;
            }
        }
    };

    // 序列化 proof bytes
    let output_cards_bytes = serialize_ciphertexts_from_json(&payload.output_cards);
    let shuffle_proof_bytes = serialize_shuffle_proof_from_json(&payload.shuffle_proof);

    match (output_cards_bytes, shuffle_proof_bytes) {
        (Ok(oc), Ok(sp)) => {
            match build_crypto_action_ptb(
                &state.config,
                &chain_table_id,
                seat_index as u64,
                CryptoActionParams::Shuffle {
                    output_cards: oc,
                    shuffle_proof: sp,
                },
            )
            .await
            {
                Ok(tx_kind_b64) => {
                    let _ = try_on_chain_crypto_action(s, state, payload.table_id, "shuffle", tx_kind_b64, None).await;
                    return true;
                }
                Err(e) => {
                    tracing::warn!(
                        "[SHUFFLE_SUBMIT] on-chain mode: failed to build PTB: {}, falling through (no local fallback in on-chain mode)",
                        e
                    );
                    let _ = s.emit("error", &serde_json::json!({
                        "msg": format!("on-chain mode: failed to build shuffle PTB: {}", e),
                        "action": "shuffle",
                        "table_id": payload.table_id,
                    }));
                    return true;
                }
            }
        }
        (Err(e), _) | (_, Err(e)) => {
            tracing::warn!(
                "[SHUFFLE_SUBMIT] on-chain mode: proof serialization failed: {}",
                e
            );
            let _ = s.emit("error", &serde_json::json!({
                "msg": format!("on-chain mode: shuffle proof serialization failed: {}", e),
                "action": "shuffle",
                "table_id": payload.table_id,
            }));
            return true;
        }
    }
}

/// Try on-chain mode for RECONSTRUCT_SUBMIT.
/// Returns `true` if handled (on-chain mode), `false` if local mode should proceed.
async fn handle_reconstruct_submit_on_chain(
    s: &SocketRef,
    state: &Arc<SocketState>,
    payload: &ReconstructSubmitPayload,
    pk_hex: &GamePkHex,
) -> bool {
    if !state.config.sui_on_chain_enabled {
        return false;
    }

    // 解析 chain_table_id 与 seat_index
    let (chain_table_id, seat_index) = {
        let gs = state.state.read().await;
        let table = gs.tables.get(&payload.table_id);
        let seat_index = table.and_then(|t| t.pk_to_seat.get(pk_hex).copied());
        let chain_table_id = table.and_then(|t| t.chain_table_id.clone());
        match (chain_table_id, seat_index) {
            (Some(cid), Some(sid)) => (cid, sid),
            _ => {
                tracing::warn!(
                    "[RECONSTRUCT_SUBMIT] on-chain mode: cannot resolve chain_table_id/seat_index, table_id={}, pk_hex={}",
                    payload.table_id, pk_hex
                );
                let _ = s.emit("error", &serde_json::json!({
                    "msg": "on-chain mode: cannot resolve chain_table_id or seat_index for reconstruct",
                    "action": "reconstruct",
                    "table_id": payload.table_id,
                }));
                return true;
            }
        }
    };

    // 序列化 proof bytes
    let output_cards_bytes = serialize_ciphertexts_from_json(&payload.output_cards);
    let swap_cards_bytes = serialize_ciphertexts_from_json(&payload.swap_cards);
    let user_readable_cards_bytes = serialize_ciphertexts_from_json(&payload.user_readable_cards);
    let reconstruct_proof_bytes = serialize_reconstruct_proof_from_json(&payload.proof);

    match (output_cards_bytes, swap_cards_bytes, user_readable_cards_bytes, reconstruct_proof_bytes) {
        (Ok(oc), Ok(sc), Ok(urc), Ok(rp)) => {
            match build_crypto_action_ptb(
                &state.config,
                &chain_table_id,
                seat_index as u64,
                CryptoActionParams::Reconstruct {
                    output_cards: oc,
                    swap_cards: sc,
                    user_readable_cards: urc,
                    proof: rp,
                },
            )
            .await
            {
                Ok(tx_kind_b64) => {
                    let _ = try_on_chain_crypto_action(s, state, payload.table_id, "reconstruct", tx_kind_b64, None).await;
                    return true;
                }
                Err(e) => {
                    tracing::warn!(
                        "[RECONSTRUCT_SUBMIT] on-chain mode: failed to build PTB: {}",
                        e
                    );
                    let _ = s.emit("error", &serde_json::json!({
                        "msg": format!("on-chain mode: failed to build reconstruct PTB: {}", e),
                        "action": "reconstruct",
                        "table_id": payload.table_id,
                    }));
                    return true;
                }
            }
        }
        (Err(e), _, _, _) | (_, Err(e), _, _) | (_, _, Err(e), _) | (_, _, _, Err(e)) => {
            tracing::warn!(
                "[RECONSTRUCT_SUBMIT] on-chain mode: proof serialization failed: {}",
                e
            );
            let _ = s.emit("error", &serde_json::json!({
                "msg": format!("on-chain mode: reconstruct proof serialization failed: {}", e),
                "action": "reconstruct",
                "table_id": payload.table_id,
            }));
            return true;
        }
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
        // tracing::info!("on_connect FETCH_LOBBY_INFO: {}", claims.user.id.clone());
        let new_socket_id = s.id.to_string();
        let user_id = claims.user.id.clone();

        let old_player = {
            let gs = state.state.read().await;
            gs.players.values().find(|t| t.id == user_id).cloned()
        };
        // tracing::info!("on_connect FETCH_LOBBY_INFO: {} old_sid={:?}", claims.user.id.clone(), old_player.as_ref().map(|p| p.socket_id.clone()));

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
                        ids.push(table.summary.id);
                    }
                }
                ids
            };

            let db_user = state.db.find_user_by_id(&user_id).await;
            if let Some(user) = db_user {
                let bankroll = get_available_chips(&state, &user).await;
                let mut gs = state.state.write().await;
                gs.players.insert(new_socket_id.clone(), Player {
                    socket_id: new_socket_id.clone(),
                    id: user.id,
                    name: user.name,
                    bankroll,
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
            // tracing::info!("on_connect FETCH_LOBBY_INFO: {} old_sid={:?}", claims.user.id.clone(), old_player.as_ref().map(|p| p.socket_id.clone()));

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
        // tracing::info!("on_connect FETCH_LOBBY_INFO: {}", claims.user.id.clone());


        for tid in &table_ids_to_broadcast {
            broadcast::broadcast_to_table(&io, &state, *tid, None).await;
        }

        if !is_reconnect {
            let db_user = state.db.find_user_by_id(&claims.user.id).await;
            if let Some(user) = db_user {
                // tracing::info!("on_connect FETCH_LOBBY_INFO: {} user={:?}", claims.user.id.clone(), user);
                let bankroll = get_available_chips(&state, &user).await;
                state.state.write().await.players.insert(s.id.to_string(), Player {
                    socket_id: s.id.to_string(),
                    id: user.id,
                    name: user.name,
                    wallet_address: WalletAddress::new(user.address.clone()),
                    bankroll,
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

        broadcast::join_table_push(&io, &state, table_id, wallet).await;
        // 通知桌上所有已有玩家：新玩家加入后刷新各自的 table view
        // broadcast_to_table 会为每个玩家定制 view（hide_opponent_cards），
        // join_table_push 只发给新加入的 socket，已有玩家不会收到更新。
        broadcast::broadcast_to_table(&io, &state, table_id, Some("player joined")).await;
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

        // on-chain 模式：玩家移除和筹码退还由链上 leave_with_proof_verified 交易
        // （由 STAND_UP 触发）+ relayer 事件同步完成。LEAVE_TABLE 仅清理 socket，
        // 不执行本地 unlock_chips 或 leave_talbe_and_clear_shuffle，避免双重退还/移除。
        if state.config.sui_on_chain_enabled {
            let player_still_seated = {
                let gs = state.state.read().await;
                gs.tables.get(&table_id)
                    .map(|t| pk_hex.as_ref().map_or(false, |pk| t.find_player_by_pk(pk).is_some()))
                    .unwrap_or(false)
            };
            if player_still_seated {
                tracing::info!(
                    "[LEAVE_TABLE] on-chain mode: skipping local chip/player removal for table_id={}, pk_hex={:?} (handled by on-chain leave tx + relayer)",
                    table_id, pk_hex
                );
            }
            let tables_info = state.get_current_tables().await;
            let players_info = state.get_current_players().await;
            let _ = io.emit(actions::TABLES_UPDATED, &tables_info).await;
            let _ = io.emit(actions::PLAYERS_UPDATED, &players_info).await;
            let _ = s.emit(actions::TABLE_LEFT, &TableLeftPayload { tables: tables_info, table_id, reason: None });
            return;
        }

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
            let _ = state.db.unlock_chips(&pid, stack as i64).await;
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
        let _ = s.emit(actions::TABLE_LEFT, &TableLeftPayload { tables: tables_info, table_id, reason: None });

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
                t.players().iter()
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
        // 1. Validate request (auth, amount, pk, player, balance)
        let (player, player_pk) = match validate_sit_down_request(&s, &state, &payload).await {
            Some(v) => v,
            None => return,
        };

        // 2. On-chain mode: build PTB + emit signing request (returns true if handled)
        if build_sit_down_ptb(&s, &state, &payload, &player_pk).await {
            return;
        }

        // 3. Local mode: init seat and shuffle
        let player_id = player.id.clone();
        let player_name = truncate_name(&player.name, 12);
        let result = state.join_player_and_shuffle(
            payload.table_id,
            player,
            player_pk,
            payload.pk_proof,
            payload.mask_and_shuffle_round,
            payload.seat_id,
            payload.amount,
        ).await;

        // 4. Broadcast result
        broadcast_sit_down(
            &io, &state, payload.table_id, payload.seat_id, &payload.pk_hex,
            payload.amount, &player_id, &player_name, result,
        ).await;
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
            // E3 修复：检查余额（SUI 余额 * 10000 - locked_chips）
            let db_user = state.db.find_user_by_id(&pid).await;
            if let Some(ref user) = db_user {
                let available = get_available_chips(&state, user).await;
                if available < payload.amount as i64 {
                    tracing::warn!(
                        "[REBUY] Insufficient chips: user_id={}, available={}, required={}",
                        pid,
                        available,
                        payload.amount
                    );
                    let _ = s.emit("error", &serde_json::json!({"msg": "Insufficient chips"}));
                    // 余额不足，回滚 rebuy_player 的座位状态变更
                    let mut gs = state.state.write().await;
                    if let Some(table) = gs.tables.get_mut(&payload.table_id) {
                        // 简单回滚：从 seat stack 中减去刚加的 amount
                        if let Some(seat) = table.local_seats.get_mut(&payload.seat_id) {
                            seat.stack = seat.stack.saturating_sub(payload.amount);
                        }
                    }
                    broadcast::broadcast_to_table(&io, &state, payload.table_id, None).await;
                    return;
                }
            }
            // 锁定筹码（rebuy 时扣除可用余额）
            let _ = state.db.lock_chips(&pid, payload.amount as i64).await;
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

        // On-chain mode: build PTB + emit signing request (returns true if handled)
        if handle_stand_up_on_chain(&s, &state, &payload, &pk_hex, &player_pk, table_id, &socket_id).await {
            return;
        }

        // Local mode: verify leave proof, remove player, broadcast
        handle_stand_up_local(&state, &io, &payload, &pk_hex, &player_pk, table_id, &socket_id).await;
    });

    socket.on(actions::SITTING_OUT, async move |_s: SocketRef, Data::<SittingPayload>(payload), io: SocketIo, State(state): State<Arc<SocketState>>| {
        {
            let mut gs = state.state.write().await;
            if let Some(table) = gs.tables.get_mut(&payload.table_id) {
                if let Some(seat) = table.local_seats.get_mut(&payload.seat_id) {
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
                if let Some(seat) = table.local_seats.get_mut(&payload.seat_id) {
                    seat.sitting_out = false;
                }
                table.summary.hand_over && table.active_players().len() == MIN_START_NUM as usize
            } else { false }
        };

        broadcast::broadcast_to_table(&io, &state, payload.table_id, None).await;

        if should_start {
            state.start_game_loop(io, state.clone(), payload.table_id).await;
        }
    });

    socket.on(actions::SHUFFLE_SUBMIT, async move |s: SocketRef, Data::<serde_json::Value>(data), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let payload: Result<ShuffleSubmitPayload, _> = serde_json::from_value(data.clone());
        let payload = match payload {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("[SHUFFLE_SUBMIT] Failed to parse payload: {}, raw: {:?}", e, data);
                return;
            }
        };

        let socket_id = s.id.to_string();
        tracing::info!("[SHUFFLE_SUBMIT] request received, pk_hex={}, table_id={}", payload.pk_hex, payload.table_id);
        let pk_hex = GamePkHex::new(payload.pk_hex.to_lowercase());

        // A3 修复：验证发送者拥有所声称的 pk_hex
        if !verify_socket_sender(&s, &state, payload.table_id, &pk_hex).await {
            tracing::warn!("[SHUFFLE_SUBMIT] Failed to verify socket sender, pk_hex={}, table_id={}", pk_hex, payload.table_id);
            return;
        }

        // Task 3: on-chain 模式下构建 submit_shuffle PTB + emit 签名请求，跳过本地验证
        if handle_shuffle_submit_on_chain(&s, &state, &payload, &pk_hex).await {
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
            Ok(reveal_started) => {
                tracing::debug!("[SHUFFLE_SUBMIT] shuffle submitted and verified, pk_hex={}, table_id={}, reveal_started={}", pk_hex, payload.table_id, reveal_started);
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
                    None,
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
                    None,
                ).await;
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

        // Task 4: on-chain 模式下构建 submit_reconstruct_deck PTB + emit 签名请求，跳过本地验证
        if handle_reconstruct_submit_on_chain(&s, &state, &payload, &pk_hex).await {
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
            None,
        ).await;
    });

    socket.on(actions::REVEAL_SUBMIT, async move |s: SocketRef, Data::<RevealSubmitPayload>(payload), io: SocketIo, State(state): State<Arc<SocketState>>| {
        // tracing::info!("[REVEAL_SUBMIT] Received RevealSubmitPayload: {:?}", payload);
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

        // Task 5: 若 payload 携带 reveal_tokens，则按 on-chain / 本地模式分别处理
        if let Some(reveal_tokens) = payload.reveal_tokens.as_ref() {
            // 解析 pk_hex：优先使用 payload.pk_hex，否则通过 wallet_address 查找
            let pk_hex = match payload.pk_hex.clone() {
                Some(p) => p,
                None => {
                    let gs = state.state.read().await;
                    gs.tables.get(&payload.table_id)
                        .and_then(|t| t.get_pk_hex_by_wallet_address(&wallet_address))
                        .unwrap_or_default()
                }
            };

            if pk_hex.0.is_empty() {
                tracing::warn!(
                    "[REVEAL_SUBMIT] cannot resolve pk_hex for socket_id={}, table_id={}",
                    socket_id, payload.table_id
                );
                let _ = s.emit("error", &serde_json::json!({"msg": "Cannot resolve pk_hex for reveal"}));
                return;
            }

            // A3 修复：验证发送者拥有所声称的 pk_hex
            if !verify_socket_sender(&s, &state, payload.table_id, &pk_hex).await {
                return;
            }

            // 获取 reveal phase（与 HTTP submit_reveal_token 一致），在 mark_reveal_complete 之前读取
            let reveal_phase = state.get_reveal_phase_for_table(payload.table_id).await.unwrap_or_default();

            // Task 5: on-chain 模式下构建 submit_player_reveal_tokens PTB + emit 签名请求
            if state.config.sui_on_chain_enabled {
                // 解析 chain_table_id、seat_index 与 deck_encrypted
                let (chain_table_id, seat_index, deck_encrypted) = {
                    let gs = state.state.read().await;
                    let table = gs.tables.get(&payload.table_id);
                    let seat_index = table.and_then(|t| t.pk_to_seat.get(&pk_hex).copied());
                    let chain_table_id = table.and_then(|t| t.chain_table_id.clone());
                    let deck_encrypted = table.map(|t| t.summary.crypto.deck_encrypted.clone());
                    match (chain_table_id, seat_index, deck_encrypted) {
                        (Some(cid), Some(sid), Some(de)) => (cid, sid, de),
                        _ => {
                            tracing::warn!(
                                "[REVEAL_SUBMIT] on-chain mode: cannot resolve chain_table_id/seat_index/deck_encrypted, table_id={}, pk_hex={}",
                                payload.table_id, pk_hex
                            );
                            let _ = s.emit("error", &serde_json::json!({
                                "msg": "on-chain mode: cannot resolve chain_table_id, seat_index or deck_encrypted for reveal",
                                "action": "reveal",
                                "table_id": payload.table_id,
                            }));
                            return;
                        }
                    }
                };

                // 序列化 reveal_tokens 与 proof bytes
                let (reveal_tokens_bytes, reveal_proof_bytes_list) = match serialize_reveal_proofs(&s, reveal_tokens, payload.table_id) {
                    Some(v) => v,
                    None => return,
                };

                // 构建 PTB 并 emit 签名请求（helper 内部已处理所有路径，调用后直接 return）
                build_reveal_ptb_and_emit_signing_request(
                    &s, &state, payload.table_id, &chain_table_id, seat_index as u64,
                    reveal_tokens, reveal_tokens_bytes, reveal_proof_bytes_list, &deck_encrypted,
                    reveal_phase,
                ).await;
                return;
            }

            // 本地模式：复用 HTTP submit_reveal_token 逻辑
            let player_pk = match poker_protocol::z_poker::convert::hex_to_ecpoint(&pk_hex.0) {
                Ok(pt) => pt,
                Err(e) => {
                    tracing::warn!("[REVEAL_SUBMIT] invalid pk_hex: {}", e);
                    let _ = s.emit("error", &serde_json::json!({"msg": format!("Invalid pk_hex: {}", e)}));
                    return;
                }
            };

            let tokens_len = reveal_tokens.len();
            if tokens_len == 0 {
                tracing::warn!("[REVEAL_SUBMIT] no reveal tokens provided");
                let _ = s.emit("error", &serde_json::json!({"msg": "No reveal tokens provided"}));
                return;
            }

            let tokens: Result<Vec<_>, String> = reveal_tokens.iter()
                .enumerate()
                .map(|(idx, item)| {
                    let encrypted_card = item.encrypted_card.to_ciphertext()
                        .map_err(|e| format!("Token[{}]: Invalid encrypted_card: {}", idx, e))?;
                    let reveal_token = poker_protocol::z_poker::convert::hex_to_ecpoint(&item.reveal_token_hex)
                        .map_err(|e| format!("Token[{}]: Invalid reveal_token_hex: {}", idx, e))?;
                    let proof = item.reveal_token_proof.to_proof()
                        .map_err(|e| format!("Token[{}]: Invalid reveal_token_proof: {}", idx, e))?;
                    Ok(poker_protocol::z_poker::protocol::RevealToken {
                        user_public_key: player_pk,
                        encrypted_card,
                        proof,
                        reveal_token,
                    })
                })
                .collect();

            let tokens = match tokens {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!("[REVEAL_SUBMIT] token parse error: {}", e);
                    let _ = s.emit("error", &serde_json::json!({"msg": format!("Token parse error: {}", e)}));
                    return;
                }
            };

            if let Err(e) = state.submit_reveal_tokens_for_pk(payload.table_id, &pk_hex, tokens).await {
                tracing::warn!("[REVEAL_SUBMIT] submit failed, table_id={}, pk_hex={}, error={}", payload.table_id, pk_hex, e);
                state.broadcast_crypto_event(
                    payload.table_id,
                    broadcast::CryptoEventType::RevealToken,
                    pk_hex.0.clone(),
                    None,
                    false,
                    Some(format!("reveal_token proof verification failed: {}", e)),
                    None,
                ).await;
                let _ = s.emit("error", &serde_json::json!({"msg": format!("Reveal token submit failed: {}", e)}));
                return;
            }

            // ZK 可视化：reveal_token 证明验证成功
            state.broadcast_crypto_event(
                payload.table_id,
                broadcast::CryptoEventType::RevealToken,
                pk_hex.0.clone(),
                None,
                true,
                Some("reveal_token proof verified".to_string()),
                None,
            ).await;

            let all_complete = match state.mark_reveal_complete_for_pk(payload.table_id, &pk_hex).await {
                Ok(result) => {
                    tracing::info!("[REVEAL_SUBMIT] reveal marked, table_id={}, pk_hex={}, all_complete={}", payload.table_id, pk_hex, result);
                    result
                }
                Err(e) => {
                    tracing::warn!("[REVEAL_SUBMIT] mark reveal failed, table_id={}, pk_hex={}, error={}", payload.table_id, pk_hex, e);
                    let _ = s.emit("error", &serde_json::json!({"msg": format!("Mark reveal failed: {}", e)}));
                    return;
                }
            };

            advance_reveal_phase_locally(&state, payload.table_id, all_complete, reveal_phase).await;
            broadcast::broadcast_to_table(&io, &state, payload.table_id, None).await;
            return;
        }

        // 旧路径：reveal_tokens 为 None，保持原有行为（仅标记完成）
        // 获取 reveal phase（与 HTTP submit_reveal_token 一致），在 mark_reveal_complete 之前读取
        let reveal_phase = state.get_reveal_phase_for_table(payload.table_id).await.unwrap_or_default();
        let pk_hex_str = {
            let gs = state.state.read().await;
            gs.tables.get(&payload.table_id)
                .and_then(|t| t.get_pk_hex_by_wallet_address(&wallet_address))
                .map(|pk| pk.0.clone())
        };
        // ZK 可视化：reveal_token 证明验证成功（与 HTTP 路径一致）
        if let Some(pk_str) = pk_hex_str.as_ref() {
            state.broadcast_crypto_event(
                payload.table_id,
                broadcast::CryptoEventType::RevealToken,
                pk_str.clone(),
                None,
                true,
                Some("reveal_token proof verified".to_string()),
                None,
            ).await;
        }
        let all_complete = {
            let mut gs = state.state.write().await;
            if let Some(table) = gs.tables.get_mut(&payload.table_id) {
                let pk_hex = table.get_pk_hex_by_wallet_address(&wallet_address);
                pk_hex.map_or(false, |pk| table.mark_player_reveal_complete(&pk))
            } else {
                false
            }
        };
        advance_reveal_phase_locally(&state, payload.table_id, all_complete, reveal_phase).await;
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
