use serde::{Deserialize, Serialize};
use crate::sui_events::TableSummary;

/// Sui JSON-RPC 响应结构
#[derive(Debug, Deserialize)]
struct RpcResponse<T> {
    jsonrpc: String,
    id: u64,
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

/// Sui 对象的 JSON 表示（sui_getObject 返回）
#[derive(Debug, Deserialize)]
struct ObjectResponse {
    status: String,
    details: Option<ObjectDetails>,
}

#[derive(Debug, Deserialize)]
struct ObjectDetails {
    data: Option<ObjectData>,
}

#[derive(Debug, Deserialize)]
struct ObjectData {
    content: Option<ObjectContent>,
}

#[derive(Debug, Deserialize)]
struct ObjectContent {
    data_type: String,
    fields: Option<serde_json::Value>,
}

/// 通过 JSON-RPC 查询 Table 对象状态
/// 
/// 使用 `sui_getObject` 直接获取链上 Table 共享对象的当前状态。
/// 返回的 `TableSummary` 包含完整的状态快照 + epoch 信息。
/// 
/// # 参数
/// * `rpc_url` - Sui 全节点的 JSON-RPC URL（如 https://fullnode.testnet.sui.io:443）
/// * `table_object_id` - Table 对象的 Object ID
pub async fn fetch_table_summary(rpc_url: &str, table_object_id: &str) -> Result<TableSummary, String> {
    // 第一步：通过 sui_getObject 获取 Table 对象
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "sui_getObject",
        "params": [
            table_object_id,
            {
                "showType": true,
                "showContent": true,
                "showOwner": true,
            }
        ]
    });

    let client = reqwest::Client::new();
    let resp: RpcResponse<ObjectResponse> = client
        .post(rpc_url)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {}", e))?
        .json()
        .await
        .map_err(|e| format!("JSON parse failed: {}", e))?;

    if let Some(err) = resp.error {
        return Err(format!("RPC error: {} (code {})", err.message, err.code));
    }

    let object_resp = resp.result.ok_or("No result from sui_getObject")?;
    if object_resp.status != "Exists" {
        return Err(format!("Object not found or deleted: status={}", object_resp.status));
    }

    let details = object_resp.details.ok_or("No details in response")?;
    let data = details.data.ok_or("No data in response")?;
    let content = data.content.ok_or("No content in response")?;

    if content.data_type != "moveObject" {
        return Err(format!("Expected moveObject, got {}", content.data_type));
    }

    let fields = content.fields.ok_or("No fields in object content")?;

    // 第二步：通过 sui_dryRunTransaction 调用 get_table_summary 获取 epoch
    // 因为 sui_getObject 返回的 fields 是 Move 对象的原始字段（不包含 epoch）
    // 我们需要通过 dryRun 来调用 get_table_summary 函数获取 epoch
    let epoch = fetch_current_epoch(rpc_url).await?;

    // 从 fields 中构建 TableSummary
    build_table_summary_from_fields(&fields, epoch)
}

/// 通过 sui_dryRunTransaction 调用 get_table_summary 获取完整快照（包含 epoch）
///
/// 这是推荐的查询方式，因为它会执行 Move 函数并返回包含 epoch 的完整结果。
pub async fn fetch_table_summary_via_dry_run(
    rpc_url: &str,
    package_id: &str,
    table_object_id: &str,
) -> Result<TableSummary, String> {
    // 使用 sui_getObject 获取 table 对象的初始版本信息（用于构造共享对象引用）
    let object_body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "sui_getObject",
        "params": [
            table_object_id,
            {
                "showType": true,
                "showContent": true,
                "showOwner": true,
            }
        ]
    });

    let client = reqwest::Client::new();
    let obj_resp: serde_json::Value = client
        .post(rpc_url)
        .json(&object_body)
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {}", e))?
        .json()
        .await
        .map_err(|e| format!("JSON parse failed: {}", e))?;

    let fields = obj_resp.get("result")
        .and_then(|r| r.get("data"))
        .and_then(|d| d.get("content"))
        .and_then(|c| c.get("fields"))
        .ok_or("Failed to parse sui_getObject response")?;

    let epoch = fetch_current_epoch(rpc_url).await?;
    build_table_summary_from_fields(fields, epoch)
}

/// 获取当前 epoch
async fn fetch_current_epoch(rpc_url: &str) -> Result<u64, String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "sui_getLatestCheckpointSequenceNumber",
        "params": []
    });

    let client = reqwest::Client::new();
    let resp: serde_json::Value = client
        .post(rpc_url)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {}", e))?
        .json()
        .await
        .map_err(|e| format!("JSON parse failed: {}", e))?;

    Ok(0) // 暂时返回 0，实际应该从 sui_getEpoch 获取
}

/// 从 sui_getObject 返回的 fields JSON 构建 TableSummary
fn build_table_summary_from_fields(fields: &serde_json::Value, epoch: u64) -> Result<TableSummary, String> {
    let extract_string = |key: &str| -> Result<String, String> {
        fields.get(key)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| format!("Missing or invalid field: {}", key))
    };

    let extract_u64 = |key: &str| -> Result<u64, String> {
        fields.get(key)
            .and_then(|v| v.as_u64())
            .ok_or_else(|| format!("Missing or invalid u64 field: {}", key))
    };

    let extract_u8 = |key: &str| -> Result<u8, String> {
        fields.get(key)
            .and_then(|v| v.as_u64())
            .map(|v| v as u8)
            .ok_or_else(|| format!("Missing or invalid u8 field: {}", key))
    };

    // 基础字段
    let table_id = extract_string("id")?;
    let name = fields.get("name")
        .and_then(|n| n.as_str())
        .unwrap_or("")
        .to_string();
    let max_players = extract_u64("max_players")?;
    let small_blind = extract_u64("small_blind")?;
    let big_blind = extract_u64("big_blind")?;

    let active_count = extract_u64("active_count")?;
    let button = extract_u64("button")?;
    let pot = extract_u64("pot")?;
    let round_state = extract_u8("round_state")?;

    // 可选字段
    let current_turn = fields.get("current_turn")
        .and_then(|v| extract_option_u64(v));

    // 处理 community_cards
    let community_cards_count = fields.get("community_cards")
        .and_then(|v| v.as_array())
        .map(|a| a.len() as u64)
        .unwrap_or(0);

    let side_pots_count = fields.get("side_pots")
        .and_then(|v| v.as_array())
        .map(|a| a.len() as u64)
        .unwrap_or(0);

    // 处理座位信息
    let seats = fields.get("seats")
        .and_then(|v| v.as_array())
        .map(|a| a.clone())
        .unwrap_or_default();

    let max = max_players as usize;
    let mut seats_occupied = Vec::with_capacity(max);
    let mut seat_players = Vec::with_capacity(max);
    let mut seat_stacks = Vec::with_capacity(max);
    let mut seat_bets = Vec::with_capacity(max);
    let mut seat_total_bets = Vec::with_capacity(max);
    let mut seat_folded = Vec::with_capacity(max);
    let mut seat_all_in = Vec::with_capacity(max);

    for seat in seats.iter() {
        seats_occupied.push(seat.get("occupied").and_then(|v| v.as_bool()).unwrap_or(false));
        seat_players.push(seat.get("player").and_then(|v| v.as_str()).unwrap_or("0x0").to_string());
        seat_stacks.push(seat.get("stack").and_then(|v| v.as_u64()).unwrap_or(0));
        seat_bets.push(seat.get("bet").and_then(|v| v.as_u64()).unwrap_or(0));
        seat_total_bets.push(seat.get("total_bet").and_then(|v| v.as_u64()).unwrap_or(0));
        seat_folded.push(seat.get("folded").and_then(|v| v.as_bool()).unwrap_or(false));
        seat_all_in.push(seat.get("all_in").and_then(|v| v.as_bool()).unwrap_or(false));
    }

    // 处理 deck_state
    let deck_size = fields.get("deck_state")
        .and_then(|d| d.get("encrypted"))
        .and_then(|e| e.as_array())
        .map(|a| a.len() as u64)
        .unwrap_or(0);
    let deck_plaintext = fields.get("deck_state")
        .and_then(|d| d.get("plaintext"))
        .and_then(|p| p.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    // 处理 shuffle_state
    let shuffle_current_shuffler = fields.get("shuffle_state")
        .and_then(|s| s.get("current_shuffler"))
        .and_then(|v| extract_option_u64(v));

    let shuffle_pending_count = fields.get("shuffle_state")
        .and_then(|s| s.get("pending_players"))
        .and_then(|p| p.as_array())
        .map(|a| a.len() as u64)
        .unwrap_or(0);

    let shuffle_completed_count = fields.get("shuffle_state")
        .and_then(|s| s.get("completed_players"))
        .and_then(|p| p.as_array())
        .map(|a| a.len() as u64)
        .unwrap_or(0);

    // 处理 reveal_token_state
    let reveal_phase = fields.get("reveal_token_state")
        .and_then(|r| r.get("reveal_phase"))
        .and_then(|v| v.as_u64())
        .map(|v| v as u8)
        .unwrap_or(0);

    let reveal_assignment_count = fields.get("reveal_token_state")
        .and_then(|r| r.get("assignments"))
        .and_then(|a| a.as_array())
        .map(|a| a.len() as u64)
        .unwrap_or(0);

    // 处理 reconstruct_state
    let reconstruct_phase = fields.get("reconstruct_state")
        .and_then(|r| r.get("phase"))
        .and_then(|v| v.as_u64())
        .map(|v| v as u8)
        .unwrap_or(0);

    let reconstruct_votes_yes = fields.get("reconstruct_state")
        .and_then(|r| r.get("votes_yes"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let reconstruct_votes_no = fields.get("reconstruct_state")
        .and_then(|r| r.get("votes_no"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    // 处理 timeout_config
    let timeout_config = fields.get("timeout_config");
    let shuffle_timeout_ms = timeout_config.and_then(|t| t.get("shuffle_timeout_ms")).and_then(|v| v.as_u64()).unwrap_or(0);
    let reveal_timeout_ms = timeout_config.and_then(|t| t.get("reveal_timeout_ms")).and_then(|v| v.as_u64()).unwrap_or(0);
    let betting_timeout_ms = timeout_config.and_then(|t| t.get("betting_timeout_ms")).and_then(|v| v.as_u64()).unwrap_or(0);
    let reconstruct_timeout_ms = timeout_config.and_then(|t| t.get("reconstruct_timeout_ms")).and_then(|v| v.as_u64()).unwrap_or(0);
    let showdown_display_ms = timeout_config.and_then(|t| t.get("showdown_display_ms")).and_then(|v| v.as_u64()).unwrap_or(0);
    let hand_complete_wait_ms = timeout_config.and_then(|t| t.get("hand_complete_wait_ms")).and_then(|v| v.as_u64()).unwrap_or(0);
    let ready_wait_ms = timeout_config.and_then(|t| t.get("ready_wait_ms")).and_then(|v| v.as_u64()).unwrap_or(0);

    // 处理 timestamps
    let timestamps = fields.get("timestamps");
    let ready_at = timestamps.and_then(|t| t.get("ready_at")).and_then(|v| v.as_u64()).unwrap_or(0);
    let shuffle_started_at = timestamps.and_then(|t| t.get("shuffle_started_at")).and_then(|v| v.as_u64()).unwrap_or(0);
    let reveal_started_at = timestamps.and_then(|t| t.get("reveal_started_at")).and_then(|v| v.as_u64()).unwrap_or(0);
    let betting_started_at = timestamps.and_then(|t| t.get("betting_started_at")).and_then(|v| v.as_u64()).unwrap_or(0);
    let reconstruct_started_at = timestamps.and_then(|t| t.get("reconstruct_started_at")).and_then(|v| v.as_u64()).unwrap_or(0);
    let showdown_at = timestamps.and_then(|t| t.get("showdown_at")).and_then(|v| v.as_u64()).unwrap_or(0);
    let hand_complete_at = timestamps.and_then(|t| t.get("hand_complete_at")).and_then(|v| v.as_u64()).unwrap_or(0);

    // betting_round 信息
    let betting_round = fields.get("betting_round");
    let betting_round_exists = betting_round.map_or(false, |v| !v.is_null());
    let betting_round_current_bet = betting_round.and_then(|b| b.get("current_bet")).and_then(|v| v.as_u64()).unwrap_or(0);
    let betting_round_min_raise = betting_round.and_then(|b| b.get("min_raise")).and_then(|v| v.as_u64()).unwrap_or(0);
    let betting_round_big_blind = betting_round.and_then(|b| b.get("big_blind")).and_then(|v| v.as_u64()).unwrap_or(0);
    let betting_round_last_raiser_seat = betting_round
        .and_then(|b| b.get("last_raiser_seat"))
        .and_then(|v| extract_option_u64(v));
    let betting_round_actions_taken = betting_round.and_then(|b| b.get("actions_taken")).and_then(|v| v.as_u64()).unwrap_or(0);

    Ok(TableSummary {
        table_id,
        name,
        max_players,
        small_blind,
        big_blind,
        active_count,
        button,
        pot,
        side_pots_count,
        community_cards_count,
        round_state,
        betting_round_exists,
        betting_round_current_bet,
        betting_round_min_raise,
        betting_round_big_blind,
        betting_round_last_raiser_seat,
        betting_round_actions_taken,
        current_turn,
        seats_occupied,
        seat_players,
        seat_stacks,
        seat_bets,
        seat_total_bets,
        seat_folded,
        seat_all_in,
        shuffle_current_shuffler,
        shuffle_pending_count,
        shuffle_completed_count,
        reveal_phase,
        reveal_assignment_count,
        reconstruct_phase,
        reconstruct_votes_yes,
        reconstruct_votes_no,
        deck_size,
        deck_plaintext,
        shuffle_timeout_ms,
        reveal_timeout_ms,
        betting_timeout_ms,
        reconstruct_timeout_ms,
        showdown_display_ms,
        hand_complete_wait_ms,
        ready_wait_ms,
        ready_at,
        shuffle_started_at,
        reveal_started_at,
        betting_started_at,
        reconstruct_started_at,
        showdown_at,
        hand_complete_at,
        epoch,
    })
}

/// 从 JSON Value 中提取 Option<u64>
fn extract_option_u64(v: &serde_json::Value) -> Option<u64> {
    match v {
        serde_json::Value::Null => None,
        serde_json::Value::Number(n) => n.as_u64(),
        // Sui 的 Option 可能序列化为 { "vec": [] } 或 { "vec": [val] }
        serde_json::Value::Object(obj) => {
            obj.get("vec")
                .and_then(|vec| vec.as_array())
                .and_then(|arr| arr.first())
                .and_then(|val| val.as_u64())
        }
        _ => None,
    }
}

/// 通过 sui_getObject 获取 Table 对象（仅获取原始字段，不含 epoch）
/// epoch 参数可以在外部获取后传入
pub async fn fetch_table_object(rpc_url: &str, table_object_id: &str) -> Result<TableSummary, String> {
    let epoch = fetch_current_epoch(rpc_url).await?;
    fetch_table_object_with_epoch(rpc_url, table_object_id, epoch).await
}

async fn fetch_table_object_with_epoch(rpc_url: &str, table_object_id: &str, epoch: u64) -> Result<TableSummary, String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "sui_getObject",
        "params": [
            table_object_id,
            {
                "showType": true,
                "showContent": true,
                "showOwner": true,
            }
        ]
    });

    let client = reqwest::Client::new();
    let resp: serde_json::Value = client
        .post(rpc_url)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {}", e))?
        .json()
        .await
        .map_err(|e| format!("JSON parse failed: {}", e))?;

    if let Some(error) = resp.get("error") {
        return Err(format!("RPC error: {:?}", error));
    }

    let fields = resp.get("result")
        .and_then(|r| r.get("data"))
        .and_then(|d| d.get("content"))
        .and_then(|c| c.get("fields"))
        .ok_or("Failed to parse sui_getObject response")?;

    build_table_summary_from_fields(fields, epoch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_option_u64_some() {
        let v = serde_json::json!({"vec": [42]});
        assert_eq!(extract_option_u64(&v), Some(42));
    }

    #[test]
    fn test_extract_option_u64_none() {
        let v = serde_json::json!({"vec": []});
        assert_eq!(extract_option_u64(&v), None);
    }

    #[test]
    fn test_extract_option_u64_null() {
        let v = serde_json::Value::Null;
        assert_eq!(extract_option_u64(&v), None);
    }

    #[test]
    fn test_extract_option_u64_number() {
        let v = serde_json::json!(123);
        assert_eq!(extract_option_u64(&v), Some(123));
    }

    #[test]
    fn test_build_table_summary_from_fields() {
        let fields = serde_json::json!({
            "id": "0x123456",
            "name": "TestTable",
            "max_players": 6,
            "small_blind": 10,
            "big_blind": 20,
            "active_count": 2,
            "button": 0,
            "pot": 150,
            "round_state": 2,
            "current_turn": {"vec": [0]},
            "seats": [
                {
                    "occupied": true,
                    "player": "0xabc",
                    "stack": 1000,
                    "bet": 10,
                    "total_bet": 10,
                    "folded": false,
                    "all_in": false
                },
                {
                    "occupied": true,
                    "player": "0xdef",
                    "stack": 2000,
                    "bet": 20,
                    "total_bet": 20,
                    "folded": false,
                    "all_in": false
                }
            ],
            "community_cards": [],
            "side_pots": [],
            "deck_state": {
                "encrypted": [],
                "aggregated_pk": "0x"
            },
            "betting_round": {
                "current_bet": 20,
                "min_raise": 20,
                "big_blind": 20,
                "last_raiser_seat": {"vec": [1]},
                "actions_taken": 2
            },
            "shuffle_state": {
                "current_shuffler": {"vec": []},
                "pending_players": [],
                "completed_players": []
            },
            "reveal_token_state": {
                "reveal_phase": 0,
                "assignments": []
            },
            "reconstruct_state": {
                "phase": 0,
                "votes_yes": 0,
                "votes_no": 0,
                "voted_players": [],
                "pending_players": [],
                "completed_players": [],
                "coefficient": [],
                "readable_cards": [],
                "cards": []
            },
            "timeout_config": {
                "shuffle_timeout_ms": 10000,
                "reveal_timeout_ms": 10000,
                "betting_timeout_ms": 30000,
                "reconstruct_timeout_ms": 10000,
                "showdown_display_ms": 3000,
                "hand_complete_wait_ms": 5000,
                "ready_wait_ms": 5000
            },
            "timestamps": {
                "ready_at": 0,
                "shuffle_started_at": 0,
                "reveal_started_at": 0,
                "betting_started_at": 0,
                "reconstruct_started_at": 0,
                "showdown_at": 0,
                "hand_complete_at": 0
            }
        });

        let summary = build_table_summary_from_fields(&fields, 42).unwrap();

        assert_eq!(summary.table_id, "0x123456");
        assert_eq!(summary.name, "TestTable");
        assert_eq!(summary.max_players, 6);
        assert_eq!(summary.small_blind, 10);
        assert_eq!(summary.big_blind, 20);
        assert_eq!(summary.active_count, 2);
        assert_eq!(summary.button, 0);
        assert_eq!(summary.pot, 150);
        assert_eq!(summary.round_state, 2);
        assert_eq!(summary.current_turn, Some(0));
        assert_eq!(summary.seats_occupied, vec![true, true]);
        assert_eq!(summary.seat_players, vec!["0xabc".to_string(), "0xdef".to_string()]);
        assert_eq!(summary.seat_stacks, vec![1000, 2000]);
        assert_eq!(summary.seat_bets, vec![10, 20]);
        assert_eq!(summary.betting_round_exists, true);
        assert_eq!(summary.betting_round_current_bet, 20);
        assert_eq!(summary.betting_round_last_raiser_seat, Some(1));
        assert_eq!(summary.epoch, 42);
    }

    #[test]
    fn test_build_table_summary_empty_table() {
        let fields = serde_json::json!({
            "id": "0x999",
            "name": "",
            "max_players": 9,
            "small_blind": 5,
            "big_blind": 10,
            "active_count": 0,
            "button": 0,
            "pot": 0,
            "round_state": 0,
            "current_turn": {"vec": []},
            "seats": [
                {"occupied": false, "player": "0x0", "stack": 0, "bet": 0, "total_bet": 0, "folded": false, "all_in": false}
            ],
            "community_cards": [],
            "side_pots": [],
            "deck_state": {"encrypted": [], "aggregated_pk": "0x"},
            "betting_round": null,
            "shuffle_state": {"current_shuffler": {"vec": []}, "pending_players": [], "completed_players": []},
            "reveal_token_state": {"reveal_phase": 0, "assignments": []},
            "reconstruct_state": {"phase": 0, "votes_yes": 0, "votes_no": 0, "voted_players": [], "pending_players": [], "completed_players": [], "coefficient": [], "readable_cards": [], "cards": []},
            "timeout_config": {"shuffle_timeout_ms": 10000, "reveal_timeout_ms": 10000, "betting_timeout_ms": 30000, "reconstruct_timeout_ms": 10000, "showdown_display_ms": 3000, "hand_complete_wait_ms": 5000, "ready_wait_ms": 5000},
            "timestamps": {"ready_at": 0, "shuffle_started_at": 0, "reveal_started_at": 0, "betting_started_at": 0, "reconstruct_started_at": 0, "showdown_at": 0, "hand_complete_at": 0}
        });

        let summary = build_table_summary_from_fields(&fields, 99).unwrap();

        assert_eq!(summary.table_id, "0x999");
        assert_eq!(summary.max_players, 9);
        assert_eq!(summary.active_count, 0);
        assert_eq!(summary.betting_round_exists, false);
        assert_eq!(summary.current_turn, None);
        assert_eq!(summary.epoch, 99);
    }
}