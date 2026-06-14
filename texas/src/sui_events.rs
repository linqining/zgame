use serde::{Deserialize, Serialize};

/// 链上 Table 的快照，对应合约中 get_table_summary 的返回值
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TableSummary {
    // 元数据
    pub table_id: String,
    pub name: String,
    pub max_players: u64,
    pub small_blind: u64,
    pub big_blind: u64,
    // 活跃座位信息
    pub active_count: u64,
    pub button: u64,
    // 底池
    pub pot: u64,
    pub side_pots_count: u64,
    pub community_cards_count: u64,
    // 阶段
    pub round_state: u8,
    // 下注轮信息
    pub betting_round_exists: bool,
    pub betting_round_current_bet: u64,
    pub betting_round_min_raise: u64,
    pub betting_round_big_blind: u64,
    pub betting_round_last_raiser_seat: Option<u64>,
    pub betting_round_actions_taken: u64,
    // 当前行动玩家
    pub current_turn: Option<u64>,
    // 座位快照
    pub seats_occupied: Vec<bool>,
    pub seat_players: Vec<String>,
    pub seat_stacks: Vec<u64>,
    pub seat_bets: Vec<u64>,
    pub seat_total_bets: Vec<u64>,
    pub seat_folded: Vec<bool>,
    pub seat_all_in: Vec<bool>,
    // 洗牌状态
    pub shuffle_current_shuffler: Option<u64>,
    pub shuffle_pending_count: u64,
    pub shuffle_completed_count: u64,
    // Reveal 阶段
    pub reveal_phase: u8,
    pub reveal_assignment_count: u64,
    // Reconstruct 阶段
    pub reconstruct_phase: u8,
    pub reconstruct_votes_yes: u64,
    pub reconstruct_votes_no: u64,
    // 牌组大小
    pub deck_size: u64,
    // 明文牌组（52 张 G1 compressed bytes hex strings）
    pub deck_plaintext: Vec<String>,
    // 超时配置
    pub shuffle_timeout_ms: u64,
    pub reveal_timeout_ms: u64,
    pub betting_timeout_ms: u64,
    pub reconstruct_timeout_ms: u64,
    pub showdown_display_ms: u64,
    pub hand_complete_wait_ms: u64,
    pub ready_wait_ms: u64,
    // 时间戳
    pub ready_at: u64,
    pub shuffle_started_at: u64,
    pub reveal_started_at: u64,
    pub betting_started_at: u64,
    pub reconstruct_started_at: u64,
    pub showdown_at: u64,
    pub hand_complete_at: u64,
    // 一致性保证
    pub epoch: u64,
}

/// Sui 链上事件类型，对应 texas_poker_move 合约中定义的 26 种事件
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum SuiChainEvent {
    TableCreated { table_id: String, name: String },
    PlayerJoined { table_id: String, seat_index: u64, player: String, buy_in: u64 },
    PlayerLeft { table_id: String, seat_index: u64, player: String },
    HandStarted { table_id: String, button: u64 },
    ShuffleVerified { table_id: String, seat_index: u64, player: String },
    ShuffleComplete { table_id: String },
    ShuffleTurn { table_id: String, seat_index: u64, pending_count: u64, completed_count: u64 },
    RevealTokenSubmitted { table_id: String, seat_index: u64, card_index: u64, phase: u8 },
    RevealPhaseComplete { table_id: String, phase: u8 },
    PlayerFolded { table_id: String, seat_index: u64 },
    PlayerChecked { table_id: String, seat_index: u64 },
    PlayerCalled { table_id: String, seat_index: u64, amount: u64 },
    PlayerRaised { table_id: String, seat_index: u64, total_bet: u64 },
    HandSettled { table_id: String, pot: u64 },
    ReconstructInitiated { table_id: String },
    ReconstructVote { table_id: String, seat_index: u64, vote: bool },
    ReconstructDeckSubmitted { table_id: String, seat_index: u64 },
    ReconstructComplete { table_id: String },
    RedealRequested { table_id: String, seat_index: u64, card_indices: Vec<u64> },
    PlayerKicked { table_id: String, seat_index: u64 },
    AutoFolded { table_id: String, seat_index: u64 },
    ForceFolded { table_id: String, seat_index: u64 },
    ShuffleTimeout { table_id: String, seat_index: u64 },
    RevealTimeout { table_id: String, phase: u8 },
    HandReset { table_id: String },
    ReadyToStart { table_id: String, ready_at: u64 },
    HandCleanedUp { table_id: String },
}

/// Inodra Webhook 推送的事件载荷
#[derive(Debug, Clone, Deserialize)]
pub struct InodraWebhookPayload {
    pub id: String,
    pub event_type: String,
    pub package_id: String,
    pub transaction_digest: String,
    pub timestamp: u64,
    pub checkpoint_seq: u64,
    pub data: serde_json::Value,
}

/// 从 Inodra 事件类型字符串解析出 SuiChainEvent
/// 事件类型格式: PACKAGE_ID::table::EventName
pub fn parse_chain_event(event_type: &str, data: &serde_json::Value) -> Option<SuiChainEvent> {
    // 提取事件名称（最后一个 :: 后面的部分）
    let event_name = event_type.rsplit("::").next()?;

    match event_name {
        "TableCreated" => Some(SuiChainEvent::TableCreated {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            name: data.get("name")?.as_str()?.to_string(),
        }),
        "PlayerJoined" => Some(SuiChainEvent::PlayerJoined {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: data.get("seat_index")?.as_u64()?,
            player: data.get("player")?.as_str()?.to_string(),
            buy_in: data.get("buy_in")?.as_u64()?,
        }),
        "PlayerLeft" => Some(SuiChainEvent::PlayerLeft {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: data.get("seat_index")?.as_u64()?,
            player: data.get("player")?.as_str()?.to_string(),
        }),
        "HandStarted" => Some(SuiChainEvent::HandStarted {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            button: data.get("button")?.as_u64()?,
        }),
        "ShuffleVerified" => Some(SuiChainEvent::ShuffleVerified {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: data.get("seat_index")?.as_u64()?,
            player: data.get("player")?.as_str()?.to_string(),
        }),
        "ShuffleCompleteEvt" => Some(SuiChainEvent::ShuffleComplete {
            table_id: data.get("table_id")?.as_str()?.to_string(),
        }),
        "ShuffleTurnEvt" => Some(SuiChainEvent::ShuffleTurn {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: data.get("seat_index")?.as_u64()?,
            pending_count: data.get("pending_count")?.as_u64()?,
            completed_count: data.get("completed_count")?.as_u64()?,
        }),
        "RevealTokenSubmitted" => Some(SuiChainEvent::RevealTokenSubmitted {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: data.get("seat_index")?.as_u64()?,
            card_index: data.get("card_index")?.as_u64()?,
            phase: data.get("phase")?.as_u64()? as u8,
        }),
        "RevealPhaseComplete" => Some(SuiChainEvent::RevealPhaseComplete {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            phase: data.get("phase")?.as_u64()? as u8,
        }),
        "PlayerFolded" => Some(SuiChainEvent::PlayerFolded {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: data.get("seat_index")?.as_u64()?,
        }),
        "PlayerChecked" => Some(SuiChainEvent::PlayerChecked {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: data.get("seat_index")?.as_u64()?,
        }),
        "PlayerCalled" => Some(SuiChainEvent::PlayerCalled {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: data.get("seat_index")?.as_u64()?,
            amount: data.get("amount")?.as_u64()?,
        }),
        "PlayerRaised" => Some(SuiChainEvent::PlayerRaised {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: data.get("seat_index")?.as_u64()?,
            total_bet: data.get("total_bet")?.as_u64()?,
        }),
        "HandSettled" => Some(SuiChainEvent::HandSettled {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            pot: data.get("pot")?.as_u64()?,
        }),
        "ReconstructInitiated" => Some(SuiChainEvent::ReconstructInitiated {
            table_id: data.get("table_id")?.as_str()?.to_string(),
        }),
        "ReconstructVote" => Some(SuiChainEvent::ReconstructVote {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: data.get("seat_index")?.as_u64()?,
            vote: data.get("vote")?.as_bool()?,
        }),
        "ReconstructDeckSubmitted" => Some(SuiChainEvent::ReconstructDeckSubmitted {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: data.get("seat_index")?.as_u64()?,
        }),
        "ReconstructCompleteEvt" => Some(SuiChainEvent::ReconstructComplete {
            table_id: data.get("table_id")?.as_str()?.to_string(),
        }),
        "RedealRequested" => Some(SuiChainEvent::RedealRequested {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: data.get("seat_index")?.as_u64()?,
            card_indices: data.get("card_indices")?
                .as_array()?
                .iter()
                .filter_map(|v| v.as_u64())
                .collect(),
        }),
        "PlayerKicked" => Some(SuiChainEvent::PlayerKicked {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: data.get("seat_index")?.as_u64()?,
        }),
        "AutoFolded" => Some(SuiChainEvent::AutoFolded {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: data.get("seat_index")?.as_u64()?,
        }),
        "ForceFolded" => Some(SuiChainEvent::ForceFolded {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: data.get("seat_index")?.as_u64()?,
        }),
        "ShuffleTimeout" => Some(SuiChainEvent::ShuffleTimeout {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: data.get("seat_index")?.as_u64()?,
        }),
        "RevealTimeout" => Some(SuiChainEvent::RevealTimeout {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            phase: data.get("phase")?.as_u64()? as u8,
        }),
        "HandReset" => Some(SuiChainEvent::HandReset {
            table_id: data.get("table_id")?.as_str()?.to_string(),
        }),
        "ReadyToStart" => Some(SuiChainEvent::ReadyToStart {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            ready_at: data.get("ready_at")?.as_u64()?,
        }),
        "HandCleanedUp" => Some(SuiChainEvent::HandCleanedUp {
            table_id: data.get("table_id")?.as_str()?.to_string(),
        }),
        _ => {
            tracing::warn!("[sui_events] unknown event type: {}", event_name);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 辅助函数：构造一个模拟的链上事件 JSON 并调用 parse_chain_event
    fn parse_event(event_name: &str, data: serde_json::Value) -> Option<SuiChainEvent> {
        // 模拟完整的 event_type: PACKAGE_ID::table::EventName
        let event_type = format!("0xfa::table::{}", event_name);
        parse_chain_event(&event_type, &data)
    }

    // ========== 基础事件 ==========

    #[test]
    fn test_table_created() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "name": "TestTable"
        });
        let event = parse_event("TableCreated", data).unwrap();
        assert_eq!(event, SuiChainEvent::TableCreated {
            table_id: "0x123".to_string(),
            name: "TestTable".to_string(),
        });
    }

    #[test]
    fn test_player_joined() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "seat_index": 0,
            "player": "0xabc",
            "buy_in": 1000
        });
        let event = parse_event("PlayerJoined", data).unwrap();
        assert_eq!(event, SuiChainEvent::PlayerJoined {
            table_id: "0x123".to_string(),
            seat_index: 0,
            player: "0xabc".to_string(),
            buy_in: 1000,
        });
    }

    #[test]
    fn test_player_left() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "seat_index": 1,
            "player": "0xabc"
        });
        let event = parse_event("PlayerLeft", data).unwrap();
        assert_eq!(event, SuiChainEvent::PlayerLeft {
            table_id: "0x123".to_string(),
            seat_index: 1,
            player: "0xabc".to_string(),
        });
    }

    #[test]
    fn test_hand_started() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "button": 2
        });
        let event = parse_event("HandStarted", data).unwrap();
        assert_eq!(event, SuiChainEvent::HandStarted {
            table_id: "0x123".to_string(),
            button: 2,
        });
    }

    // ========== 洗牌相关事件 ==========

    #[test]
    fn test_shuffle_verified() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "seat_index": 0,
            "player": "0xabc"
        });
        let event = parse_event("ShuffleVerified", data).unwrap();
        assert_eq!(event, SuiChainEvent::ShuffleVerified {
            table_id: "0x123".to_string(),
            seat_index: 0,
            player: "0xabc".to_string(),
        });
    }

    #[test]
    fn test_shuffle_complete() {
        let data = serde_json::json!({
            "table_id": "0x123"
        });
        let event = parse_event("ShuffleCompleteEvt", data).unwrap();
        assert_eq!(event, SuiChainEvent::ShuffleComplete {
            table_id: "0x123".to_string(),
        });
    }

    #[test]
    fn test_shuffle_turn() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "seat_index": 2,
            "pending_count": 3,
            "completed_count": 1
        });
        let event = parse_event("ShuffleTurnEvt", data).unwrap();
        assert_eq!(event, SuiChainEvent::ShuffleTurn {
            table_id: "0x123".to_string(),
            seat_index: 2,
            pending_count: 3,
            completed_count: 1,
        });
    }

    #[test]
    fn test_reveal_token_submitted() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "seat_index": 2,
            "card_index": 5,
            "phase": 1
        });
        let event = parse_event("RevealTokenSubmitted", data).unwrap();
        assert_eq!(event, SuiChainEvent::RevealTokenSubmitted {
            table_id: "0x123".to_string(),
            seat_index: 2,
            card_index: 5,
            phase: 1,
        });
    }

    #[test]
    fn test_reveal_phase_complete() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "phase": 2
        });
        let event = parse_event("RevealPhaseComplete", data).unwrap();
        assert_eq!(event, SuiChainEvent::RevealPhaseComplete {
            table_id: "0x123".to_string(),
            phase: 2,
        });
    }

    // ========== 动作事件 ==========

    #[test]
    fn test_player_folded() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "seat_index": 3
        });
        let event = parse_event("PlayerFolded", data).unwrap();
        assert_eq!(event, SuiChainEvent::PlayerFolded {
            table_id: "0x123".to_string(),
            seat_index: 3,
        });
    }

    #[test]
    fn test_player_checked() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "seat_index": 1
        });
        let event = parse_event("PlayerChecked", data).unwrap();
        assert_eq!(event, SuiChainEvent::PlayerChecked {
            table_id: "0x123".to_string(),
            seat_index: 1,
        });
    }

    #[test]
    fn test_player_called() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "seat_index": 0,
            "amount": 100
        });
        let event = parse_event("PlayerCalled", data).unwrap();
        assert_eq!(event, SuiChainEvent::PlayerCalled {
            table_id: "0x123".to_string(),
            seat_index: 0,
            amount: 100,
        });
    }

    #[test]
    fn test_player_raised() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "seat_index": 2,
            "total_bet": 500
        });
        let event = parse_event("PlayerRaised", data).unwrap();
        assert_eq!(event, SuiChainEvent::PlayerRaised {
            table_id: "0x123".to_string(),
            seat_index: 2,
            total_bet: 500,
        });
    }

    #[test]
    fn test_hand_settled() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "pot": 1500
        });
        let event = parse_event("HandSettled", data).unwrap();
        assert_eq!(event, SuiChainEvent::HandSettled {
            table_id: "0x123".to_string(),
            pot: 1500,
        });
    }

    // ========== 重建相关事件 ==========

    #[test]
    fn test_reconstruct_initiated() {
        let data = serde_json::json!({
            "table_id": "0x123"
        });
        let event = parse_event("ReconstructInitiated", data).unwrap();
        assert_eq!(event, SuiChainEvent::ReconstructInitiated {
            table_id: "0x123".to_string(),
        });
    }

    #[test]
    fn test_reconstruct_vote() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "seat_index": 1,
            "vote": true
        });
        let event = parse_event("ReconstructVote", data).unwrap();
        assert_eq!(event, SuiChainEvent::ReconstructVote {
            table_id: "0x123".to_string(),
            seat_index: 1,
            vote: true,
        });
    }

    #[test]
    fn test_reconstruct_deck_submitted() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "seat_index": 0
        });
        let event = parse_event("ReconstructDeckSubmitted", data).unwrap();
        assert_eq!(event, SuiChainEvent::ReconstructDeckSubmitted {
            table_id: "0x123".to_string(),
            seat_index: 0,
        });
    }

    #[test]
    fn test_reconstruct_complete() {
        let data = serde_json::json!({
            "table_id": "0x123"
        });
        let event = parse_event("ReconstructCompleteEvt", data).unwrap();
        assert_eq!(event, SuiChainEvent::ReconstructComplete {
            table_id: "0x123".to_string(),
        });
    }

    // ========== 管理事件 ==========

    #[test]
    fn test_redeal_requested() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "seat_index": 0,
            "card_indices": [1, 3, 5]
        });
        let event = parse_event("RedealRequested", data).unwrap();
        assert_eq!(event, SuiChainEvent::RedealRequested {
            table_id: "0x123".to_string(),
            seat_index: 0,
            card_indices: vec![1, 3, 5],
        });
    }

    #[test]
    fn test_player_kicked() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "seat_index": 4
        });
        let event = parse_event("PlayerKicked", data).unwrap();
        assert_eq!(event, SuiChainEvent::PlayerKicked {
            table_id: "0x123".to_string(),
            seat_index: 4,
        });
    }

    #[test]
    fn test_auto_folded() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "seat_index": 2
        });
        let event = parse_event("AutoFolded", data).unwrap();
        assert_eq!(event, SuiChainEvent::AutoFolded {
            table_id: "0x123".to_string(),
            seat_index: 2,
        });
    }

    #[test]
    fn test_force_folded() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "seat_index": 1
        });
        let event = parse_event("ForceFolded", data).unwrap();
        assert_eq!(event, SuiChainEvent::ForceFolded {
            table_id: "0x123".to_string(),
            seat_index: 1,
        });
    }

    // ========== 超时 & 生命周期 ==========

    #[test]
    fn test_shuffle_timeout() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "seat_index": 3
        });
        let event = parse_event("ShuffleTimeout", data).unwrap();
        assert_eq!(event, SuiChainEvent::ShuffleTimeout {
            table_id: "0x123".to_string(),
            seat_index: 3,
        });
    }

    #[test]
    fn test_reveal_timeout() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "phase": 1
        });
        let event = parse_event("RevealTimeout", data).unwrap();
        assert_eq!(event, SuiChainEvent::RevealTimeout {
            table_id: "0x123".to_string(),
            phase: 1,
        });
    }

    #[test]
    fn test_hand_reset() {
        let data = serde_json::json!({
            "table_id": "0x123"
        });
        let event = parse_event("HandReset", data).unwrap();
        assert_eq!(event, SuiChainEvent::HandReset {
            table_id: "0x123".to_string(),
        });
    }

    #[test]
    fn test_ready_to_start() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "ready_at": 1000000
        });
        let event = parse_event("ReadyToStart", data).unwrap();
        assert_eq!(event, SuiChainEvent::ReadyToStart {
            table_id: "0x123".to_string(),
            ready_at: 1000000,
        });
    }

    #[test]
    fn test_hand_cleaned_up() {
        let data = serde_json::json!({
            "table_id": "0x123"
        });
        let event = parse_event("HandCleanedUp", data).unwrap();
        assert_eq!(event, SuiChainEvent::HandCleanedUp {
            table_id: "0x123".to_string(),
        });
    }

    // ========== 边界/错误情况 ==========

    #[test]
    fn test_unknown_event_type() {
        let data = serde_json::json!({
            "table_id": "0x123"
        });
        let result = parse_event("NonExistentEvent", data);
        assert!(result.is_none());
    }

    #[test]
    fn test_missing_required_field() {
        // PlayerJoined 缺少必填字段 buy_in
        let data = serde_json::json!({
            "table_id": "0x123",
            "seat_index": 0,
            "player": "0xabc"
            // 缺少 buy_in
        });
        let result = parse_event("PlayerJoined", data);
        assert!(result.is_none());
    }

    #[test]
    fn test_wrong_field_type() {
        // seat_index 应该是数字，但给了字符串
        let data = serde_json::json!({
            "table_id": "0x123",
            "seat_index": "not_a_number",
            "player": "0xabc",
            "buy_in": 1000
        });
        let result = parse_event("PlayerJoined", data);
        assert!(result.is_none());
    }

    #[test]
    fn test_empty_event_type() {
        let data = serde_json::json!({"table_id": "0x123"});
        let result = parse_chain_event("", &data);
        assert!(result.is_none());
    }

    #[test]
    fn test_event_type_without_module() {
        // event_type 格式为 PACKAGE::module::EventName，没有 module 的情况
        let data = serde_json::json!({"table_id": "0x123"});
        let result = parse_chain_event("JustEventName", &data);
        assert!(result.is_none());
    }
}
