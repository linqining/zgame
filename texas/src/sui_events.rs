use serde::{Deserialize, Serialize};

/// G16 修复：安全地将 u64 转换为 u8，超出范围时返回 None，
/// 避免 `as u8` 静默截断导致数据错误。
fn u64_to_u8(v: u64) -> Option<u8> {
    if v > 255 {
        tracing::warn!("[sui_events] u64 value {} exceeds u8 range, truncation avoided", v);
        return None;
    }
    Some(v as u8)
}

/// 链上 Table 的元数据快照，对应 Move 合约的 TableSummaryMeta
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TableSummaryMeta {
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
    pub seat_is_waiting: Vec<bool>,
}

/// 链上 Table 的状态快照，对应 Move 合约的 TableSummaryState
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TableSummaryState {
    // 洗牌状态
    pub shuffle_current_shuffler: Option<u64>,
    pub shuffle_pending_count: u64,
    pub shuffle_completed_count: u64,
    // Reveal 阶段
    pub reveal_phase: u8,
    pub reveal_assignment_count: u64,
    // Reconstruct 阶段
    pub reconstruct_phase: u8,
    // 牌组大小
    pub deck_size: u64,
    // 已发牌数量
    pub cards_dealt: u64,
    // 明文牌组（52 张 G1 compressed bytes）
    pub deck_plaintext: Vec<Vec<u8>>,
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

/// 链上 Table 的完整快照，对应合约中 get_table_summary 的返回值
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TableSummary {
    pub meta: TableSummaryMeta,
    pub state: TableSummaryState,
}

/// Sui 链上事件类型，对应 texas_poker_move 合约中定义的事件
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum SuiChainEvent {
    // ===== 基础事件 =====
    TableCreated { table_id: String, name: String },
    PlayerJoined {
        table_id: String,
        seat_index: u64,
        player: String,
        buy_in: u64,
        is_waiting: bool,
        active_count_after: u64,
    },
    PlayerLeft { table_id: String, seat_index: u64, player: String },
    HandStarted {
        table_id: String,
        button: u64,
        small_blind: u64,
        big_blind: u64,
        participants: Vec<u64>,
    },
    // ===== 洗牌相关事件 =====
    ShuffleVerified { table_id: String, seat_index: u64, player: String },
    ShuffleComplete {
        table_id: String,
        phase: u8,
        participant_count: u64,
        deck_size: u64,
    },
    ShuffleTurn { table_id: String, seat_index: u64, pending_count: u64, completed_count: u64 },
    ShuffleTimeout {
        table_id: String,
        seat_index: u64,
        phase: u8,
        started_at: u64,
        timeout_ms: u64,
    },
    // ===== Reveal 相关事件 =====
    RevealTokenSubmitted { table_id: String, seat_index: u64, card_index: u64, phase: u8 },
    RevealPhaseComplete { table_id: String, phase: u8 },
    RevealPhaseEvt { table_id: String, phase: u8 },
    CardIsIdentity {
        table_id: String,
        card_index: u64,
        assignment_index: u64,
        phase: u8,
    },
    IdentityRedeal {
        table_id: String,
        identity_card_indices: Vec<u64>,
        redeal_count: u64,
        phase: u8,
    },
    CommunityCardRevealed {
        table_id: String,
        phase: u8,
        card_indices: Vec<u64>,
        card_ranks: Vec<u8>,
        card_suits: Vec<u8>,
    },
    RevealTimeout {
        table_id: String,
        phase: u8,
        pending_players: Vec<u64>,
    },
    // ===== 下注动作事件 =====
    BettingRoundStarted {
        table_id: String,
        round_state: u8,
        current_bet: u64,
        min_raise: u64,
        first_to_act: u64,
        pot_before: u64,
    },
    PlayerFolded {
        table_id: String,
        seat_index: u64,
        reason: u8,
        round_state: u8,
    },
    PlayerChecked { table_id: String, seat_index: u64, round_state: u8 },
    PlayerCalled {
        table_id: String,
        seat_index: u64,
        call_delta: u64,
        round_state: u8,
    },
    PlayerRaised {
        table_id: String,
        seat_index: u64,
        raise_delta: u64,
        total_bet: u64,
        round_state: u8,
    },
    PlayerAllIn {
        table_id: String,
        seat_index: u64,
        trigger_action: u8,
        amount: u64,
        round_state: u8,
    },
    PotCollected {
        table_id: String,
        round_state: u8,
        pot_after: u64,
        collected_from_seats: Vec<u64>,
    },
    RoundAdvanced {
        table_id: String,
        from_round: u8,
        to_round: u8,
        pot: u64,
        community_cards_count: u64,
    },
    // ===== 摊牌 & 结算事件 =====
    WinnerAwarded {
        table_id: String,
        seat_index: u64,
        player: String,
        amount: u64,
        pot_type: u8,
        hand_rank: Option<u64>,
    },
    HandEndedWithoutShowdown {
        table_id: String,
        winner_seat: u64,
        winner_player: String,
        pot: u64,
    },
    HandSettled { table_id: String, pot: u64, winners: Vec<u64> },
    // ===== 重建相关事件 =====
    ReconstructInitiated {
        table_id: String,
        expected_players: Vec<u64>,
        round_state: u8,
    },
    ReconstructDeckSubmitted { table_id: String, seat_index: u64 },
    ReconstructComplete { table_id: String },
    ReconstructTimeout {
        table_id: String,
        pending_players: Vec<u64>,
    },
    RedealRequested { table_id: String, seat_index: u64, card_indices: Vec<u64> },
    // ===== 管理 & 生命周期事件 =====
    PlayerKicked {
        table_id: String,
        seat_index: u64,
        player: String,
        reason: u8,
    },
    PlayerRefund {
        table_id: String,
        seat_index: u64,
        player: String,
        amount: u64,
        refund_type: u8,
    },
    HandReset {
        table_id: String,
        reason: u8,
        round_state: u8,
    },
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
        // ===== 基础事件 =====
        "TableCreated" => Some(SuiChainEvent::TableCreated {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            name: data.get("name")?.as_str()?.to_string(),
        }),
        "PlayerJoined" => Some(SuiChainEvent::PlayerJoined {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: data.get("seat_index")?.as_u64()?,
            player: data.get("player")?.as_str()?.to_string(),
            buy_in: data.get("buy_in")?.as_u64()?,
            is_waiting: data.get("is_waiting")?.as_bool()?,
            active_count_after: data.get("active_count_after")?.as_u64()?,
        }),
        "PlayerLeft" => Some(SuiChainEvent::PlayerLeft {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: data.get("seat_index")?.as_u64()?,
            player: data.get("player")?.as_str()?.to_string(),
        }),
        "HandStarted" => Some(SuiChainEvent::HandStarted {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            button: data.get("button")?.as_u64()?,
            small_blind: data.get("small_blind")?.as_u64()?,
            big_blind: data.get("big_blind")?.as_u64()?,
            participants: data.get("participants")?
                .as_array()?
                .iter()
                .filter_map(|v| v.as_u64())
                .collect(),
        }),
        // ===== 洗牌相关事件 =====
        "ShuffleVerified" => Some(SuiChainEvent::ShuffleVerified {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: data.get("seat_index")?.as_u64()?,
            player: data.get("player")?.as_str()?.to_string(),
        }),
        "ShuffleCompleteEvt" => Some(SuiChainEvent::ShuffleComplete {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            phase: u64_to_u8(data.get("phase")?.as_u64()?)?,
            participant_count: data.get("participant_count")?.as_u64()?,
            deck_size: data.get("deck_size")?.as_u64()?,
        }),
        "ShuffleTurnEvt" => Some(SuiChainEvent::ShuffleTurn {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: data.get("seat_index")?.as_u64()?,
            pending_count: data.get("pending_count")?.as_u64()?,
            completed_count: data.get("completed_count")?.as_u64()?,
        }),
        "ShuffleTimeout" => Some(SuiChainEvent::ShuffleTimeout {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: data.get("seat_index")?.as_u64()?,
            phase: u64_to_u8(data.get("phase")?.as_u64()?)?,
            started_at: data.get("started_at")?.as_u64()?,
            timeout_ms: data.get("timeout_ms")?.as_u64()?,
        }),
        // ===== Reveal 相关事件 =====
        "RevealTokenSubmitted" => Some(SuiChainEvent::RevealTokenSubmitted {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: data.get("seat_index")?.as_u64()?,
            card_index: data.get("card_index")?.as_u64()?,
            phase: u64_to_u8(data.get("phase")?.as_u64()?)?,
        }),
        "RevealPhaseComplete" => Some(SuiChainEvent::RevealPhaseComplete {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            phase: u64_to_u8(data.get("phase")?.as_u64()?)?,
        }),
        "RevealPhaseEvt" => Some(SuiChainEvent::RevealPhaseEvt {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            phase: u64_to_u8(data.get("phase")?.as_u64()?)?,
        }),
        "CardIsIdentity" => Some(SuiChainEvent::CardIsIdentity {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            card_index: data.get("card_index")?.as_u64()?,
            assignment_index: data.get("assignment_index")?.as_u64()?,
            phase: u64_to_u8(data.get("phase")?.as_u64()?)?,
        }),
        "IdentityRedeal" => Some(SuiChainEvent::IdentityRedeal {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            identity_card_indices: data.get("identity_card_indices")?
                .as_array()?
                .iter()
                .filter_map(|v| v.as_u64())
                .collect(),
            redeal_count: data.get("redeal_count")?.as_u64()?,
            phase: u64_to_u8(data.get("phase")?.as_u64()?)?,
        }),
        "CommunityCardRevealed" => Some(SuiChainEvent::CommunityCardRevealed {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            phase: u64_to_u8(data.get("phase")?.as_u64()?)?,
            card_indices: data.get("card_indices")?
                .as_array()?
                .iter()
                .filter_map(|v| v.as_u64())
                .collect(),
            // G16 修复：card_ranks / card_suits 使用 filter_map + u64_to_u8 安全转换
            card_ranks: data.get("card_ranks")?
                .as_array()?
                .iter()
                .filter_map(|v| v.as_u64())
                .filter_map(u64_to_u8)
                .collect(),
            card_suits: data.get("card_suits")?
                .as_array()?
                .iter()
                .filter_map(|v| v.as_u64())
                .filter_map(u64_to_u8)
                .collect(),
        }),
        "RevealTimeout" => Some(SuiChainEvent::RevealTimeout {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            phase: u64_to_u8(data.get("phase")?.as_u64()?)?,
            pending_players: data.get("pending_players")?
                .as_array()?
                .iter()
                .filter_map(|v| v.as_u64())
                .collect(),
        }),
        // ===== 下注动作事件 =====
        "BettingRoundStarted" => Some(SuiChainEvent::BettingRoundStarted {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            round_state: u64_to_u8(data.get("round_state")?.as_u64()?)?,
            current_bet: data.get("current_bet")?.as_u64()?,
            min_raise: data.get("min_raise")?.as_u64()?,
            first_to_act: data.get("first_to_act")?.as_u64()?,
            pot_before: data.get("pot_before")?.as_u64()?,
        }),
        "PlayerFolded" => Some(SuiChainEvent::PlayerFolded {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: data.get("seat_index")?.as_u64()?,
            reason: u64_to_u8(data.get("reason")?.as_u64()?)?,
            round_state: u64_to_u8(data.get("round_state")?.as_u64()?)?,
        }),
        "PlayerChecked" => Some(SuiChainEvent::PlayerChecked {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: data.get("seat_index")?.as_u64()?,
            round_state: u64_to_u8(data.get("round_state")?.as_u64()?)?,
        }),
        "PlayerCalled" => Some(SuiChainEvent::PlayerCalled {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: data.get("seat_index")?.as_u64()?,
            call_delta: data.get("call_delta")?.as_u64()?,
            round_state: u64_to_u8(data.get("round_state")?.as_u64()?)?,
        }),
        "PlayerRaised" => Some(SuiChainEvent::PlayerRaised {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: data.get("seat_index")?.as_u64()?,
            raise_delta: data.get("raise_delta")?.as_u64()?,
            total_bet: data.get("total_bet")?.as_u64()?,
            round_state: u64_to_u8(data.get("round_state")?.as_u64()?)?,
        }),
        "PlayerAllIn" => Some(SuiChainEvent::PlayerAllIn {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: data.get("seat_index")?.as_u64()?,
            trigger_action: u64_to_u8(data.get("trigger_action")?.as_u64()?)?,
            amount: data.get("amount")?.as_u64()?,
            round_state: u64_to_u8(data.get("round_state")?.as_u64()?)?,
        }),
        "PotCollected" => Some(SuiChainEvent::PotCollected {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            round_state: u64_to_u8(data.get("round_state")?.as_u64()?)?,
            pot_after: data.get("pot_after")?.as_u64()?,
            collected_from_seats: data.get("collected_from_seats")?
                .as_array()?
                .iter()
                .filter_map(|v| v.as_u64())
                .collect(),
        }),
        "RoundAdvanced" => Some(SuiChainEvent::RoundAdvanced {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            from_round: u64_to_u8(data.get("from_round")?.as_u64()?)?,
            to_round: u64_to_u8(data.get("to_round")?.as_u64()?)?,
            pot: data.get("pot")?.as_u64()?,
            community_cards_count: data.get("community_cards_count")?.as_u64()?,
        }),
        // ===== 摊牌 & 结算事件 =====
        "WinnerAwarded" => Some(SuiChainEvent::WinnerAwarded {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: data.get("seat_index")?.as_u64()?,
            player: data.get("player")?.as_str()?.to_string(),
            amount: data.get("amount")?.as_u64()?,
            pot_type: u64_to_u8(data.get("pot_type")?.as_u64()?)?,
            hand_rank: data.get("hand_rank").and_then(|v| v.as_u64()),
        }),
        "HandEndedWithoutShowdown" => Some(SuiChainEvent::HandEndedWithoutShowdown {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            winner_seat: data.get("winner_seat")?.as_u64()?,
            winner_player: data.get("winner_player")?.as_str()?.to_string(),
            pot: data.get("pot")?.as_u64()?,
        }),
        "HandSettled" => Some(SuiChainEvent::HandSettled {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            pot: data.get("pot")?.as_u64()?,
            winners: data.get("winners")?
                .as_array()?
                .iter()
                .filter_map(|v| v.as_u64())
                .collect(),
        }),
        // ===== 重建相关事件 =====
        "ReconstructInitiated" => Some(SuiChainEvent::ReconstructInitiated {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            expected_players: data.get("expected_players")?
                .as_array()?
                .iter()
                .filter_map(|v| v.as_u64())
                .collect(),
            round_state: u64_to_u8(data.get("round_state")?.as_u64()?)?,
        }),
        "ReconstructDeckSubmitted" => Some(SuiChainEvent::ReconstructDeckSubmitted {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: data.get("seat_index")?.as_u64()?,
        }),
        "ReconstructCompleteEvt" => Some(SuiChainEvent::ReconstructComplete {
            table_id: data.get("table_id")?.as_str()?.to_string(),
        }),
        "ReconstructTimeout" => Some(SuiChainEvent::ReconstructTimeout {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            pending_players: data.get("pending_players")?
                .as_array()?
                .iter()
                .filter_map(|v| v.as_u64())
                .collect(),
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
        // ===== 管理 & 生命周期事件 =====
        "PlayerKicked" => Some(SuiChainEvent::PlayerKicked {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: data.get("seat_index")?.as_u64()?,
            player: data.get("player")?.as_str()?.to_string(),
            reason: u64_to_u8(data.get("reason")?.as_u64()?)?,
        }),
        "PlayerRefund" => Some(SuiChainEvent::PlayerRefund {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: data.get("seat_index")?.as_u64()?,
            player: data.get("player")?.as_str()?.to_string(),
            amount: data.get("amount")?.as_u64()?,
            refund_type: u64_to_u8(data.get("refund_type")?.as_u64()?)?,
        }),
        "HandReset" => Some(SuiChainEvent::HandReset {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            reason: u64_to_u8(data.get("reason")?.as_u64()?)?,
            round_state: u64_to_u8(data.get("round_state")?.as_u64()?)?,
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
            "buy_in": 1000,
            "is_waiting": false,
            "active_count_after": 3
        });
        let event = parse_event("PlayerJoined", data).unwrap();
        assert_eq!(event, SuiChainEvent::PlayerJoined {
            table_id: "0x123".to_string(),
            seat_index: 0,
            player: "0xabc".to_string(),
            buy_in: 1000,
            is_waiting: false,
            active_count_after: 3,
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
            "button": 2,
            "small_blind": 10,
            "big_blind": 20,
            "participants": [0, 1, 2, 3]
        });
        let event = parse_event("HandStarted", data).unwrap();
        assert_eq!(event, SuiChainEvent::HandStarted {
            table_id: "0x123".to_string(),
            button: 2,
            small_blind: 10,
            big_blind: 20,
            participants: vec![0, 1, 2, 3],
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
            "table_id": "0x123",
            "phase": 1,
            "participant_count": 4,
            "deck_size": 52
        });
        let event = parse_event("ShuffleCompleteEvt", data).unwrap();
        assert_eq!(event, SuiChainEvent::ShuffleComplete {
            table_id: "0x123".to_string(),
            phase: 1,
            participant_count: 4,
            deck_size: 52,
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
    fn test_shuffle_timeout() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "seat_index": 3,
            "phase": 0,
            "started_at": 1000000,
            "timeout_ms": 30000
        });
        let event = parse_event("ShuffleTimeout", data).unwrap();
        assert_eq!(event, SuiChainEvent::ShuffleTimeout {
            table_id: "0x123".to_string(),
            seat_index: 3,
            phase: 0,
            started_at: 1000000,
            timeout_ms: 30000,
        });
    }

    // ========== Reveal 相关事件 ==========

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

    #[test]
    fn test_reveal_phase_evt() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "phase": 1
        });
        let event = parse_event("RevealPhaseEvt", data).unwrap();
        assert_eq!(event, SuiChainEvent::RevealPhaseEvt {
            table_id: "0x123".to_string(),
            phase: 1,
        });
    }

    #[test]
    fn test_card_is_identity() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "card_index": 7,
            "assignment_index": 3,
            "phase": 1
        });
        let event = parse_event("CardIsIdentity", data).unwrap();
        assert_eq!(event, SuiChainEvent::CardIsIdentity {
            table_id: "0x123".to_string(),
            card_index: 7,
            assignment_index: 3,
            phase: 1,
        });
    }

    #[test]
    fn test_identity_redeal() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "identity_card_indices": [1, 3, 5],
            "redeal_count": 2,
            "phase": 1
        });
        let event = parse_event("IdentityRedeal", data).unwrap();
        assert_eq!(event, SuiChainEvent::IdentityRedeal {
            table_id: "0x123".to_string(),
            identity_card_indices: vec![1, 3, 5],
            redeal_count: 2,
            phase: 1,
        });
    }

    #[test]
    fn test_community_card_revealed() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "phase": 2,
            "card_indices": [0, 1, 2],
            "card_ranks": [12, 5, 9],
            "card_suits": [0, 1, 2]
        });
        let event = parse_event("CommunityCardRevealed", data).unwrap();
        assert_eq!(event, SuiChainEvent::CommunityCardRevealed {
            table_id: "0x123".to_string(),
            phase: 2,
            card_indices: vec![0, 1, 2],
            card_ranks: vec![12, 5, 9],
            card_suits: vec![0, 1, 2],
        });
    }

    #[test]
    fn test_reveal_timeout() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "phase": 1,
            "pending_players": [0, 2]
        });
        let event = parse_event("RevealTimeout", data).unwrap();
        assert_eq!(event, SuiChainEvent::RevealTimeout {
            table_id: "0x123".to_string(),
            phase: 1,
            pending_players: vec![0, 2],
        });
    }

    // ========== 下注动作事件 ==========

    #[test]
    fn test_betting_round_started() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "round_state": 0,
            "current_bet": 20,
            "min_raise": 20,
            "first_to_act": 1,
            "pot_before": 30
        });
        let event = parse_event("BettingRoundStarted", data).unwrap();
        assert_eq!(event, SuiChainEvent::BettingRoundStarted {
            table_id: "0x123".to_string(),
            round_state: 0,
            current_bet: 20,
            min_raise: 20,
            first_to_act: 1,
            pot_before: 30,
        });
    }

    #[test]
    fn test_player_folded() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "seat_index": 3,
            "reason": 0,
            "round_state": 1
        });
        let event = parse_event("PlayerFolded", data).unwrap();
        assert_eq!(event, SuiChainEvent::PlayerFolded {
            table_id: "0x123".to_string(),
            seat_index: 3,
            reason: 0,
            round_state: 1,
        });
    }

    #[test]
    fn test_player_folded_auto_timeout() {
        // reason=1 表示 auto_timeout（原 AutoFolded 已合并）
        let data = serde_json::json!({
            "table_id": "0x123",
            "seat_index": 2,
            "reason": 1,
            "round_state": 1
        });
        let event = parse_event("PlayerFolded", data).unwrap();
        assert_eq!(event, SuiChainEvent::PlayerFolded {
            table_id: "0x123".to_string(),
            seat_index: 2,
            reason: 1,
            round_state: 1,
        });
    }

    #[test]
    fn test_player_folded_force_admin() {
        // reason=2 表示 force_admin（原 ForceFolded 已合并）
        let data = serde_json::json!({
            "table_id": "0x123",
            "seat_index": 1,
            "reason": 2,
            "round_state": 1
        });
        let event = parse_event("PlayerFolded", data).unwrap();
        assert_eq!(event, SuiChainEvent::PlayerFolded {
            table_id: "0x123".to_string(),
            seat_index: 1,
            reason: 2,
            round_state: 1,
        });
    }

    #[test]
    fn test_player_checked() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "seat_index": 1,
            "round_state": 1
        });
        let event = parse_event("PlayerChecked", data).unwrap();
        assert_eq!(event, SuiChainEvent::PlayerChecked {
            table_id: "0x123".to_string(),
            seat_index: 1,
            round_state: 1,
        });
    }

    #[test]
    fn test_player_called() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "seat_index": 0,
            "call_delta": 100,
            "round_state": 1
        });
        let event = parse_event("PlayerCalled", data).unwrap();
        assert_eq!(event, SuiChainEvent::PlayerCalled {
            table_id: "0x123".to_string(),
            seat_index: 0,
            call_delta: 100,
            round_state: 1,
        });
    }

    #[test]
    fn test_player_raised() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "seat_index": 2,
            "raise_delta": 80,
            "total_bet": 500,
            "round_state": 1
        });
        let event = parse_event("PlayerRaised", data).unwrap();
        assert_eq!(event, SuiChainEvent::PlayerRaised {
            table_id: "0x123".to_string(),
            seat_index: 2,
            raise_delta: 80,
            total_bet: 500,
            round_state: 1,
        });
    }

    #[test]
    fn test_player_all_in() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "seat_index": 1,
            "trigger_action": 1,
            "amount": 1000,
            "round_state": 1
        });
        let event = parse_event("PlayerAllIn", data).unwrap();
        assert_eq!(event, SuiChainEvent::PlayerAllIn {
            table_id: "0x123".to_string(),
            seat_index: 1,
            trigger_action: 1,
            amount: 1000,
            round_state: 1,
        });
    }

    #[test]
    fn test_pot_collected() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "round_state": 1,
            "pot_after": 0,
            "collected_from_seats": [0, 1, 2]
        });
        let event = parse_event("PotCollected", data).unwrap();
        assert_eq!(event, SuiChainEvent::PotCollected {
            table_id: "0x123".to_string(),
            round_state: 1,
            pot_after: 0,
            collected_from_seats: vec![0, 1, 2],
        });
    }

    #[test]
    fn test_round_advanced() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "from_round": 0,
            "to_round": 1,
            "pot": 200,
            "community_cards_count": 3
        });
        let event = parse_event("RoundAdvanced", data).unwrap();
        assert_eq!(event, SuiChainEvent::RoundAdvanced {
            table_id: "0x123".to_string(),
            from_round: 0,
            to_round: 1,
            pot: 200,
            community_cards_count: 3,
        });
    }

    // ========== 摊牌 & 结算事件 ==========

    #[test]
    fn test_winner_awarded() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "seat_index": 1,
            "player": "0xabc",
            "amount": 1500,
            "pot_type": 0,
            "hand_rank": 7
        });
        let event = parse_event("WinnerAwarded", data).unwrap();
        assert_eq!(event, SuiChainEvent::WinnerAwarded {
            table_id: "0x123".to_string(),
            seat_index: 1,
            player: "0xabc".to_string(),
            amount: 1500,
            pot_type: 0,
            hand_rank: Some(7),
        });
    }

    #[test]
    fn test_winner_awarded_no_hand_rank() {
        // hand_rank 为 null 的情况（无摊牌）
        let data = serde_json::json!({
            "table_id": "0x123",
            "seat_index": 1,
            "player": "0xabc",
            "amount": 1500,
            "pot_type": 0,
            "hand_rank": null
        });
        let event = parse_event("WinnerAwarded", data).unwrap();
        assert_eq!(event, SuiChainEvent::WinnerAwarded {
            table_id: "0x123".to_string(),
            seat_index: 1,
            player: "0xabc".to_string(),
            amount: 1500,
            pot_type: 0,
            hand_rank: None,
        });
    }

    #[test]
    fn test_hand_ended_without_showdown() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "winner_seat": 2,
            "winner_player": "0xabc",
            "pot": 500
        });
        let event = parse_event("HandEndedWithoutShowdown", data).unwrap();
        assert_eq!(event, SuiChainEvent::HandEndedWithoutShowdown {
            table_id: "0x123".to_string(),
            winner_seat: 2,
            winner_player: "0xabc".to_string(),
            pot: 500,
        });
    }

    #[test]
    fn test_hand_settled() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "pot": 1500,
            "winners": [1, 3]
        });
        let event = parse_event("HandSettled", data).unwrap();
        assert_eq!(event, SuiChainEvent::HandSettled {
            table_id: "0x123".to_string(),
            pot: 1500,
            winners: vec![1, 3],
        });
    }

    // ========== 重建相关事件 ==========

    #[test]
    fn test_reconstruct_initiated() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "expected_players": [0, 1, 2],
            "round_state": 3
        });
        let event = parse_event("ReconstructInitiated", data).unwrap();
        assert_eq!(event, SuiChainEvent::ReconstructInitiated {
            table_id: "0x123".to_string(),
            expected_players: vec![0, 1, 2],
            round_state: 3,
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

    #[test]
    fn test_reconstruct_timeout() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "pending_players": [1, 2]
        });
        let event = parse_event("ReconstructTimeout", data).unwrap();
        assert_eq!(event, SuiChainEvent::ReconstructTimeout {
            table_id: "0x123".to_string(),
            pending_players: vec![1, 2],
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
            "seat_index": 4,
            "player": "0xabc",
            "reason": 1
        });
        let event = parse_event("PlayerKicked", data).unwrap();
        assert_eq!(event, SuiChainEvent::PlayerKicked {
            table_id: "0x123".to_string(),
            seat_index: 4,
            player: "0xabc".to_string(),
            reason: 1,
        });
    }

    #[test]
    fn test_player_refund() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "seat_index": 2,
            "player": "0xabc",
            "amount": 500,
            "refund_type": 0
        });
        let event = parse_event("PlayerRefund", data).unwrap();
        assert_eq!(event, SuiChainEvent::PlayerRefund {
            table_id: "0x123".to_string(),
            seat_index: 2,
            player: "0xabc".to_string(),
            amount: 500,
            refund_type: 0,
        });
    }

    // ========== 超时 & 生命周期 ==========

    #[test]
    fn test_hand_reset() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "reason": 0,
            "round_state": 2
        });
        let event = parse_event("HandReset", data).unwrap();
        assert_eq!(event, SuiChainEvent::HandReset {
            table_id: "0x123".to_string(),
            reason: 0,
            round_state: 2,
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
            "player": "0xabc",
            "is_waiting": false,
            "active_count_after": 1
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
            "buy_in": 1000,
            "is_waiting": false,
            "active_count_after": 1
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
