use serde::{Deserialize, Serialize};

use crate::pokergame::side_pot::SidePot;

/// G16 修复：安全地将 u64 转换为 u8，超出范围时返回 None，
/// 避免 `as u8` 静默截断导致数据错误。
fn u64_to_u8(v: u64) -> Option<u8> {
    if v > 255 {
        tracing::warn!("[sui_events] u64 value {} exceeds u8 range, truncation avoided", v);
        return None;
    }
    Some(v as u8)
}

/// 从 JSON Value 提取 u64，兼容数字和字符串两种表示。
///
/// gRPC BCS 解码返回数字，GraphQL MoveValue.json 将 u64/u128/u256 表示为字符串。
fn json_as_u64(v: &serde_json::Value) -> Option<u64> {
    v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))
}

/// 从 JSON Value 提取 bool，兼容数字和字符串两种表示。
fn json_as_bool(v: &serde_json::Value) -> Option<bool> {
    v.as_bool().or_else(|| {
        v.as_str().and_then(|s| match s {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        })
    })
}

/// 链上 Table 的元数据快照，对应 Move 合约的 TableSummaryMeta
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct TableSummaryMeta {
    // 元数据
    // Move 类型为 ID，BCS 序列化为 32 字节原始 address（无长度前缀）
    pub table_id: [u8; 32],
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
    // Move 类型为 vector<address>，BCS 序列化为 Vec<[u8; 32]>
    pub seat_players: Vec<[u8; 32]>,
    pub seat_stacks: Vec<u64>,
    pub seat_bets: Vec<u64>,
    pub seat_total_bets: Vec<u64>,
    pub seat_folded: Vec<bool>,
    pub seat_all_in: Vec<bool>,
    pub seat_is_waiting: Vec<bool>,
}

/// 链上 Table 的加密状态快照，对应 Move 合约的 TableSummaryCryptoState
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct TableSummaryCryptoState {
    /// 加密牌组（每个元素为 96 bytes: c1 || c2）
    pub deck_encrypted: Vec<Vec<u8>>,
    /// 聚合公钥 (G1 compressed bytes, 48 bytes)
    pub aggregated_pk: Vec<u8>,
    /// 每个座位的玩家公钥（空座位为空 vector）
    pub seat_pks: Vec<Vec<u8>>,
    /// 待洗牌玩家 seat_index 列表
    pub shuffle_pending_players: Vec<u64>,
    /// 已完成洗牌玩家 seat_index 列表
    pub shuffle_completed_players: Vec<u64>,
    /// reconstruct 随机系数 (scalar bytes, 32 bytes)
    pub reconstruct_coefficient: Vec<u8>,
    /// 待提交 reconstruct deck 的玩家 seat_index 列表
    pub reconstruct_pending_players: Vec<u64>,
    /// 已提交 reconstruct deck 的玩家 seat_index 列表
    pub reconstruct_completed_players: Vec<u64>,
}

/// 链上 Table 的状态快照，对应 Move 合约的 TableSummaryState
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
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

/// 链上 Table 的完整快照（V1），对应合约中 get_table_summary 的返回值
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct TableSummary {
    pub meta: TableSummaryMeta,
    pub state: TableSummaryState,
}

/// 链上 Table 的扩展快照（V2），对应合约中 get_table_summary_v2 的返回值。
/// 由于合约部署原因，crypto 字段移至独立的 V2 结构体（与 Move TableSummaryV2 对齐）。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct TableSummaryV2 {
    pub meta: TableSummaryMeta,
    pub state: TableSummaryState,
    pub crypto: TableSummaryCryptoState,
    /// 本地 socket table ID（区别于 meta.table_id 链上地址 [u8;32]）
    pub id: u32,
    /// 桌面限额
    pub limit: u64,
    /// 当前跟注金额
    pub call_amount: Option<u64>,
    /// 最小下注额
    pub min_bet: u64,
    /// 当前手牌是否结束
    pub hand_over: bool,
    /// 胜利消息列表
    pub win_messages: Vec<String>,
    /// 是否进入摊牌
    pub went_to_showdown: bool,
    /// 边池列表（meta.side_pots_count 仅存数量，此处存完整结构）
    pub side_pots: Vec<SidePot>,
    /// 历史操作记录
    pub history: Vec<serde_json::Value>,
}

/// 链上 BCS 反序列化专用结构体，仅包含 Move 合约 `get_table_summary_v2` 返回的字段。
/// `TableSummaryV2` 中的 `id`/`limit`/`call_amount` 等字段是本地运行时状态，
/// 不在链上 struct 中，直接用 `TableSummaryV2` 做 BCS 反序列化会失败。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TableSummaryV2Chain {
    pub meta: TableSummaryMeta,
    pub state: TableSummaryState,
    pub crypto: TableSummaryCryptoState,
}

impl From<TableSummaryV2Chain> for TableSummaryV2 {
    fn from(chain: TableSummaryV2Chain) -> Self {
        TableSummaryV2 {
            meta: chain.meta,
            state: chain.state,
            crypto: chain.crypto,
            ..Default::default()
        }
    }
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
    BlindsPosted {
        table_id: String,
        sb_seat: u64,
        bb_seat: u64,
        sb_amount: u64,
        bb_amount: u64,
        first_to_act: u64,
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
    ShowdownHoleCardsRevealed {
        table_id: String,
        seat_index: u64,
        player: String,
        card_indices: Vec<u64>,
        card_ranks: Vec<u8>,
        card_suits: Vec<u8>,
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
    DeckRebuilt {
        table_id: String,
        reason: u8,
        deck_size: u64,
    },
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
    TimeoutConfigUpdated {
        table_id: String,
        betting_timeout_ms: u64,
        shuffle_timeout_ms: u64,
        reveal_timeout_ms: u64,
        reconstruct_timeout_ms: u64,
        showdown_display_ms: u64,
    },
    CurrentTurnChanged {
        table_id: String,
        old_turn: Option<u64>,
        new_turn: Option<u64>,
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

    let result = parse_chain_event_inner(event_name, data);
    if result.is_none() {
        tracing::warn!(
            "[parse_chain_event] FAILED to parse event '{}', fields: {}",
            event_name,
            serde_json::to_string(data).unwrap_or_default()
        );
    }
    tracing::info!("[parse_chain_event] {}: {:?}", event_name, serde_json::to_string(data).unwrap_or_default());
    result
}

fn parse_chain_event_inner(event_name: &str, data: &serde_json::Value) -> Option<SuiChainEvent> {
    match event_name {
        // ===== 基础事件 =====
        "TableCreated" => Some(SuiChainEvent::TableCreated {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            name: data.get("name")?.as_str()?.to_string(),
        }),
        "PlayerJoined" => Some(SuiChainEvent::PlayerJoined {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: json_as_u64(data.get("seat_index")?)?,
            player: data.get("player")?.as_str()?.to_string(),
            buy_in: data.get("buy_in").and_then(json_as_u64).unwrap_or(0),
            is_waiting: data.get("is_waiting").and_then(json_as_bool).unwrap_or(false),
            active_count_after: data.get("active_count_after").and_then(json_as_u64).unwrap_or(0),
        }),
        "PlayerLeft" => Some(SuiChainEvent::PlayerLeft {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: json_as_u64(data.get("seat_index")?)?,
            player: data.get("player")?.as_str()?.to_string(),
        }),
        "HandStarted" => Some(SuiChainEvent::HandStarted {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            button: json_as_u64(data.get("button")?)?,
            small_blind: json_as_u64(data.get("small_blind")?)?,
            big_blind: json_as_u64(data.get("big_blind")?)?,
            participants: data.get("participants")?
                .as_array()?
                .iter()
                .filter_map(|v| v.as_u64())
                .collect(),
        }),
        "BlindsPosted" => Some(SuiChainEvent::BlindsPosted {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            sb_seat: json_as_u64(data.get("sb_seat")?)?,
            bb_seat: json_as_u64(data.get("bb_seat")?)?,
            sb_amount: json_as_u64(data.get("sb_amount")?)?,
            bb_amount: json_as_u64(data.get("bb_amount")?)?,
            first_to_act: json_as_u64(data.get("first_to_act")?)?,
        }),
        // ===== 洗牌相关事件 =====
        "ShuffleVerified" => Some(SuiChainEvent::ShuffleVerified {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: json_as_u64(data.get("seat_index")?)?,
            player: data.get("player")?.as_str()?.to_string(),
        }),
        "ShuffleCompleteEvt" => Some(SuiChainEvent::ShuffleComplete {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            phase: u64_to_u8(json_as_u64(data.get("phase")?)?)?,
            participant_count: json_as_u64(data.get("participant_count")?)?,
            deck_size: json_as_u64(data.get("deck_size")?)?,
        }),
        "ShuffleTurnEvt" => Some(SuiChainEvent::ShuffleTurn {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: json_as_u64(data.get("seat_index")?)?,
            pending_count: json_as_u64(data.get("pending_count")?)?,
            completed_count: json_as_u64(data.get("completed_count")?)?,
        }),
        "ShuffleTimeout" => Some(SuiChainEvent::ShuffleTimeout {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: json_as_u64(data.get("seat_index")?)?,
            phase: u64_to_u8(json_as_u64(data.get("phase")?)?)?,
            started_at: json_as_u64(data.get("started_at")?)?,
            timeout_ms: json_as_u64(data.get("timeout_ms")?)?,
        }),
        // ===== Reveal 相关事件 =====
        "RevealTokenSubmitted" => Some(SuiChainEvent::RevealTokenSubmitted {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: json_as_u64(data.get("seat_index")?)?,
            card_index: json_as_u64(data.get("card_index")?)?,
            phase: u64_to_u8(json_as_u64(data.get("phase")?)?)?,
        }),
        "RevealPhaseComplete" => Some(SuiChainEvent::RevealPhaseComplete {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            phase: u64_to_u8(json_as_u64(data.get("phase")?)?)?,
        }),
        "RevealPhaseEvt" => Some(SuiChainEvent::RevealPhaseEvt {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            phase: u64_to_u8(json_as_u64(data.get("phase")?)?)?,
        }),
        "CardIsIdentity" => Some(SuiChainEvent::CardIsIdentity {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            card_index: json_as_u64(data.get("card_index")?)?,
            assignment_index: json_as_u64(data.get("assignment_index")?)?,
            phase: u64_to_u8(json_as_u64(data.get("phase")?)?)?,
        }),
        "IdentityRedeal" => Some(SuiChainEvent::IdentityRedeal {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            identity_card_indices: data.get("identity_card_indices")?
                .as_array()?
                .iter()
                .filter_map(|v| v.as_u64())
                .collect(),
            redeal_count: json_as_u64(data.get("redeal_count")?)?,
            phase: u64_to_u8(json_as_u64(data.get("phase")?)?)?,
        }),
        "CommunityCardRevealed" => Some(SuiChainEvent::CommunityCardRevealed {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            phase: u64_to_u8(json_as_u64(data.get("phase")?)?)?,
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
            phase: u64_to_u8(json_as_u64(data.get("phase")?)?)?,
            pending_players: data.get("pending_players")?
                .as_array()?
                .iter()
                .filter_map(|v| v.as_u64())
                .collect(),
        }),
        // ===== 下注动作事件 =====
        "BettingRoundStarted" => Some(SuiChainEvent::BettingRoundStarted {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            round_state: u64_to_u8(json_as_u64(data.get("round_state")?)?)?,
            current_bet: json_as_u64(data.get("current_bet")?)?,
            min_raise: json_as_u64(data.get("min_raise")?)?,
            first_to_act: json_as_u64(data.get("first_to_act")?)?,
            pot_before: json_as_u64(data.get("pot_before")?)?,
        }),
        "PlayerFolded" => Some(SuiChainEvent::PlayerFolded {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: json_as_u64(data.get("seat_index")?)?,
            reason: u64_to_u8(json_as_u64(data.get("reason")?)?)?,
            round_state: u64_to_u8(json_as_u64(data.get("round_state")?)?)?,
        }),
        "PlayerChecked" => Some(SuiChainEvent::PlayerChecked {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: json_as_u64(data.get("seat_index")?)?,
            round_state: u64_to_u8(json_as_u64(data.get("round_state")?)?)?,
        }),
        "PlayerCalled" => Some(SuiChainEvent::PlayerCalled {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: json_as_u64(data.get("seat_index")?)?,
            call_delta: json_as_u64(data.get("call_delta")?)?,
            round_state: u64_to_u8(json_as_u64(data.get("round_state")?)?)?,
        }),
        "PlayerRaised" => Some(SuiChainEvent::PlayerRaised {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: json_as_u64(data.get("seat_index")?)?,
            raise_delta: json_as_u64(data.get("raise_delta")?)?,
            total_bet: json_as_u64(data.get("total_bet")?)?,
            round_state: u64_to_u8(json_as_u64(data.get("round_state")?)?)?,
        }),
        "PlayerAllIn" => Some(SuiChainEvent::PlayerAllIn {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: json_as_u64(data.get("seat_index")?)?,
            trigger_action: u64_to_u8(json_as_u64(data.get("trigger_action")?)?)?,
            amount: json_as_u64(data.get("amount")?)?,
            round_state: u64_to_u8(json_as_u64(data.get("round_state")?)?)?,
        }),
        "PotCollected" => Some(SuiChainEvent::PotCollected {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            round_state: u64_to_u8(json_as_u64(data.get("round_state")?)?)?,
            pot_after: json_as_u64(data.get("pot_after")?)?,
            collected_from_seats: data.get("collected_from_seats")?
                .as_array()?
                .iter()
                .filter_map(|v| v.as_u64())
                .collect(),
        }),
        "RoundAdvanced" => Some(SuiChainEvent::RoundAdvanced {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            from_round: u64_to_u8(json_as_u64(data.get("from_round")?)?)?,
            to_round: u64_to_u8(json_as_u64(data.get("to_round")?)?)?,
            pot: json_as_u64(data.get("pot")?)?,
            community_cards_count: json_as_u64(data.get("community_cards_count")?)?,
        }),
        // ===== 摊牌 & 结算事件 =====
        "WinnerAwarded" => Some(SuiChainEvent::WinnerAwarded {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: json_as_u64(data.get("seat_index")?)?,
            player: data.get("player")?.as_str()?.to_string(),
            amount: json_as_u64(data.get("amount")?)?,
            pot_type: u64_to_u8(json_as_u64(data.get("pot_type")?)?)?,
            hand_rank: data.get("hand_rank").and_then(json_as_u64),
        }),
        "HandEndedWithoutShowdown" => Some(SuiChainEvent::HandEndedWithoutShowdown {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            winner_seat: json_as_u64(data.get("winner_seat")?)?,
            winner_player: data.get("winner_player")?.as_str()?.to_string(),
            pot: json_as_u64(data.get("pot")?)?,
        }),
        "ShowdownHoleCardsRevealed" => Some(SuiChainEvent::ShowdownHoleCardsRevealed {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: json_as_u64(data.get("seat_index")?)?,
            player: data.get("player")?.as_str()?.to_string(),
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
        "HandSettled" => Some(SuiChainEvent::HandSettled {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            pot: json_as_u64(data.get("pot")?)?,
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
            round_state: u64_to_u8(json_as_u64(data.get("round_state")?)?)?,
        }),
        "ReconstructDeckSubmitted" => Some(SuiChainEvent::ReconstructDeckSubmitted {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: json_as_u64(data.get("seat_index")?)?,
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
            seat_index: json_as_u64(data.get("seat_index")?)?,
            card_indices: data.get("card_indices")?
                .as_array()?
                .iter()
                .filter_map(|v| v.as_u64())
                .collect(),
        }),
        "DeckRebuilt" => Some(SuiChainEvent::DeckRebuilt {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            reason: u64_to_u8(json_as_u64(data.get("reason")?)?)?,
            deck_size: json_as_u64(data.get("deck_size")?)?,
        }),
        // ===== 管理 & 生命周期事件 =====
        "PlayerKicked" => Some(SuiChainEvent::PlayerKicked {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: json_as_u64(data.get("seat_index")?)?,
            player: data.get("player")?.as_str()?.to_string(),
            reason: u64_to_u8(json_as_u64(data.get("reason")?)?)?,
        }),
        "PlayerRefund" => Some(SuiChainEvent::PlayerRefund {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            seat_index: json_as_u64(data.get("seat_index")?)?,
            player: data.get("player")?.as_str()?.to_string(),
            amount: json_as_u64(data.get("amount")?)?,
            refund_type: u64_to_u8(json_as_u64(data.get("refund_type")?)?)?,
        }),
        "HandReset" => Some(SuiChainEvent::HandReset {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            reason: u64_to_u8(json_as_u64(data.get("reason")?)?)?,
            round_state: u64_to_u8(json_as_u64(data.get("round_state")?)?)?,
        }),
        "TimeoutConfigUpdated" => Some(SuiChainEvent::TimeoutConfigUpdated {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            betting_timeout_ms: json_as_u64(data.get("betting_timeout_ms")?)?,
            shuffle_timeout_ms: json_as_u64(data.get("shuffle_timeout_ms")?)?,
            reveal_timeout_ms: json_as_u64(data.get("reveal_timeout_ms")?)?,
            reconstruct_timeout_ms: json_as_u64(data.get("reconstruct_timeout_ms")?)?,
            showdown_display_ms: json_as_u64(data.get("showdown_display_ms")?)?,
        }),
        "CurrentTurnChanged" => Some(SuiChainEvent::CurrentTurnChanged {
            table_id: data.get("table_id")?.as_str()?.to_string(),
            old_turn: data.get("old_turn").and_then(json_as_u64),
            new_turn: data.get("new_turn").and_then(json_as_u64),
            round_state: u64_to_u8(json_as_u64(data.get("round_state")?)?)?,
        }),
        _ => {
            tracing::warn!("[sui_events] unknown event type: {}", event_name);
            None
        }
    }
}

// ========== BCS 回退解析 ==========
//
// gRPC SubscribeCheckpoints 的 Event.json 字段可能不被服务端填充。
// 当 json 为 None 但 contents (BCS) 存在时，使用此模块解析。
//
// BCS 编码规则:
//   address / ID: 32 字节原始数据
//   u64: 8 字节小端
//   u8: 1 字节
//   bool: 1 字节 (0 或 1)
//   String: ULEB128 长度 + UTF-8 字节
//   vector<T>: ULEB128 长度 + N 个元素
//   Option<T>: 1 字节标签 (0=None, 1=Some) + 值

struct BcsReader<'a> { data: &'a [u8], pos: usize }

impl<'a> BcsReader<'a> {
    fn new(data: &'a [u8]) -> Self { Self { data, pos: 0 } }

    fn read_bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.pos + n > self.data.len() { return None; }
        let r = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Some(r)
    }
    fn read_uleb128(&mut self) -> Option<u64> {
        let mut result: u64 = 0; let mut shift = 0;
        loop {
            let b = self.read_bytes(1)?[0];
            result |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 { break; }
            shift += 7; if shift >= 64 { return None; }
        }
        Some(result)
    }
    fn read_address(&mut self) -> Option<String> {
        Some(format!("0x{}", hex::encode(self.read_bytes(32)?)))
    }
    fn read_u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.read_bytes(8)?.try_into().ok()?))
    }
    fn read_u8(&mut self) -> Option<u8> { Some(self.read_bytes(1)?[0]) }
    fn read_bool(&mut self) -> Option<bool> { Some(self.read_u8()? != 0) }
    fn read_string(&mut self) -> Option<String> {
        let len = self.read_uleb128()? as usize;
        String::from_utf8(self.read_bytes(len)?.to_vec()).ok()
    }
    fn read_vec_u64(&mut self) -> Option<Vec<u64>> {
        let len = self.read_uleb128()? as usize;
        (0..len).map(|_| self.read_u64()).collect()
    }
    fn read_vec_u8(&mut self) -> Option<Vec<u8>> {
        let len = self.read_uleb128()? as usize;
        Some(self.read_bytes(len)?.to_vec())
    }
    fn read_option_u64(&mut self) -> Option<Option<u64>> {
        if self.read_u8()? == 0 { Some(None) } else { Some(Some(self.read_u64()?)) }
    }
}

/// 从 BCS 字节解析事件，返回 JSON Value 供 parse_chain_event 使用。
pub fn parse_bcs_event(event_type: &str, bytes: &[u8]) -> Option<serde_json::Value> {
    let event_name = event_type.rsplit("::").next()?;
    let mut r = BcsReader::new(bytes);
    let mut m = serde_json::Map::new();
    macro_rules! addr { ($n:expr) => { m.insert($n.to_string(), serde_json::json!(r.read_address()?)); } }
    macro_rules! u64 { ($n:expr) => { m.insert($n.to_string(), serde_json::json!(r.read_u64()?)); } }
    macro_rules! u8 { ($n:expr) => { m.insert($n.to_string(), serde_json::json!(r.read_u8()?)); } }
    macro_rules! bool { ($n:expr) => { m.insert($n.to_string(), serde_json::json!(r.read_bool()?)); } }
    macro_rules! str { ($n:expr) => { m.insert($n.to_string(), serde_json::json!(r.read_string()?)); } }
    macro_rules! vu64 { ($n:expr) => { m.insert($n.to_string(), serde_json::json!(r.read_vec_u64()?)); } }
    macro_rules! vu8 { ($n:expr) => { m.insert($n.to_string(), serde_json::json!(r.read_vec_u8()?)); } }
    macro_rules! ou64 { ($n:expr) => { m.insert($n.to_string(), match r.read_option_u64()? { Some(v) => serde_json::json!(v), None => serde_json::Value::Null }); } }

    match event_name {
        "TableCreated" => { addr!("table_id"); str!("name"); }
        "PlayerJoined" => { addr!("table_id"); u64!("seat_index"); addr!("player"); u64!("buy_in"); bool!("is_waiting"); u64!("active_count_after"); }
        "PlayerLeft" => { addr!("table_id"); u64!("seat_index"); addr!("player"); }
        "HandStarted" => { addr!("table_id"); u64!("button"); u64!("small_blind"); u64!("big_blind"); vu64!("participants"); }
        "BlindsPosted" => { addr!("table_id"); u64!("sb_seat"); u64!("bb_seat"); u64!("sb_amount"); u64!("bb_amount"); u64!("first_to_act"); }
        "BettingRoundStarted" => { addr!("table_id"); u8!("round_state"); u64!("current_bet"); u64!("min_raise"); u64!("first_to_act"); u64!("pot_before"); }
        "RoundAdvanced" => { addr!("table_id"); u8!("from_round"); u8!("to_round"); u64!("pot"); u64!("community_cards_count"); }
        "PotCollected" => { addr!("table_id"); u8!("round_state"); u64!("pot_after"); vu64!("collected_from_seats"); }
        "WinnerAwarded" => { addr!("table_id"); u64!("seat_index"); addr!("player"); u64!("amount"); u8!("pot_type"); ou64!("hand_rank"); }
        "HandSettled" => { addr!("table_id"); u64!("pot"); vu64!("winners"); }
        "HandEndedWithoutShowdown" => { addr!("table_id"); u64!("winner_seat"); addr!("winner_player"); u64!("pot"); }
        "HandReset" => { addr!("table_id"); u8!("reason"); u8!("round_state"); }
        "PlayerFolded" => { addr!("table_id"); u64!("seat_index"); u8!("reason"); u8!("round_state"); }
        "PlayerChecked" => { addr!("table_id"); u64!("seat_index"); u8!("round_state"); }
        "PlayerCalled" => { addr!("table_id"); u64!("seat_index"); u64!("call_delta"); u8!("round_state"); }
        "PlayerRaised" => { addr!("table_id"); u64!("seat_index"); u64!("raise_delta"); u64!("total_bet"); u8!("round_state"); }
        "PlayerAllIn" => { addr!("table_id"); u64!("seat_index"); u8!("trigger_action"); u64!("amount"); u8!("round_state"); }
        "ShuffleVerified" => { addr!("table_id"); u64!("seat_index"); addr!("player"); }
        "ShuffleTurnEvt" => { addr!("table_id"); u64!("seat_index"); u64!("pending_count"); u64!("completed_count"); }
        "ShuffleCompleteEvt" => { addr!("table_id"); u8!("phase"); u64!("participant_count"); u64!("deck_size"); }
        "ShuffleTimeout" => { addr!("table_id"); u64!("seat_index"); u8!("phase"); u64!("started_at"); u64!("timeout_ms"); }
        "RevealPhaseEvt" => { addr!("table_id"); u8!("phase"); }
        "RevealTokenSubmitted" => { addr!("table_id"); u64!("seat_index"); u64!("card_index"); u8!("phase"); }
        "RevealPhaseComplete" => { addr!("table_id"); u8!("phase"); }
        "RevealTimeout" => { addr!("table_id"); u8!("phase"); vu64!("pending_players"); }
        "CardIsIdentity" => { addr!("table_id"); u64!("card_index"); u64!("assignment_index"); u8!("phase"); }
        "IdentityRedeal" => { addr!("table_id"); vu64!("identity_card_indices"); u64!("redeal_count"); u8!("phase"); }
        "RedealRequested" => { addr!("table_id"); u64!("seat_index"); vu64!("card_indices"); }
        "CommunityCardRevealed" => { addr!("table_id"); u8!("phase"); vu64!("card_indices"); vu8!("card_ranks"); vu8!("card_suits"); }
        "ShowdownHoleCardsRevealed" => { addr!("table_id"); u64!("seat_index"); addr!("player"); vu64!("card_indices"); vu8!("card_ranks"); vu8!("card_suits"); }
        "ReconstructInitiated" => { addr!("table_id"); vu64!("expected_players"); u8!("round_state"); }
        "ReconstructDeckSubmitted" => { addr!("table_id"); u64!("seat_index"); }
        "ReconstructCompleteEvt" => { addr!("table_id"); }
        "ReconstructTimeout" => { addr!("table_id"); vu64!("pending_players"); }
        "PlayerKicked" => { addr!("table_id"); u64!("seat_index"); addr!("player"); u8!("reason"); }
        "PlayerRefund" => { addr!("table_id"); u64!("seat_index"); addr!("player"); u64!("amount"); u8!("refund_type"); }
        "TimeoutConfigUpdated" => { addr!("table_id"); u64!("betting_timeout_ms"); u64!("shuffle_timeout_ms"); u64!("reveal_timeout_ms"); u64!("reconstruct_timeout_ms"); u64!("showdown_display_ms"); }
        "CurrentTurnChanged" => { addr!("table_id"); ou64!("old_turn"); ou64!("new_turn"); u8!("round_state"); }
        _ => { tracing::warn!("[parse_bcs_event] unknown event: {}", event_name); return None; }
    }
    Some(serde_json::Value::Object(m))
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

    #[test]
    fn test_current_turn_changed() {
        let data = serde_json::json!({
            "table_id": "0x123",
            "old_turn": 2,
            "new_turn": 3,
            "round_state": 1
        });
        let event = parse_event("CurrentTurnChanged", data).unwrap();
        assert_eq!(event, SuiChainEvent::CurrentTurnChanged {
            table_id: "0x123".to_string(),
            old_turn: Some(2),
            new_turn: Some(3),
            round_state: 1,
        });
    }

    #[test]
    fn test_current_turn_changed_cleared() {
        // new_turn 为 null 表示 current_turn 被清空（如轮次结束）
        let data = serde_json::json!({
            "table_id": "0x123",
            "old_turn": 3,
            "new_turn": null,
            "round_state": 2
        });
        let event = parse_event("CurrentTurnChanged", data).unwrap();
        assert_eq!(event, SuiChainEvent::CurrentTurnChanged {
            table_id: "0x123".to_string(),
            old_turn: Some(3),
            new_turn: None,
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
        // PlayerJoined 缺少必填字段 player
        let data = serde_json::json!({
            "table_id": "0x123",
            "seat_index": 0,
            "buy_in": 1000,
            "is_waiting": false,
            "active_count_after": 1
            // 缺少 player
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
