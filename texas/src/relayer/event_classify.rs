//! 事件分类与去重辅助函数。
//!
//! 提供 SuiChainEvent 变体名称提取、table_id 提取、round_state 提取、
//! 关键事件判定，以及基于事件内容的去重 key 构建。

use crate::sui_events::SuiChainEvent;

/// Task 16: 返回 SuiChainEvent 变体的简短名称（用于去重 key）。
pub(crate) fn event_type_name(event: &SuiChainEvent) -> &'static str {
    match event {
        SuiChainEvent::TableCreated { .. } => "TableCreated",
        SuiChainEvent::PlayerJoined { .. } => "PlayerJoined",
        SuiChainEvent::PlayerLeft { .. } => "PlayerLeft",
        SuiChainEvent::HandStarted { .. } => "HandStarted",
        SuiChainEvent::BlindsPosted { .. } => "BlindsPosted",
        SuiChainEvent::ShuffleVerified { .. } => "ShuffleVerified",
        SuiChainEvent::ShuffleComplete { .. } => "ShuffleComplete",
        SuiChainEvent::ShuffleTurn { .. } => "ShuffleTurn",
        SuiChainEvent::ShuffleTimeout { .. } => "ShuffleTimeout",
        SuiChainEvent::RevealTokenSubmitted { .. } => "RevealTokenSubmitted",
        SuiChainEvent::RevealPhaseComplete { .. } => "RevealPhaseComplete",
        SuiChainEvent::RevealPhaseEvt { .. } => "RevealPhaseEvt",
        SuiChainEvent::CardIsIdentity { .. } => "CardIsIdentity",
        SuiChainEvent::IdentityRedeal { .. } => "IdentityRedeal",
        SuiChainEvent::CommunityCardRevealed { .. } => "CommunityCardRevealed",
        SuiChainEvent::RevealTimeout { .. } => "RevealTimeout",
        SuiChainEvent::BettingRoundStarted { .. } => "BettingRoundStarted",
        SuiChainEvent::PlayerFolded { .. } => "PlayerFolded",
        SuiChainEvent::PlayerChecked { .. } => "PlayerChecked",
        SuiChainEvent::PlayerCalled { .. } => "PlayerCalled",
        SuiChainEvent::PlayerRaised { .. } => "PlayerRaised",
        SuiChainEvent::PlayerAllIn { .. } => "PlayerAllIn",
        SuiChainEvent::PotCollected { .. } => "PotCollected",
        SuiChainEvent::RoundAdvanced { .. } => "RoundAdvanced",
        SuiChainEvent::WinnerAwarded { .. } => "WinnerAwarded",
        SuiChainEvent::HandEndedWithoutShowdown { .. } => "HandEndedWithoutShowdown",
        SuiChainEvent::ShowdownHoleCardsRevealed { .. } => "ShowdownHoleCardsRevealed",
        SuiChainEvent::HandSettled { .. } => "HandSettled",
        SuiChainEvent::ReconstructInitiated { .. } => "ReconstructInitiated",
        SuiChainEvent::ReconstructDeckSubmitted { .. } => "ReconstructDeckSubmitted",
        SuiChainEvent::ReconstructComplete { .. } => "ReconstructComplete",
        SuiChainEvent::ReconstructTimeout { .. } => "ReconstructTimeout",
        SuiChainEvent::RedealRequested { .. } => "RedealRequested",
        SuiChainEvent::DeckRebuilt { .. } => "DeckRebuilt",
        SuiChainEvent::PlayerKicked { .. } => "PlayerKicked",
        SuiChainEvent::PlayerRefund { .. } => "PlayerRefund",
        SuiChainEvent::HandReset { .. } => "HandReset",
        SuiChainEvent::TimeoutConfigUpdated { .. } => "TimeoutConfigUpdated",
        SuiChainEvent::CurrentTurnChanged { .. } => "CurrentTurnChanged",
    }
}

/// Task 16: 为任意 SuiChainEvent 构建去重 key。
///
/// - 带 seat_index 的事件：`evt:{table_id}:{event_type}:{seat_index}:{phase_or_round}:{card_index_or_zero}`
/// - 不带 seat_index 的事件：`evt:{table_id}:{event_type}:{content_hash}`
///   （tx_digest 不易获取，使用事件内容哈希作为去重依据）
pub fn build_event_dedup_key(event: &SuiChainEvent) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let table_id = table_id_from_event(event);
    let etype = event_type_name(event);

    match event {
        // 含 player 钱包地址的座位事件：必须把 player 纳入 key，
        // 否则不同玩家复用同一座位时去重 key 碰撞（A 离开 seat 1 后 B 加入又离开，
        // 两次 PlayerLeft 的 key 相同，第二次被错误跳过，B 永远不会被移除）。
        SuiChainEvent::PlayerJoined { seat_index, player, .. }
        | SuiChainEvent::PlayerLeft { seat_index, player, .. }
        | SuiChainEvent::PlayerKicked { seat_index, player, .. }
        | SuiChainEvent::PlayerRefund { seat_index, player, .. } => {
            format!("evt:{}:{}:{}:{}:0", table_id, etype, seat_index, player)
        }
        // 其他带 seat_index 的事件（无 player 字段）
        SuiChainEvent::ShuffleVerified { seat_index, .. }
        | SuiChainEvent::ShuffleTurn { seat_index, .. }
        | SuiChainEvent::ShuffleTimeout { seat_index, .. }
        | SuiChainEvent::ReconstructDeckSubmitted { seat_index, .. }
        | SuiChainEvent::RedealRequested { seat_index, .. }
        | SuiChainEvent::ShowdownHoleCardsRevealed { seat_index, .. }
        | SuiChainEvent::WinnerAwarded { seat_index, .. } => {
            format!("evt:{}:{}:{}:0:0", table_id, etype, seat_index)
        }
        // 带 seat_index + round_state 的行动事件
        SuiChainEvent::PlayerFolded { seat_index, round_state, .. }
        | SuiChainEvent::PlayerChecked { seat_index, round_state, .. }
        | SuiChainEvent::PlayerCalled { seat_index, round_state, .. }
        | SuiChainEvent::PlayerRaised { seat_index, round_state, .. }
        | SuiChainEvent::PlayerAllIn { seat_index, round_state, .. } => {
            format!("evt:{}:{}:{}:{}:0", table_id, etype, seat_index, round_state)
        }
        // 带 seat_index + card_index 的事件
        SuiChainEvent::RevealTokenSubmitted { seat_index, card_index, phase, .. } => {
            format!("evt:{}:{}:{}:{}:{}", table_id, etype, seat_index, phase, card_index)
        }
        // CardIsIdentity 有 card_index 但无 seat_index
        SuiChainEvent::CardIsIdentity { card_index, phase, .. } => {
            format!("evt:{}:{}:0:{}:{}", table_id, etype, phase, card_index)
        }
        // 带 phase 的事件（无 seat_index）
        SuiChainEvent::ShuffleComplete { phase, .. }
        | SuiChainEvent::RevealPhaseComplete { phase, .. }
        | SuiChainEvent::RevealPhaseEvt { phase, .. }
        | SuiChainEvent::IdentityRedeal { phase, .. }
        | SuiChainEvent::CommunityCardRevealed { phase, .. }
        | SuiChainEvent::RevealTimeout { phase, .. } => {
            format!("evt:{}:{}:0:{}:0", table_id, etype, phase)
        }
        // 带 round_state 的事件（无 seat_index）
        SuiChainEvent::BettingRoundStarted { round_state, .. }
        | SuiChainEvent::PotCollected { round_state, .. }
        | SuiChainEvent::ReconstructInitiated { round_state, .. }
        | SuiChainEvent::HandReset { round_state, .. } => {
            format!("evt:{}:{}:0:{}:0", table_id, etype, round_state)
        }
        // 其他无 seat_index 的事件：使用内容哈希
        _ => {
            let mut hasher = DefaultHasher::new();
            if let Ok(s) = serde_json::to_string(event) {
                s.hash(&mut hasher);
            } else {
                format!("{:?}", event).hash(&mut hasher);
            }
            format!("evt:{}:{}:{:016x}", table_id, etype, hasher.finish())
        }
    }
}

/// 从 SuiChainEvent 中提取 table_id
pub(crate) fn table_id_from_event(event: &SuiChainEvent) -> &str {
    match event {
        SuiChainEvent::TableCreated { table_id, .. } => table_id,
        SuiChainEvent::PlayerJoined { table_id, .. } => table_id,
        SuiChainEvent::PlayerLeft { table_id, .. } => table_id,
        SuiChainEvent::HandStarted { table_id, .. } => table_id,
        SuiChainEvent::BlindsPosted { table_id, .. } => table_id,
        SuiChainEvent::ShuffleVerified { table_id, .. } => table_id,
        SuiChainEvent::ShuffleComplete { table_id, .. } => table_id,
        SuiChainEvent::ShuffleTurn { table_id, .. } => table_id,
        SuiChainEvent::ShuffleTimeout { table_id, .. } => table_id,
        SuiChainEvent::RevealTokenSubmitted { table_id, .. } => table_id,
        SuiChainEvent::RevealPhaseComplete { table_id, .. } => table_id,
        SuiChainEvent::RevealPhaseEvt { table_id, .. } => table_id,
        SuiChainEvent::CardIsIdentity { table_id, .. } => table_id,
        SuiChainEvent::IdentityRedeal { table_id, .. } => table_id,
        SuiChainEvent::CommunityCardRevealed { table_id, .. } => table_id,
        SuiChainEvent::RevealTimeout { table_id, .. } => table_id,
        SuiChainEvent::BettingRoundStarted { table_id, .. } => table_id,
        SuiChainEvent::PlayerFolded { table_id, .. } => table_id,
        SuiChainEvent::PlayerChecked { table_id, .. } => table_id,
        SuiChainEvent::PlayerCalled { table_id, .. } => table_id,
        SuiChainEvent::PlayerRaised { table_id, .. } => table_id,
        SuiChainEvent::PlayerAllIn { table_id, .. } => table_id,
        SuiChainEvent::PotCollected { table_id, .. } => table_id,
        SuiChainEvent::RoundAdvanced { table_id, .. } => table_id,
        SuiChainEvent::WinnerAwarded { table_id, .. } => table_id,
        SuiChainEvent::HandEndedWithoutShowdown { table_id, .. } => table_id,
        SuiChainEvent::ShowdownHoleCardsRevealed { table_id, .. } => table_id,
        SuiChainEvent::HandSettled { table_id, .. } => table_id,
        SuiChainEvent::ReconstructInitiated { table_id, .. } => table_id,
        SuiChainEvent::ReconstructDeckSubmitted { table_id, .. } => table_id,
        SuiChainEvent::ReconstructComplete { table_id, .. } => table_id,
        SuiChainEvent::ReconstructTimeout { table_id, .. } => table_id,
        SuiChainEvent::RedealRequested { table_id, .. } => table_id,
        SuiChainEvent::DeckRebuilt { table_id, .. } => table_id,
        SuiChainEvent::PlayerKicked { table_id, .. } => table_id,
        SuiChainEvent::PlayerRefund { table_id, .. } => table_id,
        SuiChainEvent::HandReset { table_id, .. } => table_id,
        SuiChainEvent::TimeoutConfigUpdated { table_id, .. } => table_id,
        SuiChainEvent::CurrentTurnChanged { table_id, .. } => table_id,
    }
}

/// 从玩家行动事件中提取 round_state。
/// 用于 trick：行动事件后直接同步 current_turn，需要 round_state 作为参数。
pub(crate) fn round_state_from_event(event: &SuiChainEvent) -> Option<u8> {
    match event {
        SuiChainEvent::PlayerFolded { round_state, .. }
        | SuiChainEvent::PlayerChecked { round_state, .. }
        | SuiChainEvent::PlayerCalled { round_state, .. }
        | SuiChainEvent::PlayerRaised { round_state, .. }
        | SuiChainEvent::PlayerAllIn { round_state, .. } => Some(*round_state),
        _ => None,
    }
}

/// 判断事件是否为关键事件（状态变更类），需要 fetch 完整快照。
/// 非关键事件（如 ShuffleTurn / RevealTokenSubmitted 等中间过程事件）
/// 在缓存已存在且非 stale 时跳过 fetch，减少冗余 RPC。
pub(crate) fn is_key_event(event: &SuiChainEvent) -> bool {
    // G2 修复：PlayerJoined/PlayerLeft 改变了 seat_players 映射，必须刷新缓存
    matches!(
        event,
        SuiChainEvent::TableCreated { .. }
            | SuiChainEvent::PlayerJoined { .. }
            | SuiChainEvent::PlayerLeft { .. }
            | SuiChainEvent::HandStarted { .. }
            | SuiChainEvent::ShuffleComplete { .. }
            | SuiChainEvent::RevealPhaseComplete { .. }
            | SuiChainEvent::BettingRoundStarted { .. }
            | SuiChainEvent::RoundAdvanced { .. }
            | SuiChainEvent::HandSettled { .. }
            | SuiChainEvent::HandReset { .. }
            | SuiChainEvent::ReconstructInitiated { .. }
            | SuiChainEvent::ReconstructComplete { .. }
            | SuiChainEvent::PlayerFolded { .. }
            | SuiChainEvent::PlayerCalled { .. }
            | SuiChainEvent::PlayerRaised { .. }
            | SuiChainEvent::PlayerAllIn { .. }
            | SuiChainEvent::PotCollected { .. }
            | SuiChainEvent::CurrentTurnChanged { .. }
    )
}
