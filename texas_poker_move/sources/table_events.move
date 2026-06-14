module texas_poker::table_events;

/// 所有牌桌相关的事件定义
/// 从 table.move 中提取，便于链下索引和调试
///
/// 事件分类:
/// 1. 牌桌生命周期: TableCreated, PlayerJoined, PlayerLeft
/// 2. 手牌生命周期: HandStarted, BlindsPosted, BettingRoundStarted, RoundAdvanced,
///    PotCollected, WinnerAwarded, HandSettled, HandEndedWithoutShowdown, HandReset
/// 3. 下注操作: PlayerFolded, PlayerChecked, PlayerCalled, PlayerRaised, PlayerAllIn
/// 4. 洗牌协议: ShuffleVerified, ShuffleTurnEvt, ShuffleCompleteEvt, ShuffleTimeout
/// 5. 揭示协议: RevealPhaseEvt, RevealTokenSubmitted, RevealPhaseComplete, RevealTimeout,
///    CardIsIdentity, IdentityRedeal, RedealRequested, CommunityCardRevealed
/// 6. 重构协议: ReconstructInitiated, ReconstructDeckSubmitted, ReconstructCompleteEvt, ReconstructTimeout
/// 7. 玩家管理: PlayerKicked, PlayerRefund

use sui::event;
use std::string::String;

// ========== 退款类型常量 ==========
const REFUND_TYPE_STACK_ONLY: u8 = 0;
const REFUND_TYPE_STACK_AND_BET: u8 = 1;
const REFUND_TYPE_BET_ONLY: u8 = 2;

// ========== 踢人原因常量 ==========
const KICK_REASON_TIMEOUT: u8 = 0;
const KICK_REASON_ADMIN: u8 = 1;
const KICK_REASON_RECONSTRUCT_TIMEOUT: u8 = 2;

// ========== 重置原因常量 ==========
const RESET_REASON_TIMEOUT: u8 = 0;
const RESET_REASON_KICK: u8 = 1;
const RESET_REASON_RECONSTRUCT_FAIL: u8 = 2;
const RESET_REASON_LAST_PLAYER_STANDING: u8 = 3;

// ========== 弃牌原因常量 ==========
const FOLD_REASON_MANUAL: u8 = 0;
const FOLD_REASON_AUTO_TIMEOUT: u8 = 1;
const FOLD_REASON_FORCE_ADMIN: u8 = 2;

// ========== 常量访问器 ==========
public fun refund_type_stack_only(): u8 { REFUND_TYPE_STACK_ONLY }
public fun refund_type_stack_and_bet(): u8 { REFUND_TYPE_STACK_AND_BET }
public fun refund_type_bet_only(): u8 { REFUND_TYPE_BET_ONLY }

public fun kick_reason_timeout(): u8 { KICK_REASON_TIMEOUT }
public fun kick_reason_admin(): u8 { KICK_REASON_ADMIN }
public fun kick_reason_reconstruct_timeout(): u8 { KICK_REASON_RECONSTRUCT_TIMEOUT }

public fun reset_reason_timeout(): u8 { RESET_REASON_TIMEOUT }
public fun reset_reason_kick(): u8 { RESET_REASON_KICK }
public fun reset_reason_reconstruct_fail(): u8 { RESET_REASON_RECONSTRUCT_FAIL }
public fun reset_reason_last_player_standing(): u8 { RESET_REASON_LAST_PLAYER_STANDING }

public fun fold_reason_manual(): u8 { FOLD_REASON_MANUAL }
public fun fold_reason_auto_timeout(): u8 { FOLD_REASON_AUTO_TIMEOUT }
public fun fold_reason_force_admin(): u8 { FOLD_REASON_FORCE_ADMIN }

// ========== 1. 牌桌生命周期 ==========

public struct TableCreated has copy, drop {
    table_id: ID,
    name: String,
}

public struct PlayerJoined has copy, drop {
    table_id: ID,
    seat_index: u64,
    player: address,
    buy_in: u64,
    is_waiting: bool,
    active_count_after: u64,
}

public struct PlayerLeft has copy, drop {
    table_id: ID,
    seat_index: u64,
    player: address,
}

// ========== 2. 手牌生命周期 ==========

public struct HandStarted has copy, drop {
    table_id: ID,
    button: u64,
    small_blind: u64,
    big_blind: u64,
    participants: vector<u64>,
}

public struct BlindsPosted has copy, drop {
    table_id: ID,
    sb_seat: u64,
    bb_seat: u64,
    sb_amount: u64,
    bb_amount: u64,
    first_to_act: u64,
}

public struct BettingRoundStarted has copy, drop {
    table_id: ID,
    round_state: u8,
    current_bet: u64,
    min_raise: u64,
    first_to_act: u64,
    pot_before: u64,
}

public struct RoundAdvanced has copy, drop {
    table_id: ID,
    from_round: u8,
    to_round: u8,
    pot: u64,
    community_cards_count: u64,
}

public struct PotCollected has copy, drop {
    table_id: ID,
    round_state: u8,
    pot_after: u64,
    collected_from_seats: vector<u64>,
}

public struct WinnerAwarded has copy, drop {
    table_id: ID,
    seat_index: u64,
    player: address,
    amount: u64,
    /// 0=main_pot, 1=side_pot
    pot_type: u8,
    /// 最佳牌型 (None=无摊牌直接获胜)
    hand_rank: Option<u64>,
}

public struct HandSettled has copy, drop {
    table_id: ID,
    pot: u64,
    winners: vector<u64>,
}

public struct HandEndedWithoutShowdown has copy, drop {
    table_id: ID,
    winner_seat: u64,
    winner_player: address,
    pot: u64,
}

public struct HandReset has copy, drop {
    table_id: ID,
    reason: u8,
    round_state: u8,
}

// ========== 3. 下注操作 ==========

public struct PlayerFolded has copy, drop {
    table_id: ID,
    seat_index: u64,
    /// 0=manual, 1=auto_timeout, 2=force_admin
    reason: u8,
    round_state: u8,
}

public struct PlayerChecked has copy, drop {
    table_id: ID,
    seat_index: u64,
    round_state: u8,
}

public struct PlayerCalled has copy, drop {
    table_id: ID,
    seat_index: u64,
    /// 本次实际投入增量
    call_delta: u64,
    round_state: u8,
}

public struct PlayerRaised has copy, drop {
    table_id: ID,
    seat_index: u64,
    /// 本次加注增量
    raise_delta: u64,
    /// 加注后该玩家累计下注
    total_bet: u64,
    round_state: u8,
}

public struct PlayerAllIn has copy, drop {
    table_id: ID,
    seat_index: u64,
    /// 0=call_all_in, 1=raise_all_in
    trigger_action: u8,
    amount: u64,
    round_state: u8,
}

// ========== 4. 洗牌协议 ==========

public struct ShuffleVerified has copy, drop {
    table_id: ID,
    seat_index: u64,
    player: address,
}

public struct ShuffleTurnEvt has copy, drop {
    table_id: ID,
    seat_index: u64,
    pending_count: u64,
    completed_count: u64,
}

public struct ShuffleCompleteEvt has copy, drop {
    table_id: ID,
    phase: u8,
    participant_count: u64,
    deck_size: u64,
}

public struct ShuffleTimeout has copy, drop {
    table_id: ID,
    seat_index: u64,
    phase: u8,
    started_at: u64,
    timeout_ms: u64,
}

// ========== 5. 揭示协议 ==========

public struct RevealPhaseEvt has copy, drop {
    table_id: ID,
    phase: u8,
}

public struct RevealTokenSubmitted has copy, drop {
    table_id: ID,
    seat_index: u64,
    card_index: u64,
    phase: u8,
}

public struct RevealPhaseComplete has copy, drop {
    table_id: ID,
    phase: u8,
}

public struct RevealTimeout has copy, drop {
    table_id: ID,
    phase: u8,
    pending_players: vector<u64>,
}

public struct CardIsIdentity has copy, drop {
    table_id: ID,
    card_index: u64,
    assignment_index: u64,
    phase: u8,
}

public struct IdentityRedeal has copy, drop {
    table_id: ID,
    identity_card_indices: vector<u64>,
    redeal_count: u64,
    phase: u8,
}

public struct RedealRequested has copy, drop {
    table_id: ID,
    seat_index: u64,
    card_indices: vector<u64>,
}

public struct CommunityCardRevealed has copy, drop {
    table_id: ID,
    phase: u8,
    card_indices: vector<u64>,
    card_ranks: vector<u8>,
    card_suits: vector<u8>,
}

// ========== 6. 重构协议 ==========

public struct ReconstructInitiated has copy, drop {
    table_id: ID,
    expected_players: vector<u64>,
    round_state: u8,
}

public struct ReconstructDeckSubmitted has copy, drop {
    table_id: ID,
    seat_index: u64,
}

public struct ReconstructCompleteEvt has copy, drop {
    table_id: ID,
}

public struct ReconstructTimeout has copy, drop {
    table_id: ID,
    pending_players: vector<u64>,
}

// ========== 7. 玩家管理 ==========

public struct PlayerKicked has copy, drop {
    table_id: ID,
    seat_index: u64,
    player: address,
    reason: u8,
}

public struct PlayerRefund has copy, drop {
    table_id: ID,
    seat_index: u64,
    player: address,
    amount: u64,
    refund_type: u8,
}

// ========== 便捷发射函数 ==========

// --- 牌桌生命周期 ---
public fun emit_table_created(table_id: ID, name: String) {
    event::emit(TableCreated { table_id, name });
}

public fun emit_player_joined(table_id: ID, seat_index: u64, player: address, buy_in: u64, is_waiting: bool, active_count_after: u64) {
    event::emit(PlayerJoined { table_id, seat_index, player, buy_in, is_waiting, active_count_after });
}

public fun emit_player_left(table_id: ID, seat_index: u64, player: address) {
    event::emit(PlayerLeft { table_id, seat_index, player });
}

// --- 手牌生命周期 ---
public fun emit_hand_started(table_id: ID, button: u64, small_blind: u64, big_blind: u64, participants: vector<u64>) {
    event::emit(HandStarted { table_id, button, small_blind, big_blind, participants });
}

public fun emit_blinds_posted(table_id: ID, sb_seat: u64, bb_seat: u64, sb_amount: u64, bb_amount: u64, first_to_act: u64) {
    event::emit(BlindsPosted { table_id, sb_seat, bb_seat, sb_amount, bb_amount, first_to_act });
}

public fun emit_betting_round_started(table_id: ID, round_state: u8, current_bet: u64, min_raise: u64, first_to_act: u64, pot_before: u64) {
    event::emit(BettingRoundStarted { table_id, round_state, current_bet, min_raise, first_to_act, pot_before });
}

public fun emit_round_advanced(table_id: ID, from_round: u8, to_round: u8, pot: u64, community_cards_count: u64) {
    event::emit(RoundAdvanced { table_id, from_round, to_round, pot, community_cards_count });
}

public fun emit_pot_collected(table_id: ID, round_state: u8, pot_after: u64, collected_from_seats: vector<u64>) {
    event::emit(PotCollected { table_id, round_state, pot_after, collected_from_seats });
}

public fun emit_winner_awarded(table_id: ID, seat_index: u64, player: address, amount: u64, pot_type: u8, hand_rank: Option<u64>) {
    event::emit(WinnerAwarded { table_id, seat_index, player, amount, pot_type, hand_rank });
}

public fun emit_hand_settled(table_id: ID, pot: u64, winners: vector<u64>) {
    event::emit(HandSettled { table_id, pot, winners });
}

public fun emit_hand_ended_without_showdown(table_id: ID, winner_seat: u64, winner_player: address, pot: u64) {
    event::emit(HandEndedWithoutShowdown { table_id, winner_seat, winner_player, pot });
}

public fun emit_hand_reset(table_id: ID, reason: u8, round_state: u8) {
    event::emit(HandReset { table_id, reason, round_state });
}

// --- 下注操作 ---
public fun emit_player_folded(table_id: ID, seat_index: u64, reason: u8, round_state: u8) {
    event::emit(PlayerFolded { table_id, seat_index, reason, round_state });
}

public fun emit_player_checked(table_id: ID, seat_index: u64, round_state: u8) {
    event::emit(PlayerChecked { table_id, seat_index, round_state });
}

public fun emit_player_called(table_id: ID, seat_index: u64, call_delta: u64, round_state: u8) {
    event::emit(PlayerCalled { table_id, seat_index, call_delta, round_state });
}

public fun emit_player_raised(table_id: ID, seat_index: u64, raise_delta: u64, total_bet: u64, round_state: u8) {
    event::emit(PlayerRaised { table_id, seat_index, raise_delta, total_bet, round_state });
}

public fun emit_player_all_in(table_id: ID, seat_index: u64, trigger_action: u8, amount: u64, round_state: u8) {
    event::emit(PlayerAllIn { table_id, seat_index, trigger_action, amount, round_state });
}

// --- 洗牌协议 ---
public fun emit_shuffle_verified(table_id: ID, seat_index: u64, player: address) {
    event::emit(ShuffleVerified { table_id, seat_index, player });
}

public fun emit_shuffle_turn(table_id: ID, seat_index: u64, pending_count: u64, completed_count: u64) {
    event::emit(ShuffleTurnEvt { table_id, seat_index, pending_count, completed_count });
}

public fun emit_shuffle_complete(table_id: ID, phase: u8, participant_count: u64, deck_size: u64) {
    event::emit(ShuffleCompleteEvt { table_id, phase, participant_count, deck_size });
}

public fun emit_shuffle_timeout(table_id: ID, seat_index: u64, phase: u8, started_at: u64, timeout_ms: u64) {
    event::emit(ShuffleTimeout { table_id, seat_index, phase, started_at, timeout_ms });
}

// --- 揭示协议 ---
public fun emit_reveal_phase(table_id: ID, phase: u8) {
    event::emit(RevealPhaseEvt { table_id, phase });
}

public fun emit_reveal_token_submitted(table_id: ID, seat_index: u64, card_index: u64, phase: u8) {
    event::emit(RevealTokenSubmitted { table_id, seat_index, card_index, phase });
}

public fun emit_reveal_phase_complete(table_id: ID, phase: u8) {
    event::emit(RevealPhaseComplete { table_id, phase });
}

public fun emit_reveal_timeout(table_id: ID, phase: u8, pending_players: vector<u64>) {
    event::emit(RevealTimeout { table_id, phase, pending_players });
}

public fun emit_card_is_identity(table_id: ID, card_index: u64, assignment_index: u64, phase: u8) {
    event::emit(CardIsIdentity { table_id, card_index, assignment_index, phase });
}

public fun emit_identity_redeal(table_id: ID, identity_card_indices: vector<u64>, redeal_count: u64, phase: u8) {
    event::emit(IdentityRedeal { table_id, identity_card_indices, redeal_count, phase });
}

public fun emit_redeal_requested(table_id: ID, seat_index: u64, card_indices: vector<u64>) {
    event::emit(RedealRequested { table_id, seat_index, card_indices });
}

public fun emit_community_card_revealed(table_id: ID, phase: u8, card_indices: vector<u64>, card_ranks: vector<u8>, card_suits: vector<u8>) {
    event::emit(CommunityCardRevealed { table_id, phase, card_indices, card_ranks, card_suits });
}

// --- 重构协议 ---
public fun emit_reconstruct_initiated(table_id: ID, expected_players: vector<u64>, round_state: u8) {
    event::emit(ReconstructInitiated { table_id, expected_players, round_state });
}

public fun emit_reconstruct_deck_submitted(table_id: ID, seat_index: u64) {
    event::emit(ReconstructDeckSubmitted { table_id, seat_index });
}

public fun emit_reconstruct_complete(table_id: ID) {
    event::emit(ReconstructCompleteEvt { table_id });
}

public fun emit_reconstruct_timeout(table_id: ID, pending_players: vector<u64>) {
    event::emit(ReconstructTimeout { table_id, pending_players });
}

// --- 玩家管理 ---
public fun emit_player_kicked(table_id: ID, seat_index: u64, player: address, reason: u8) {
    event::emit(PlayerKicked { table_id, seat_index, player, reason });
}

public fun emit_player_refund(table_id: ID, seat_index: u64, player: address, amount: u64, refund_type: u8) {
    event::emit(PlayerRefund { table_id, seat_index, player, amount, refund_type });
}
