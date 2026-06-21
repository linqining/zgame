module texas_poker::table;

use sui::clock::Clock;
use sui::bls12381;
use sui::balance::{Self, Balance};
use sui::coin::{Self, Coin};
use sui::sui::SUI;
use std::string::String;
use texas_poker::card::{Self, Card};
use texas_poker::hand_evaluator::{Self, HandRank};
use texas_poker::betting::{Self, BettingRound};
use texas_poker::side_pot::{Self, SidePot};
use texas_poker::bls_elgamal::{Self, ElGamalCiphertext};
use texas_poker::bls_scalar;
use texas_poker::zk_verifier;
use texas_poker::bls_scalar::hash_to_scalar;
use texas_poker::table_events;
use texas_poker::table_constants;
use texas_poker::table_serialization;

// ========== SUI <-> Stack 兑换比例 ==========
// 1 SUI = 100000 stack chips (即 0.1 SUI = 10000 stack, 0.01 SUI = 1000 stack)
const STACK_TO_SUI_RATIO: u64 = 100000;

// ========== 错误码 ==========
#[error]
const ETableFull: vector<u8> = b"Table is full";
#[error]
const ENotPlayerTurn: vector<u8> = b"Not this player's turn";
#[error]
const EInvalidRoundState: vector<u8> = b"Invalid round state for this action";
#[error]
const EInvalidShufflePhase: vector<u8> = b"Invalid shuffle phase state for this action";
#[error]
const EInvalidReconstructPhase: vector<u8> = b"Invalid reconstruct phase state for this action";

#[error]
const EPlayerAlreadySeated: vector<u8> = b"Player already seated";
#[error]
const ENotEnoughPlayers: vector<u8> = b"Not enough players to start";
#[error]
const EInvalidSeatIndex: vector<u8> = b"Invalid seat index";
#[error]
const ESeatOccupied: vector<u8> = b"Seat is occupied";
#[error]
const EInvalidBetAmount: vector<u8> = b"Invalid bet amount";
#[error]
const EPlayerNotSeated: vector<u8> = b"Player is not seated";
#[error]
const EAlreadyFolded: vector<u8> = b"Player has already folded";
#[error]
const EAlreadyAllIn: vector<u8> = b"Player is already all-in";
#[error]
const ESeatEmpty: vector<u8> = b"Seat is empty";
#[error]
const ENotOwner: vector<u8> = b"Not the owner of this seat";
#[error]
const ECannotCheck: vector<u8> = b"Cannot check when there is a bet to call";
#[error]
const ENotCurrentShuffler: vector<u8> = b"Not the current shuffler";
#[error]
const EShuffleAlreadyCompleted: vector<u8> = b"Player already completed shuffle";
#[error]
const EInvalidRevealPhaseState: vector<u8> = b"Invalid reveal phase state for this action";
#[error]
const ENotPendingRevealer: vector<u8> = b"Player is not pending to reveal this card";
#[error]
const ECardAlreadyDecrypted: vector<u8> = b"Card already decrypted";
#[error]
const EInvalidCardIndex: vector<u8> = b"Invalid card index";
#[error]
const EReconstructNotVoting: vector<u8> = b"Reconstruct is not in voting phase";
#[error]
const EAlreadyVoted: vector<u8> = b"Player already voted";
#[error]
const EReconstructNotCollecting: vector<u8> = b"Reconstruct is not in collecting phase";
#[error]
const EReconstructAlreadySubmitted: vector<u8> = b"Player already submitted reconstruct deck";
#[error]
const EInvalidReconstructDeckSize: vector<u8> = b"Invalid reconstruct deck size";
#[error]
const EPkAlreadyRegistered: vector<u8> = b"Player PK already registered";
#[error]
const ENotTimedOut: vector<u8> = b"Player has not timed out yet";
#[error]
const ETablePlaying: vector<u8> = b"Table is playing";
#[error]
const ENotShuffling: vector<u8> = b"Player has not completed shuffle";
#[error]
const ENotLeaveable: vector<u8> = b"Not in leaveable state";
#[error]
const ENotJoinable: vector<u8> = b"Not in join state";
#[error]
const ELeaveProofMissing: vector<u8> = b"Leave proof is missing";
#[error]
const EPotNotFullyDistributed: vector<u8> = b"Pot was not fully distributed";



// ========== 座位 ==========
public struct Seat has store, drop {
    player: address,
    stack: u64,
    hand: vector<Card>,
    bet: u64,
    total_bet: u64,
    folded: bool,
    all_in: bool,
    acted_this_round: bool,
    is_waiting: bool,                   // 本局不参与，等下一局开始
    left_during_hand: bool,             // 本局中途离开（被踢），total_bet 保留供 side pot 计算
    pk: vector<u8>,                     // 玩家 ElGamal 公钥 (G1 compressed bytes)
    refunded: bool,                     // total_bet 是否已退款，避免重复退款
}

/// 判断座位是否被活跃占用：player != @0x0 且未中途离开
/// 被踢玩家 (left_during_hand=true) 保留 player 用于退款，但不视为活跃占用
fun is_seat_occupied(seat: &Seat): bool {
    seat.player != @0x0 && !seat.left_during_hand
}

// ========== 洗牌状态 ==========
public struct ShuffleState has store, drop {
    phase: u8,                          // None / Shuffling
    current_shuffler: Option<u64>,      // 当前洗牌者 seat_index
    pending_players: vector<u64>,       // 等待洗牌的玩家列表
    completed_players: vector<u64>,     // 已完成洗牌的玩家列表
}

// ========== Reveal 分配 ==========
public struct RevealAssignment has store, drop {
    encrypted_card_index: u64,          // 牌组中的索引
    pending_players: vector<u64>,       // 待提交 reveal token 的玩家 seat_index
    reveal_tokens: vector<RevealTokenData>, // 已收集的 reveal tokens
    decrypted: bool,                    // 是否已解密
}

// ========== Reveal Token 数据 ==========
public struct RevealTokenData has store, drop {
    seat_index: u64,
    token: vector<u8>,                  // c1 * sk (G1 compressed bytes)
}

// ========== Reveal Token 状态 ==========
public struct RevealTokenState has store, drop {
    reveal_phase: u8,                   // HandReveal / CommunityReveal / ShowdownReveal / RedealReveal
    assignments: vector<RevealAssignment>,
}

// ========== Reconstruct 状态 ==========
/// 存储单个玩家提交的 reconstruct 输出
public struct ReconstructPlayerDeck has store, drop {
    seat_index: u64,
    output_cts: vector<ElGamalCiphertext>,  // 该玩家重建后的牌组
}

public struct ReconstructState has store, drop {
    phase: u8,                          // None / Voting / Collecting / Complete
    pending_players: vector<u64>,       // 待提交 reconstruct deck 的玩家
    coefficient: vector<u8>, // 随机系数 (scalar bytes)

    player_decks: vector<ReconstructPlayerDeck>, // 所有玩家提交的重建牌组
}

// ========== 超时配置 ==========
public struct TimeoutConfig has store, drop {
    shuffle_timeout_ms: u64,            // 洗牌超时 (默认 10000)
    reveal_timeout_ms: u64,             // 揭牌超时 (默认 10000)
    betting_timeout_ms: u64,            // 下注超时 (默认 30000)
    reconstruct_timeout_ms: u64,        // 重构投票超时 (默认 10000)
    showdown_display_ms: u64,           // 摊牌展示时间 (默认 3000)
    hand_complete_wait_ms: u64,         // 一手结束后等待时间 (默认 5000)
    ready_wait_ms: u64,                 // 开始倒计时 (默认 5000)
}

// ========== 时间戳 ==========
public struct Timestamps has store, drop {
    ready_at: u64,                      // 准备好开始的时间戳 (0=未设置)
    shuffle_started_at: u64,            // 当前洗牌者开始时间
    reveal_started_at: u64,             // 当前 reveal 阶段开始时间
    betting_started_at: u64,            // 当前下注者开始时间
    reconstruct_started_at: u64,        // reconstruct 投票开始时间
    showdown_at: u64,                   // 摊牌展示结束时间
    hand_complete_at: u64,              // 一手结束时间
    current_turn_changed_at: u64,       // current_turn 最后变化时间 (0=待 tick 填充)
}

// ========== 牌组状态 ==========
// ========== 已解密牌 ==========
/// 存储链上解密结果
/// 手牌(preflop): 其他玩家提交 reveal token 后得到部分解密密文(ciphertext_bytes)，牌主尚未提交
/// 公共牌: 所有玩家提交后得到明文(plaintext_bytes)
/// 手牌(showdown): 牌主提交后从部分解密密文得到明文(plaintext_bytes)
public struct DecryptedCard has store, drop {
    encrypted_card_index: u64,          // 原始加密牌组中的索引
    owner_seat_index: u64,              // 牌主 seat_index (公共牌为 MAX_U64)
    ciphertext_bytes: vector<u8>,       // 部分解密密文 (96 bytes: c1+c2)，空=已完全解密
    plaintext_bytes: vector<u8>,        // 完全解密明文 (48 bytes G1 compressed)，空=仅部分解密
}

// ========== 牌组状态 ==========
public struct DeckState has store, drop {
    encrypted: vector<ElGamalCiphertext>,
    aggregated_pk: vector<u8>,          // 聚合公钥 (G1 compressed bytes)
    plaintext: vector<vector<u8>>,      // 52 张明文牌 (G1 compressed bytes)，由合约生成
    cards_dealt: u64,                   // 已从牌组发出的牌数量
    decrypted_cards: vector<DecryptedCard>, // 已解密的合法牌
}

// ========== 扑克牌 ==========
/// 扑克牌，对应 Rust 端 PlayingCard
public struct PlayingCard has copy, drop, store {
    rank: u8,   // 2-14 (2=Two, ..., 14=Ace)
    suit: u8,   // 0=Club, 1=Diamond, 2=Heart, 3=Spade
}

/// 根据 index (0-51) 获取标准扑克牌
/// 对应 Rust 端 PlayingCard::from_id(index)
public fun playing_card_from_index(index: u64): PlayingCard {
    assert!(index < table_constants::n_cards(), EInvalidCardIndex);
    let rank_idx = index % 13;
    let suit_idx = index / 13;
    PlayingCard { rank: (rank_idx + 2) as u8, suit: suit_idx as u8 }
}

/// 根据明文 G1 点查找对应的 PlayingCard
/// 在 deck_plaintext 中查找匹配的 index，再映射到 PlayingCard
public fun plaintext_to_playing_card(plaintext: &vector<vector<u8>>, point_bytes: &vector<u8>): PlayingCard {
    let mut i = 0;
    while (i < plaintext.length()) {
        if (plaintext[i] == *point_bytes) {
            return playing_card_from_index(i)
        };
        i = i + 1;
    };
    abort EInvalidCardIndex
}

/// 获取牌的 rank (2-14)
public fun card_rank(card: &PlayingCard): u8 { card.rank }

/// 获取牌的 suit (0-3)
public fun card_suit(card: &PlayingCard): u8 { card.suit }

// M-D10 修复：PlayingCard 花色编码（0=Club,1=Diamond,2=Heart,3=Spade）
// 与 card.move 花色编码（SPADES=0,HEARTS=1,DIAMONDS=2,CLUBS=3）不一致，
// 转换时需要做映射
fun playing_card_suit_to_card_suit(s: u8): u8 {
    if (s == 0) { card::clubs() }         // PlayingCard 0=Club → Card CLUBS=3
    else if (s == 1) { card::diamonds() } // 1=Diamond → 2
    else if (s == 2) { card::hearts() }   // 2=Heart → 1
    else { card::spades() }               // 3=Spade → 0
}

// ========== 管理员能力对象 ==========
public struct AdminCap has key, store {
    id: UID,
}

// ========== 牌桌（共享对象） ==========
public struct Table has key {
    id: UID,
    name: String,
    max_players: u64,
    small_blind: u64,
    big_blind: u64,

    seats: vector<Seat>,
    button: u64,

    pot: u64,
    side_pots: vector<SidePot>,
    community_cards: vector<Card>,

    round_state: u8,
    betting_round: Option<BettingRound>,
    current_turn: Option<u64>,

    // 加密牌组
    deck_state: DeckState,

    // 协议状态
    shuffle_state: ShuffleState,
    reveal_token_state: RevealTokenState,
    reconstruct_state: ReconstructState,

    // 超时配置
    timeout_config: TimeoutConfig,

    // 时间戳
    timestamps: Timestamps,

    // 玩家存入的 SUI 资金池（用于 buy_in 兑换 stack，离开时兑换回 SUI）
    sui_balance: Balance<SUI>,
}

// ========== Table 快照（供客户端查询） ==========
// 注意：Sui Move 限制每个结构体最多 32 个字段，因此拆分为两个子结构体
public struct TableSummaryMeta has drop {
    // 元数据
    table_id: ID,
    name: String,
    max_players: u64,
    small_blind: u64,
    big_blind: u64,
    // 活跃座位信息
    active_count: u64,
    button: u64,
    // 底池
    pot: u64,
    side_pots_count: u64,
    community_cards_count: u64,
    // 阶段
    round_state: u8,
    // 下注轮信息（展开 BettingRound）
    betting_round_exists: bool,
    betting_round_current_bet: u64,
    betting_round_min_raise: u64,
    betting_round_big_blind: u64,
    betting_round_last_raiser_seat: Option<u64>,
    betting_round_actions_taken: u64,
    // 当前行动玩家
    current_turn: Option<u64>,
    // 座位快照（每个座位的公开信息）
    seats_occupied: vector<bool>,
    seat_players: vector<address>,
    seat_stacks: vector<u64>,
    seat_bets: vector<u64>,
    seat_total_bets: vector<u64>,
    seat_folded: vector<bool>,
    seat_all_in: vector<bool>,
    seat_is_waiting: vector<bool>,
}

public struct TableSummaryCryptoState has drop {
    // 加密牌组（每个元素为 96 bytes: c1 || c2，通过 ciphertext_to_bytes 序列化）
    deck_encrypted: vector<vector<u8>>,
    // 聚合公钥 (G1 compressed bytes, 48 bytes)
    aggregated_pk: vector<u8>,
    // 每个座位的玩家公钥（空座位为空 vector）
    seat_pks: vector<vector<u8>>,
    // 待洗牌玩家 seat_index 列表
    shuffle_pending_players: vector<u64>,
    // 已完成洗牌玩家 seat_index 列表
    shuffle_completed_players: vector<u64>,
    // reconstruct 随机系数 (scalar bytes, 32 bytes)
    reconstruct_coefficient: vector<u8>,
    // 待提交 reconstruct deck 的玩家 seat_index 列表
    reconstruct_pending_players: vector<u64>,
    // 已提交 reconstruct deck 的玩家 seat_index 列表（从 player_decks 派生）
    reconstruct_completed_players: vector<u64>,
}

public struct TableSummaryState has drop {
    // 洗牌状态
    shuffle_current_shuffler: Option<u64>,
    shuffle_pending_count: u64,
    shuffle_completed_count: u64,
    // Reveal 阶段
    reveal_phase: u8,
    reveal_assignment_count: u64,
    // Reconstruct 阶段
    reconstruct_phase: u8,
    // 牌组大小
    deck_size: u64,
    // 已发牌数量
    cards_dealt: u64,
    // 明文牌组（52 张 G1 compressed bytes）
    deck_plaintext: vector<vector<u8>>,
    // 超时配置
    shuffle_timeout_ms: u64,
    reveal_timeout_ms: u64,
    betting_timeout_ms: u64,
    reconstruct_timeout_ms: u64,
    showdown_display_ms: u64,
    hand_complete_wait_ms: u64,
    ready_wait_ms: u64,
    // 时间戳
    ready_at: u64,
    shuffle_started_at: u64,
    reveal_started_at: u64,
    betting_started_at: u64,
    reconstruct_started_at: u64,
    showdown_at: u64,
    hand_complete_at: u64,
    current_turn_changed_at: u64,
    // 一致性保证
    epoch: u64,
}

public struct TableSummary has drop {
    meta: TableSummaryMeta,
    state: TableSummaryState,
}

/// 扩展版 TableSummary，包含加密状态（V2，升级后新增）
public struct TableSummaryV2 has drop {
    meta: TableSummaryMeta,
    state: TableSummaryState,
    crypto: TableSummaryCryptoState,
}

// ========== 获取 Table 快照 ==========
public fun get_table_summary(table: &Table, ctx: &TxContext): TableSummary {
    let len = table.seats.length();
    let mut seats_occupied = vector[];
    let mut seat_players = vector[];
    let mut seat_stacks = vector[];
    let mut seat_bets = vector[];
    let mut seat_total_bets = vector[];
    let mut seat_folded = vector[];
    let mut seat_all_in = vector[];
    let mut seat_is_waiting = vector[];

    let mut i = 0;
    while (i < len) {
        let seat = &table.seats[i];
        seats_occupied.push_back(is_seat_occupied(seat));
        seat_players.push_back(seat.player);
        seat_stacks.push_back(seat.stack);
        seat_bets.push_back(seat.bet);
        seat_total_bets.push_back(seat.total_bet);
        seat_folded.push_back(seat.folded);
        seat_all_in.push_back(seat.all_in);
        seat_is_waiting.push_back(seat.is_waiting);
        i = i + 1;
    };


    let meta = TableSummaryMeta {
        table_id: object::id(table),
        name: table.name,
        max_players: table.max_players,
        small_blind: table.small_blind,
        big_blind: table.big_blind,
        active_count: count_active_occupied(&table.seats),
        button: table.button,
        pot: table.pot,
        side_pots_count: table.side_pots.length(),
        community_cards_count: table.community_cards.length(),
        round_state: table.round_state,
        betting_round_exists: table.betting_round.is_some(),
        betting_round_current_bet: if (table.betting_round.is_some()) { table.betting_round.borrow().current_bet() } else { 0 },
        betting_round_min_raise: if (table.betting_round.is_some()) { table.betting_round.borrow().min_raise() } else { 0 },
        betting_round_big_blind: if (table.betting_round.is_some()) { table.betting_round.borrow().big_blind() } else { 0 },
        betting_round_last_raiser_seat: if (table.betting_round.is_some()) { table.betting_round.borrow().last_raiser_seat() } else { option::none() },
        betting_round_actions_taken: if (table.betting_round.is_some()) { table.betting_round.borrow().actions_taken() } else { 0 },
        current_turn: table.current_turn,
        seats_occupied,
        seat_players,
        seat_stacks,
        seat_bets,
        seat_total_bets,
        seat_folded,
        seat_all_in,
        seat_is_waiting,
    };
    let state = TableSummaryState {
        shuffle_current_shuffler: table.shuffle_state.current_shuffler,
        shuffle_pending_count: table.shuffle_state.pending_players.length(),
        shuffle_completed_count: table.shuffle_state.completed_players.length(),
        reveal_phase: table.reveal_token_state.reveal_phase,
        reveal_assignment_count: table.reveal_token_state.assignments.length(),
        reconstruct_phase: table.reconstruct_state.phase,
        deck_size: table.deck_state.encrypted.length(),
        cards_dealt: table.deck_state.cards_dealt,
        deck_plaintext: table.deck_state.plaintext,
        shuffle_timeout_ms: table.timeout_config.shuffle_timeout_ms,
        reveal_timeout_ms: table.timeout_config.reveal_timeout_ms,
        betting_timeout_ms: table.timeout_config.betting_timeout_ms,
        reconstruct_timeout_ms: table.timeout_config.reconstruct_timeout_ms,
        showdown_display_ms: table.timeout_config.showdown_display_ms,
        hand_complete_wait_ms: table.timeout_config.hand_complete_wait_ms,
        ready_wait_ms: table.timeout_config.ready_wait_ms,
        ready_at: table.timestamps.ready_at,
        shuffle_started_at: table.timestamps.shuffle_started_at,
        reveal_started_at: table.timestamps.reveal_started_at,
        betting_started_at: table.timestamps.betting_started_at,
        reconstruct_started_at: table.timestamps.reconstruct_started_at,
        showdown_at: table.timestamps.showdown_at,
        hand_complete_at: table.timestamps.hand_complete_at,
        current_turn_changed_at: table.timestamps.current_turn_changed_at,
        epoch: ctx.epoch(),
    };
    TableSummary { meta, state }
}

/// 获取扩展版 Table 快照（包含加密状态）
public fun get_table_summary_v2(table: &Table, ctx: &TxContext): TableSummaryV2 {
    let summary = get_table_summary(table, ctx);
    let TableSummary { meta, state } = summary;
    let crypto = build_crypto_state(table);
    TableSummaryV2 { meta, state, crypto }
}

/// 构建 TableSummaryCryptoState：收集加密牌组、聚合公钥、座位公钥、玩家列表、reconstruct 系数
fun build_crypto_state(table: &Table): TableSummaryCryptoState {
    // deck_encrypted: 每个密文序列化为 96 bytes (c1 || c2)
    let mut deck_encrypted_bytes = vector[];
    let mut d = 0;
    let deck_len = table.deck_state.encrypted.length();
    while (d < deck_len) {
        deck_encrypted_bytes.push_back(bls_elgamal::ciphertext_to_bytes(&table.deck_state.encrypted[d]));
        d = d + 1;
    };

    // seat_pks: 每个座位的公钥（空座位为空 vector）
    let mut seat_pks = vector[];
    let mut s = 0;
    let seats_len = table.seats.length();
    while (s < seats_len) {
        seat_pks.push_back(table.seats[s].pk);
        s = s + 1;
    };

    // reconstruct_completed_players: 从 player_decks 派生 seat_index 列表
    let mut reconstruct_completed = vector[];
    let mut p = 0;
    let player_decks_len = table.reconstruct_state.player_decks.length();
    while (p < player_decks_len) {
        reconstruct_completed.push_back(table.reconstruct_state.player_decks[p].seat_index);
        p = p + 1;
    };

    TableSummaryCryptoState {
        deck_encrypted: deck_encrypted_bytes,
        aggregated_pk: table.deck_state.aggregated_pk,
        seat_pks,
        shuffle_pending_players: table.shuffle_state.pending_players,
        shuffle_completed_players: table.shuffle_state.completed_players,
        reconstruct_coefficient: table.reconstruct_state.coefficient,
        reconstruct_pending_players: table.reconstruct_state.pending_players,
        reconstruct_completed_players: reconstruct_completed,
    }
}

// ========== TableSummary 访问器（供后端查询） ==========
public fun summary_table_id(s: &TableSummary): ID { s.meta.table_id }
public fun summary_name(s: &TableSummary): &String { &s.meta.name }
public fun summary_max_players(s: &TableSummary): u64 { s.meta.max_players }
public fun summary_small_blind(s: &TableSummary): u64 { s.meta.small_blind }
public fun summary_big_blind(s: &TableSummary): u64 { s.meta.big_blind }
public fun summary_active_count(s: &TableSummary): u64 { s.meta.active_count }
public fun summary_button(s: &TableSummary): u64 { s.meta.button }
public fun summary_pot(s: &TableSummary): u64 { s.meta.pot }
public fun summary_side_pots_count(s: &TableSummary): u64 { s.meta.side_pots_count }
public fun summary_community_cards_count(s: &TableSummary): u64 { s.meta.community_cards_count }
public fun summary_round_state(s: &TableSummary): u8 { s.meta.round_state }
public fun summary_betting_round_exists(s: &TableSummary): bool { s.meta.betting_round_exists }
public fun summary_betting_round_current_bet(s: &TableSummary): u64 { s.meta.betting_round_current_bet }
public fun summary_betting_round_min_raise(s: &TableSummary): u64 { s.meta.betting_round_min_raise }
public fun summary_betting_round_big_blind(s: &TableSummary): u64 { s.meta.betting_round_big_blind }
public fun summary_betting_round_last_raiser_seat(s: &TableSummary): Option<u64> { s.meta.betting_round_last_raiser_seat }
public fun summary_betting_round_actions_taken(s: &TableSummary): u64 { s.meta.betting_round_actions_taken }
public fun summary_current_turn(s: &TableSummary): Option<u64> { s.meta.current_turn }
public fun summary_seats_occupied(s: &TableSummary): &vector<bool> { &s.meta.seats_occupied }
public fun summary_seat_players(s: &TableSummary): &vector<address> { &s.meta.seat_players }
public fun summary_seat_stacks(s: &TableSummary): &vector<u64> { &s.meta.seat_stacks }
public fun summary_seat_bets(s: &TableSummary): &vector<u64> { &s.meta.seat_bets }
public fun summary_seat_total_bets(s: &TableSummary): &vector<u64> { &s.meta.seat_total_bets }
public fun summary_seat_folded(s: &TableSummary): &vector<bool> { &s.meta.seat_folded }
public fun summary_seat_all_in(s: &TableSummary): &vector<bool> { &s.meta.seat_all_in }
public fun summary_seat_is_waiting(s: &TableSummary): &vector<bool> { &s.meta.seat_is_waiting }
public fun summary_shuffle_current_shuffler(s: &TableSummary): Option<u64> { s.state.shuffle_current_shuffler }
public fun summary_shuffle_pending_count(s: &TableSummary): u64 { s.state.shuffle_pending_count }
public fun summary_shuffle_completed_count(s: &TableSummary): u64 { s.state.shuffle_completed_count }
public fun summary_reveal_phase(s: &TableSummary): u8 { s.state.reveal_phase }
public fun summary_reveal_assignment_count(s: &TableSummary): u64 { s.state.reveal_assignment_count }
public fun summary_reconstruct_phase(s: &TableSummary): u8 { s.state.reconstruct_phase }
public fun summary_deck_size(s: &TableSummary): u64 { s.state.deck_size }
public fun summary_cards_dealt(s: &TableSummary): u64 { s.state.cards_dealt }
public fun summary_deck_plaintext(s: &TableSummary): &vector<vector<u8>> { &s.state.deck_plaintext }
public fun summary_shuffle_timeout_ms(s: &TableSummary): u64 { s.state.shuffle_timeout_ms }
public fun summary_reveal_timeout_ms(s: &TableSummary): u64 { s.state.reveal_timeout_ms }
public fun summary_betting_timeout_ms(s: &TableSummary): u64 { s.state.betting_timeout_ms }
public fun summary_reconstruct_timeout_ms(s: &TableSummary): u64 { s.state.reconstruct_timeout_ms }
public fun summary_showdown_display_ms(s: &TableSummary): u64 { s.state.showdown_display_ms }
public fun summary_hand_complete_wait_ms(s: &TableSummary): u64 { s.state.hand_complete_wait_ms }
public fun summary_ready_wait_ms(s: &TableSummary): u64 { s.state.ready_wait_ms }
public fun summary_ready_at(s: &TableSummary): u64 { s.state.ready_at }
public fun summary_shuffle_started_at(s: &TableSummary): u64 { s.state.shuffle_started_at }
public fun summary_reveal_started_at(s: &TableSummary): u64 { s.state.reveal_started_at }
public fun summary_betting_started_at(s: &TableSummary): u64 { s.state.betting_started_at }
public fun summary_reconstruct_started_at(s: &TableSummary): u64 { s.state.reconstruct_started_at }
public fun summary_showdown_at(s: &TableSummary): u64 { s.state.showdown_at }
public fun summary_hand_complete_at(s: &TableSummary): u64 { s.state.hand_complete_at }
public fun summary_current_turn_changed_at(s: &TableSummary): u64 { s.state.current_turn_changed_at }
public fun summary_epoch(s: &TableSummary): u64 { s.state.epoch }
public fun summary_crypto(s: &TableSummaryV2): &TableSummaryCryptoState { &s.crypto }
public fun summary_crypto_deck_encrypted(s: &TableSummaryV2): &vector<vector<u8>> { &s.crypto.deck_encrypted }
public fun summary_crypto_aggregated_pk(s: &TableSummaryV2): &vector<u8> { &s.crypto.aggregated_pk }
public fun summary_crypto_seat_pks(s: &TableSummaryV2): &vector<vector<u8>> { &s.crypto.seat_pks }
public fun summary_crypto_shuffle_pending_players(s: &TableSummaryV2): &vector<u64> { &s.crypto.shuffle_pending_players }
public fun summary_crypto_shuffle_completed_players(s: &TableSummaryV2): &vector<u64> { &s.crypto.shuffle_completed_players }
public fun summary_crypto_reconstruct_coefficient(s: &TableSummaryV2): &vector<u8> { &s.crypto.reconstruct_coefficient }
public fun summary_crypto_reconstruct_pending_players(s: &TableSummaryV2): &vector<u64> { &s.crypto.reconstruct_pending_players }
public fun summary_crypto_reconstruct_completed_players(s: &TableSummaryV2): &vector<u64> { &s.crypto.reconstruct_completed_players }

// ========== 创建空座位 ==========
fun empty_seat(): Seat {
    Seat {
        player: @0x0,
        stack: 0,
        hand: vector[],
        bet: 0,
        total_bet: 0,
        folded: false,
        all_in: false,
        acted_this_round: false,
        is_waiting: false,
        left_during_hand: false,
        pk: vector[],
        refunded: false,
    }
}

fun init_seat(seat: &mut Seat, player: address, stack: u64, pk: vector<u8>, is_waiting: bool) {
    seat.player = player;
    seat.stack = stack;
    seat.hand = vector[];
    seat.bet = 0;
    seat.total_bet = 0;
    seat.folded = false;
    seat.all_in = false;
    seat.acted_this_round = false;
    seat.is_waiting = is_waiting;
    seat.left_during_hand = false;
    seat.pk = pk;
    seat.refunded = false;
}

fun reset_seat(seat: &mut Seat) {
    seat.player = @0x0;
    seat.stack = 0;
    seat.hand = vector[];
    seat.bet = 0;
    seat.total_bet = 0;
    seat.folded = false;
    seat.all_in = false;
    seat.acted_this_round = false;
    seat.is_waiting = false;
    seat.left_during_hand = false;
    seat.pk = vector[];
    seat.refunded = false;
}

/// 将玩家的 stack chips 兑换回 SUI 并转账给玩家
/// 兑换比例：1 SUI = 100000 stack (STACK_TO_SUI_RATIO)
/// 不足 1 MIST 的零头（refund_amount * STACK_TO_SUI_RATIO == 0）不退还
fun refund_sui_to_player(
    table: &mut Table,
    player: address,
    refund_amount: u64,
    ctx: &mut TxContext,
) {
    let sui_amount = refund_amount * STACK_TO_SUI_RATIO;
    if (sui_amount > 0) {
        let sui_balance = table.sui_balance.split(sui_amount);
        let coin = coin::from_balance(sui_balance, ctx);
        transfer::public_transfer(coin, player);
    };
}

// ========== 创建空协议状态 ==========
fun empty_shuffle_state(): ShuffleState {
    ShuffleState {
        phase: table_constants::shuffle_phase_none(),
        current_shuffler: option::none(),
        pending_players: vector[],
        completed_players: vector[],
    }
}

fun empty_reveal_token_state(): RevealTokenState {
    RevealTokenState {
        reveal_phase: table_constants::reveal_phase_none(),
        assignments: vector[],
    }
}

fun empty_reconstruct_state(): ReconstructState {
    ReconstructState {
        phase: table_constants::reconstruct_phase_none(),
        pending_players: vector[],
        coefficient: bls_scalar::scalar_to_bytes(&bls_scalar::scalar_one()),
        player_decks: vector[],
    }
}

// ========== 初始化（发布时自动执行） ==========
fun init(ctx: &mut TxContext) {
    // 创建 AdminCap 并转移给发布者
    let admin_cap = AdminCap { id: object::new(ctx) };
    transfer::transfer(admin_cap, ctx.sender());
}

// ========== 创建牌桌 ==========
public  fun create_table(
    name: String,
    small_blind: u64,
    big_blind: u64,
    max_players: u64,
    _admin_cap: &AdminCap,
    ctx: &mut TxContext,
) {
    assert!(max_players <= table_constants::max_players(), ETableFull);
    assert!(big_blind >= small_blind * 2, EInvalidBetAmount);

    let mut seats = vector[];
    let mut i = 0;
    while (i < max_players) {
        seats.push_back(empty_seat());
        i = i + 1;
    };

    let id = object::new(ctx);
    let mut table = Table {
        id,
        name,
        max_players,
        small_blind,
        big_blind,
        seats,
        button: 0,
        pot: 0,
        side_pots: vector[],
        community_cards: vector[],
        round_state: table_constants::round_waiting(),
        betting_round: option::none(),
        current_turn: option::none(),
        deck_state: DeckState {
            encrypted: vector[],
            aggregated_pk: vector[],
            plaintext: table_serialization::generate_plaintext_bytes(),
            cards_dealt: 0,
            decrypted_cards: vector[],
        },
        shuffle_state: empty_shuffle_state(),
        reveal_token_state: empty_reveal_token_state(),
        reconstruct_state: empty_reconstruct_state(),
        timeout_config: TimeoutConfig {
            shuffle_timeout_ms: 30000,
            reveal_timeout_ms: 30000,
            betting_timeout_ms: 30000,
            reconstruct_timeout_ms: 10000,
            showdown_display_ms: 3000,
            hand_complete_wait_ms: 5000,
            ready_wait_ms: 5000,
        },
        timestamps: Timestamps {
            ready_at: 0,
            shuffle_started_at: 0,
            reveal_started_at: 0,
            betting_started_at: 0,
            reconstruct_started_at: 0,
            showdown_at: 0,
            hand_complete_at: 0,
            current_turn_changed_at: 0,
        },
        sui_balance: balance::zero(),
    };
    set_initial_encrypted_deck(&mut table);
    let table_id = object::id(&table);
    transfer::share_object(table);
    table_events::emit_table_created(table_id, name)
}

// ========== 玩家加入（带密码学验证） ==========
public  fun join_and_shuffle(
    table: &mut Table,
    seat_index: u64,
    buy_in_coin: Coin<SUI>,             // 玩家存入的 SUI 代币，按 1:10000 兑换成 stack
    pk: vector<u8>,                     // 玩家 ElGamal 公钥 (G1 compressed bytes)
    pk_ownership_proof: vector<u8>,    // PK ownership Schnorr proof (serialized, 80 bytes: 48 commitment + 32 response)
    mask_cards: vector<u8>,             // remask 后的中间牌组 (serialized ciphertexts, flat bytes)
    output_cards: vector<u8>,           // shuffle 后的最终牌组 (serialized ciphertexts, flat bytes)
    remask_proof_bytes: vector<u8>,     // RemaskProof (serialized)
    shuffle_proof_bytes: vector<u8>,    // ShuffleProof (serialized)
    ctx: &mut TxContext,
) {
    assert!(seat_index < table.max_players, EInvalidSeatIndex);
    // 将 SUI 代币兑换成 stack chips (1 SUI = 100000 stack)
    let sui_amount = buy_in_coin.value();
    assert!(sui_amount >= 100000000, EInvalidBetAmount); //至少0.1 SUI
    let buy_in = sui_amount / STACK_TO_SUI_RATIO;
    // 将 SUI 存入牌桌资金池
    table.sui_balance.join(buy_in_coin.into_balance());

    assert!(!is_seat_occupied(&table.seats[seat_index]), ESeatOccupied);
    assert!(table.can_join_state(), ENotJoinable);

    let sender = ctx.sender();
    assert!(!is_player_seated(&table.seats, sender), EPlayerAlreadySeated);

    // 验证 PK 未被注册
    assert!(!is_pk_registered(&table.seats, &pk), EPkAlreadyRegistered);

    // 验证 PK 所有权证明（证明玩家拥有 pk 对应的私钥 sk）
    let pk_point = zk_verifier::deserialize_pk(&pk);
    zk_verifier::verify_pk_ownership_or_abort(&pk_point, &pk_ownership_proof);

    // 洗牌/等待阶段：验证 remask + shuffle 并参与本局
    // 反序列化牌组
    let output_cts = zk_verifier::deserialize_ciphertexts(&output_cards);
    // 如果已有加密牌组，验证 remask + shuffle
    if (table.deck_state.encrypted.length() > 0) {
        // 后续玩家：验证 remask + shuffle
        let remask_proof = table_serialization::deserialize_remask_proof(&remask_proof_bytes);
        let shuffle_proof = table_serialization::deserialize_shuffle_proof(&shuffle_proof_bytes);

        // 计算新的聚合公钥
        let new_aggregated_pk = table_serialization::add_pk_to_aggregated(&table.deck_state.aggregated_pk, &pk);

        // 反序列化中间牌组（remask 后、shuffle 前）
        let mask_cts = zk_verifier::deserialize_ciphertexts(&mask_cards);

        // 使用共享 Transcript 验证 remask + shuffle
        let mut transcript = zk_verifier::new_mask_shuffle_transcript();
        // 验证 remask: encrypted → mask_cards (c1 不变)
        zk_verifier::verify_remask_with_transcript_or_abort(&table.deck_state.encrypted, &mask_cts, &pk_point, &remask_proof, &mut transcript);

        // 验证 shuffle: mask_cards → output_cts (c1 变化)
        let new_pk_point = zk_verifier::deserialize_pk(&new_aggregated_pk);
        zk_verifier::verify_shuffle_with_transcript_or_abort(&mask_cts, &output_cts, &new_pk_point, &shuffle_proof, &mut transcript);

        // 更新聚合公钥
        table.deck_state.aggregated_pk = new_aggregated_pk;
    } else {
        // 首玩家或 reset_for_next_hand 后的首位洗牌者：将 pk 加入聚合公钥
        // fresh table 时 aggregated_pk 为空，add 后等于 pk；
        // reset 后 aggregated_pk 含其他活跃玩家 pk，add 后正确累加
        table.deck_state.aggregated_pk = table_serialization::add_pk_to_aggregated(&table.deck_state.aggregated_pk, &pk);
    };

    // 初始化座位（参与本局）
    init_seat(&mut table.seats[seat_index], sender, buy_in, pk, false);

    // 更新牌组
    table.deck_state.encrypted = output_cts;

    // 标记为已完成洗牌
    table.shuffle_state.completed_players.push_back(seat_index);
    remove_from_pending(&mut table.shuffle_state.pending_players, seat_index);

    table_events::emit_player_joined(object::id(table), seat_index, sender, buy_in, false, count_active_occupied(&table.seats))
}

// ========== 玩家加入（带密码学验证） ==========
public  fun join_and_shuffle_verified(
    table: &mut Table,
    seat_index: u64,
    buy_in_coin: Coin<SUI>,             // 玩家存入的 SUI 代币，按 1:10000 兑换成 stack
    pk: vector<u8>,                     // 玩家 ElGamal 公钥 (G1 compressed bytes)
    pk_ownership_proof: vector<u8>,    // PK ownership Schnorr proof (serialized, 80 bytes: 48 commitment + 32 response)
    _mask_cards: vector<u8>,             // remask 后的中间牌组 (serialized ciphertexts, flat bytes)
    output_cards: vector<u8>,           // shuffle 后的最终牌组 (serialized ciphertexts, flat bytes)
    _remask_proof_bytes: vector<u8>,     // RemaskProof (serialized)
    _shuffle_proof_bytes: vector<u8>,    // ShuffleProof (serialized)
    ctx: &mut TxContext,
) {
    assert!(seat_index < table.max_players, EInvalidSeatIndex);
    // 将 SUI 代币兑换成 stack chips (1 SUI = 100000 stack)
    let sui_amount = buy_in_coin.value();
    assert!(sui_amount >= 100000000, EInvalidBetAmount); //至少0.1 SUI
    let buy_in = sui_amount / STACK_TO_SUI_RATIO;
    // 将 SUI 存入牌桌资金池
    table.sui_balance.join(buy_in_coin.into_balance());

    assert!(!is_seat_occupied(&table.seats[seat_index]), ESeatOccupied);
    assert!(table.can_join_state(), ENotJoinable);

    let sender = ctx.sender();
    assert!(!is_player_seated(&table.seats, sender), EPlayerAlreadySeated);

    // 验证 PK 未被注册
    assert!(!is_pk_registered(&table.seats, &pk), EPkAlreadyRegistered);

    // 洗牌/等待阶段：验证 remask + shuffle 并参与本局
    // 反序列化牌组
    let output_cts = zk_verifier::deserialize_ciphertexts(&output_cards);

    table.deck_state.aggregated_pk = table_serialization::add_pk_to_aggregated(&table.deck_state.aggregated_pk, &pk);

    // 初始化座位（参与本局）
    init_seat(&mut table.seats[seat_index], sender, buy_in, pk, false);

    // 更新牌组
    table.deck_state.encrypted = output_cts;
    // 标记为已完成洗牌
    table.shuffle_state.completed_players.push_back(seat_index);
    remove_from_pending(&mut table.shuffle_state.pending_players, seat_index);
    table_events::emit_player_joined(object::id(table), seat_index, sender, buy_in, false, count_active_occupied(&table.seats))
}


// ========== 玩家离开（带密码学验证） ==========
// 玩家洗过牌
public  fun leave_with_proof(
    table: &mut Table,
    seat_index: u64,
    output_cards: vector<u8>,           // leave 后的牌组 (serialized ciphertexts, flat bytes)
    leave_proof_bytes: vector<u8>,      // LeaveProof (serialized)
    ctx: &mut TxContext,
) {
    assert!(seat_index < table.max_players, EInvalidSeatIndex);
    assert!(is_seat_occupied(&table.seats[seat_index]), ESeatEmpty);
    assert!(table.seats[seat_index].player == ctx.sender(), ENotOwner);
    assert!(table.can_leave_state(), ENotLeaveable);
    assert!(table.shuffle_state.completed_players.contains(&seat_index), ENotShuffling);

    let player_pk = table.seats[seat_index].pk;

    // 反序列化
    let output_cts = zk_verifier::deserialize_ciphertexts(&output_cards);
    let leave_proof = table_serialization::deserialize_leave_proof(&leave_proof_bytes);

    // 验证 leave proof
    zk_verifier::verify_leave_or_abort(
        &table.deck_state.encrypted,
        &output_cts,
        &zk_verifier::deserialize_pk(&player_pk),
        &leave_proof,
    );

    // 更新聚合公钥（移除该玩家 pk）
    table.deck_state.aggregated_pk = table_serialization::remove_pk_from_aggregated(&table.deck_state.aggregated_pk, &player_pk);

    // 更新牌组
    table.deck_state.encrypted = output_cts;

    // 从协议状态中移除该玩家
    remove_from_pending(&mut table.shuffle_state.pending_players, seat_index);
    remove_from_pending(&mut table.shuffle_state.completed_players, seat_index);
    let player = table.seats[seat_index].player;
    // 退还剩余 stack：将 stack chips 兑换回 SUI 并转给玩家
    let refund_amount = table.seats[seat_index].stack;
    if (refund_amount > 0) {
        refund_sui_to_player(table, player, refund_amount, ctx);
        table_events::emit_player_refund(object::id(table), seat_index, player, refund_amount, table_events::refund_type_stack_only());
    };
    reset_seat(&mut table.seats[seat_index]);
    table_events::emit_player_left(object::id(table), seat_index, player)
}

// ========== 玩家离开（带密码学验证） ==========
// 玩家洗过牌
public  fun leave_with_proof_verified(
    table: &mut Table,
    seat_index: u64,
    output_cards: vector<u8>,           // leave 后的牌组 (serialized ciphertexts, flat bytes)
    _leave_proof_bytes: vector<u8>,      // LeaveProof (serialized)
    ctx: &mut TxContext,
) {
    assert!(seat_index < table.max_players, EInvalidSeatIndex);
    assert!(is_seat_occupied(&table.seats[seat_index]), ESeatEmpty);
    assert!(table.seats[seat_index].player == ctx.sender(), ENotOwner);
    assert!(table.can_leave_state(), ENotLeaveable);
    assert!(table.shuffle_state.completed_players.contains(&seat_index), ENotShuffling);

    let player_pk = table.seats[seat_index].pk;

    // 反序列化
    let output_cts = zk_verifier::deserialize_ciphertexts(&output_cards);

    // 更新聚合公钥（移除该玩家 pk）
    table.deck_state.aggregated_pk = table_serialization::remove_pk_from_aggregated(&table.deck_state.aggregated_pk, &player_pk);

    // 更新牌组
    table.deck_state.encrypted = output_cts;

    // 从协议状态中移除该玩家
    remove_from_pending(&mut table.shuffle_state.pending_players, seat_index);
    remove_from_pending(&mut table.shuffle_state.completed_players, seat_index);
    let player = table.seats[seat_index].player;
    // 退还剩余 stack：将 stack chips 兑换回 SUI 并转给玩家
    let refund_amount = table.seats[seat_index].stack;
    if (refund_amount > 0) {
        refund_sui_to_player(table, player, refund_amount, ctx);
        table_events::emit_player_refund(object::id(table), seat_index, player, refund_amount, table_events::refund_type_stack_only());
    };
    reset_seat(&mut table.seats[seat_index]);
    table_events::emit_player_left(object::id(table), seat_index, player)
}

public  fun join_table(
    table: &mut Table,
    seat_index: u64,
    buy_in_coin: Coin<SUI>,             // 玩家存入的 SUI 代币，按 1:10000 兑换成 stack
    pk: vector<u8>,                     // 玩家 ElGamal 公钥 (G1 compressed bytes)
    pk_ownership_proof: vector<u8>,    // PK ownership Schnorr proof (serialized, 80 bytes: 48 commitment + 32 response)
    ctx: &mut TxContext,
) {
    assert!(seat_index < table.max_players, EInvalidSeatIndex);
    // 将 SUI 代币兑换成 stack chips (1 SUI = 100000 stack)
    let sui_amount = buy_in_coin.value();
    assert!(sui_amount >= 100000000, EInvalidBetAmount); //至少0.1 SUI
    let buy_in = sui_amount / STACK_TO_SUI_RATIO;
    // 将 SUI 存入牌桌资金池
    table.sui_balance.join(buy_in_coin.into_balance());

    assert!(!is_seat_occupied(&table.seats[seat_index]), ESeatOccupied);

    let sender = ctx.sender();
    assert!(!is_player_seated(&table.seats, sender), EPlayerAlreadySeated);

    // 验证 PK 未被注册
    assert!(!is_pk_registered(&table.seats, &pk), EPkAlreadyRegistered);

    // 验证 PK 所有权证明（证明玩家拥有 pk 对应的私钥 sk）
    let pk_point = zk_verifier::deserialize_pk(&pk);
    zk_verifier::verify_pk_ownership_or_abort(&pk_point, &pk_ownership_proof);
    let is_waiting = is_playing(table);
    // 非等待加入时（table 未在游戏中），将 pk 加入 aggregated_pk
    // 等待加入时，pk 会在 reset_for_next_hand 中加入
    if (!is_waiting) {
        table.deck_state.aggregated_pk = table_serialization::add_pk_to_aggregated(
            &table.deck_state.aggregated_pk, &pk);
    };
    init_seat(&mut table.seats[seat_index], sender, buy_in, pk, is_waiting);
    table_events::emit_player_joined(object::id(table), seat_index, sender, buy_in, is_waiting, count_active_occupied(&table.seats))
}

// ========== 简单离开 ==========
public  fun leave_table(
    table: &mut Table,
    seat_index: u64,
    ctx: &mut TxContext,
) {
    assert!(seat_index < table.max_players, EInvalidSeatIndex);
    assert!(is_seat_occupied(&table.seats[seat_index]), ESeatEmpty);
    assert!(table.seats[seat_index].player == ctx.sender(), ENotOwner);
    
    assert!(!table.shuffle_state.completed_players.contains(&seat_index), ELeaveProofMissing);
    let player = table.seats[seat_index].player;
    assert!(!is_playing(table) ||(is_playing(table) && table.seats[seat_index].is_waiting),ENotLeaveable );

    // 移除 aggregated_pk 中该玩家的公钥（waiting 玩家 pk 未加入 aggregated_pk，不应移除）
    let pk = table.seats[seat_index].pk;
    let was_waiting = table.seats[seat_index].is_waiting;
    if (pk.length() > 0 && !was_waiting) {
        table.deck_state.aggregated_pk = table_serialization::remove_pk_from_aggregated(
            &table.deck_state.aggregated_pk, &pk);
    };

    // 退还剩余 stack：将 stack chips 兑换回 SUI 并转给玩家
    let refund_amount = table.seats[seat_index].stack;
    if (refund_amount > 0) {
        refund_sui_to_player(table, player, refund_amount, ctx);
        table_events::emit_player_refund(object::id(table), seat_index, player, refund_amount, table_events::refund_type_stack_only());
    };
    reset_seat(&mut table.seats[seat_index]);
    table_events::emit_player_left(object::id(table), seat_index, player)
}

// ========== 开始新一手 ==========
public  fun start_hand(table: &mut Table, _ctx: &mut TxContext) {
    do_start_hand(table);
}

fun clear_waiting_players(table: &mut Table) {
    let mut i = 0;
    while (i < table.seats.length()) {
        let seat = &mut table.seats[i];
        if (is_seat_occupied(seat)) {
            seat.is_waiting = false;
        };
        i = i + 1;
    };
}
fun start_preflop_shuffle(table: &mut Table) {
    table.shuffle_state.pending_players = get_pending_seat_indices(&table.shuffle_state.completed_players,&table.seats);
    table.shuffle_state.phase = table_constants::shuffle_phase_before_preflop();
}

fun do_start_hand(table: &mut Table) {
    assert!(
        table.round_state == table_constants::round_waiting() ,
        EInvalidRoundState
    );
    assert!(count_active_occupied(&table.seats) >= table_constants::min_players_to_start(), ENotEnoughPlayers);

    move_button(table);
    table_events::emit_hand_started(
        object::id(table),
        table.button,
        table.small_blind,
        table.big_blind,
        get_active_seat_indices(&table.seats),
    );

    // 初始化洗牌状态
    table.timestamps.shuffle_started_at = 0;  // will be set when first shuffler starts
    start_preflop_shuffle(table);
    advance_shuffle(table);
}

fun rebuild_deck_and_shuffle_on_timeout(table: &mut Table, phase: u8){
    // 重新初始化牌组为 (identity, plaintext_i)，等价于用 sk=0 加密的密文。
    // shuffle_proof::verify 只要求 input_cts 非空（n != 0），不关心具体值，
    // 因此 (identity, plaintext_i) 可作为 shuffle proof 的合法输入。
    // aggregated_pk 已在 kick_player_internal 中更新为剩余活跃玩家的聚合公钥。
    set_initial_encrypted_deck(table);
    table.shuffle_state = ShuffleState {
        phase: phase,
        current_shuffler: option::none(),
        pending_players: get_active_seat_indices(&table.seats),
        completed_players: vector[],
    };
    table_events::emit_deck_rebuilt(
        object::id(table),
        table_events::deck_rebuilt_reason_shuffle_timeout(),
        table.deck_state.encrypted.length(),
    );
}

fun set_initial_encrypted_deck(table: &mut Table){
    // reconstruct 完成：根据所有玩家提交的 output_cts 构建新牌组
    // 算法（与 Rust 端一致）：
    //   1. 初始化：每张牌为 (identity, plaintext_i)
    //   2. 对每个玩家提交的 deck：c1 += card.c1, c2 += card.c2 - plaintext_i
    //   3. 最终结果即为新牌组

    let deck_len = table.deck_state.plaintext.length();
    let mut new_deck = vector[];

    // Step 1: 初始化 (identity, plaintext_i)
    let mut i = 0;
    while (i < deck_len) {
        let plaintext_point = bls12381::g1_from_bytes(&table.deck_state.plaintext[i]);
        new_deck.push_back(bls_elgamal::new_ciphertext(
            bls12381::g1_generator(),
            plaintext_point,
        ));
        i = i + 1;
    };
    table.deck_state.encrypted = new_deck;
}

fun rebuild_deck_from_reconstruct_deck(table: &mut Table){
    // reconstruct 完成：根据所有玩家提交的 output_cts 构建新牌组
    // 算法（与 Rust 端一致）：
    //   1. 初始化：每张牌为 (identity, plaintext_i)
    //   2. 对每个玩家提交的 deck：c1 += card.c1, c2 += card.c2 - plaintext_i
    //   3. 最终结果即为新牌组

    let deck_len = table.deck_state.plaintext.length();
    let mut new_deck = vector[];

    // Step 1: 初始化 (identity, plaintext_i)
    let mut i = 0;
    while (i < deck_len) {
        let plaintext_point = bls12381::g1_from_bytes(&table.deck_state.plaintext[i]);
        new_deck.push_back(bls_elgamal::new_ciphertext(
            bls12381::g1_generator(),
            plaintext_point,
        ));
        i = i + 1;
    };

    // Step 2: 累加每个玩家提交的 deck (原地更新，避免分配新 vector)
    let mut p = 0;
    while (p < table.reconstruct_state.player_decks.length()) {
        let player_deck = &table.reconstruct_state.player_decks[p].output_cts;
        let mut j = 0;
        while (j < deck_len) {
            if (j < player_deck.length()) {
                let plaintext_point = bls12381::g1_from_bytes(&table.deck_state.plaintext[j]);
                // 读取当前值（copy 出来避免借用冲突）
                let curr = new_deck[j];
                // c1 += card.c1
                let new_c1 = bls12381::g1_add(bls_elgamal::c1(&curr), bls_elgamal::c1(&player_deck[j]));
                // c2 += card.c2 - plaintext_i
                let c2_diff = bls12381::g1_sub(bls_elgamal::c2(&player_deck[j]), &plaintext_point);
                let new_c2 = bls12381::g1_add(bls_elgamal::c2(&curr), &c2_diff);
                // 原地更新
                *(vector::borrow_mut(&mut new_deck, j)) = bls_elgamal::new_ciphertext(new_c1, new_c2);
            };
            j = j + 1;
        };
        p = p + 1;
    };

    // 更新牌组
    table.deck_state.encrypted = new_deck;
    // reconstruct 后牌组已重建，需要重新发牌
    table.deck_state.cards_dealt = 0;
    table_events::emit_deck_rebuilt(
        object::id(table),
        table_events::deck_rebuilt_reason_reconstruct_complete(),
        table.deck_state.encrypted.length(),
    );
}

fun on_complete_reconstruct(table: &mut Table) {
    rebuild_deck_from_reconstruct_deck(table);
    table.reconstruct_state.phase = table_constants::reconstruct_phase_none();
    table_events::emit_reconstruct_complete(object::id(table));
    // 进入洗牌阶段
    table.shuffle_state = ShuffleState {
        phase: table_constants::shuffle_phase_reconstruct(),
        current_shuffler: option::none(),
        pending_players: get_active_seat_indices(&table.seats),
        completed_players: vector[],
    };
    advance_shuffle(table);
}

fun on_reconstruct_shuffle_failed(table: &mut Table) {
    rebuild_deck_from_reconstruct_deck(table);
    // 进入洗牌阶段
    table.shuffle_state = ShuffleState {
        phase: table_constants::shuffle_phase_reconstruct(),
        current_shuffler: option::none(),
        pending_players: get_active_seat_indices(&table.seats),
        completed_players: vector[],
    };
    advance_shuffle(table);
}

/// 将所有用户在本手牌中的下注原路退还到 stack
/// 对于已踢出的玩家（left_during_hand），将 total_bet 兑换回 SUI 并转账
fun refund_all_bets(table: &mut Table, ctx: &mut TxContext) {
    let table_id = object::id(table);
    // 先收集需要退 SUI 的已踢出玩家信息，避免借用冲突
    let mut refund_seats = vector[];
    let mut refund_players = vector[];
    let mut refund_amounts = vector[];
    let mut i = 0;
    while (i < table.seats.length()) {
        let seat = &mut table.seats[i];
        if (is_seat_occupied(seat)) {
            if (!seat.refunded && seat.total_bet > 0) {
                seat.stack = seat.stack + seat.total_bet;
                seat.refunded = true;
            };
        } else if (seat.left_during_hand && !seat.refunded && seat.total_bet > 0) {
            // 已踢出的玩家退还 total_bet（stack 已在 kick 时退还）
            refund_seats.push_back(i);
            refund_players.push_back(seat.player);
            refund_amounts.push_back(seat.total_bet);
            seat.refunded = true;
            seat.player = @0x0;
        };
        seat.bet = 0;
        seat.total_bet = 0;
        i = i + 1;
    };
    table.pot = 0;
    table.side_pots = vector[];
    // 释放 seats 借用后，再逐个退款并发事件
    let mut r = 0;
    while (r < refund_seats.length()) {
        let seat_idx = refund_seats[r];
        let player = refund_players[r];
        let refund_amount = refund_amounts[r];
        refund_sui_to_player(table, player, refund_amount, ctx);
        table_events::emit_player_refund(
            table_id,
            seat_idx,
            player,
            refund_amount,
            table_events::refund_type_bet_only(),
        );
        r = r + 1;
    };
}

/// 清除 reveal token 阶段超时的玩家：所有 pending_players 踢出桌子
/// kick_player_internal 会发 PlayerRefund 事件（只退 stack，total_bet 保留供 side pot 计算）
fun clear_reveal_timeout_player(table: &mut Table, ctx: &mut TxContext) {
    // 收集所有 assignment 的 pending_players 的并集
    let mut to_kick = vector[];
    let mut a = 0;
    while (a < table.reveal_token_state.assignments.length()) {
        let pending = &table.reveal_token_state.assignments[a].pending_players;
        let mut p = 0;
        while (p < pending.length()) {
            if (!is_in_list(&to_kick, pending[p])) {
                to_kick.push_back(pending[p]);
            };
            p = p + 1;
        };
        a = a + 1;
    };

    // 踢出所有超时玩家（kick_player_internal 会发 PlayerKicked + PlayerRefund 事件）
    let mut k = 0;
    while (k < to_kick.length()) {
        let seat_index = to_kick[k];
        if (seat_index < table.seats.length() && is_seat_occupied(&table.seats[seat_index])) {
            kick_player_internal(table, seat_index, table_events::kick_reason_timeout(), ctx);
        };
        k = k + 1;
    };
}

fun on_reconstruct_timeout(table: &mut Table, ctx: &mut TxContext) {
    assert!(table.reconstruct_state.phase == table_constants::reconstruct_phase_collecting(),EInvalidReconstructPhase);
    table_events::emit_reconstruct_timeout(object::id(table), table.reconstruct_state.pending_players);

    // 踢掉未提交 reconstruct 的玩家（kick_player_internal 会发 PlayerRefund 事件）
    let pending = table.reconstruct_state.pending_players;
    let mut k = 0;
    while (k < pending.length()) {
        let seat_index = pending[k];
        if (seat_index < table.seats.length() && is_seat_occupied(&table.seats[seat_index])) {
            kick_player_internal(table, seat_index, table_events::kick_reason_reconstruct_timeout(), ctx);
        };
        k = k + 1;
    };
    // 如果没有活跃玩家了，退还剩余筹码并重置
    if (get_active_seat_indices(&table.seats).length() == 0) {
        refund_all_bets(table, ctx);
        reset_for_next_hand(table);
        table_events::emit_hand_reset(object::id(table), table_events::reset_reason_reconstruct_fail(), table.round_state);
        return
    };
    
    // 检查是否只有一个人，一个人可以结束游戏
    let active = count_active_players(&table.seats);
    if (active == 1) {
        end_without_showdown(table);
        return
    };
    // kick_player_internal 可能已触发 reset_for_next_hand（活跃玩家不足 min）
    if (table.round_state == table_constants::round_waiting()) {
        return
    };

    // 不清空 reconstruct_state，保留已提交的 player_decks 供 on_complete_reconstruct 重建牌组
    on_complete_reconstruct(table);
}

fun on_shuffle_complete(table: &mut Table) {
    table_events::emit_shuffle_complete(
        object::id(table),
        table.shuffle_state.phase,
        table.shuffle_state.completed_players.length(),
        table.deck_state.encrypted.length(),
    );
    // shuffle 完成：重置 shuffle，进入 reveal
    table.shuffle_state = empty_shuffle_state();
}

fun on_reveal_complete(table: &mut Table) {
    // 尝试触发状态转换（如果所有牌已解密）
    // 如果有未解密的牌（如玩家被踢导致 pending 为空但未解密），则不清空 reveal state
    // 由 tick 继续检查超时，触发 on_reveal_timeout 处理
    check_reveal_phase_complete(table);
}

fun start_reconstruct(table: &mut Table, clock: &Clock){
    // 其他阶段超时：启动 reconstruct
    // 使用 table_id + 时间戳生成唯一标量，确保每次 reconstruct 的 coefficient 不同
    let mut seed = b"reconstruct_coefficient/";
    // 将 ID 的 bytes 追加到 seed
    let id_bytes = object::id(table).to_bytes();
    let mut i = 0;
    while (i < id_bytes.length()) {
        seed.push_back(*(vector::borrow(&id_bytes, i)));
        i = i + 1;
    };
    // 追加时间戳确保每次调用产生不同标量
    let now_bytes = bls_scalar::u64_to_ascii(clock.timestamp_ms());
    i = 0;
    while (i < now_bytes.length()) {
        seed.push_back(*(vector::borrow(&now_bytes, i)));
        i = i + 1;
    };
    table.reconstruct_state = ReconstructState {
        phase: table_constants::reconstruct_phase_collecting(),
        pending_players: get_active_seat_indices(&table.seats),
        coefficient: bls_scalar::scalar_to_bytes(&hash_to_scalar(&seed)),
        player_decks: vector[],
    };
    
    let now = clock.timestamp_ms();
    table.timestamps.reconstruct_started_at = now;
    table_events::emit_reconstruct_initiated(
        object::id(table),
        table.reconstruct_state.pending_players,
        table.round_state,
    );
}
    

fun on_reveal_timeout(table: &mut Table, clock: &Clock, ctx: &mut TxContext) {
    // 收集所有 assignment 的 pending_players 的并集
    let mut pending_players = vector[];
    let mut a = 0;
    while (a < table.reveal_token_state.assignments.length()) {
        let pending = &table.reveal_token_state.assignments[a].pending_players;
        let mut p = 0;
        while (p < pending.length()) {
            if (!is_in_list(&pending_players, pending[p])) {
                pending_players.push_back(pending[p]);
            };
            p = p + 1;
        };
        a = a + 1;
    };
    table_events::emit_reveal_timeout(object::id(table), table.round_state, pending_players);
    // PreFlop reveal 超时: 因为所有玩家手牌未知，可以重开整手
    if (table.round_state == table_constants::round_preflop()) {
        // 先踢超时玩家（kick_player_internal 会发 PlayerRefund 事件，只退 stack）
        clear_reveal_timeout_player(table, ctx);
        let active = count_active_players(&table.seats);
        if (active == 0) {
            refund_all_bets(table, ctx);
            reset_for_next_hand(table);
            table_events::emit_hand_reset(object::id(table), table_events::reset_reason_timeout(), table.round_state);
            return
        };
        if (active == 1) {
            end_without_showdown(table);
            return
        };
        // // clear_reveal_timeout_player 内部 kick 可能触发 reset_for_next_hand
        // if (table.round_state == table_constants::round_waiting()) {
        //     return
        // };
        // refund_all_bets(table);
        // // 清理上一轮 reveal 残留状态（保留 encrypted 牌组用于重新洗牌）
        // table.reveal_token_state = empty_reveal_token_state();
        // table.deck_state.cards_dealt = 0;
        // table.deck_state.decrypted_cards = vector[];
        // // 重新洗牌：基于现有 encrypted 牌组重新 shuffle（不清空牌组）
        // table.shuffle_state = ShuffleState {
        //     phase: table_constants::shuffle_phase_before_preflop(),
        //     current_shuffler: option::none(),
        //     pending_players: get_active_seat_indices(&table.seats),
        //     completed_players: vector[],
        // };
        // advance_shuffle(table);
        // //发个事件，通知玩家重新洗牌
        // 再退还未被踢的玩家的筹码
        refund_all_bets(table, ctx);
        // 踢人后 aggregated_pk 已变，现有牌组无效，必须 reset 让玩家重新 join_and_shuffle
        reset_for_next_hand(table);
        //发个事件，通知玩家重新开一手
        table_events::emit_hand_reset(object::id(table), table_events::reset_reason_timeout(), table.round_state);
    }else{
        // 其他阶段超时：先踢出超时玩家，再启动 reconstruct
        clear_reveal_timeout_player(table, ctx);
        // clear_reveal_timeout_player 内部 kick 可能触发 reset_for_next_hand
        if (table.round_state == table_constants::round_waiting()) {
            return
        };
        let active = count_active_players(&table.seats);
        if (active == 0) {
            refund_all_bets(table, ctx);
            reset_for_next_hand(table);
            table_events::emit_hand_reset(object::id(table), table_events::reset_reason_timeout(), table.round_state);
            return
        };
        if (active == 1) {
            end_without_showdown(table);
            return
        };
        start_reconstruct(table,clock);
    };
}

fun on_shuffle_timeout(table: &mut Table, ctx: &mut TxContext) {
    if (table.shuffle_state.current_shuffler.is_some()) {
        let shuffler = *table.shuffle_state.current_shuffler.borrow();
        table_events::emit_shuffle_timeout(
            object::id(table),
            shuffler,
            table.shuffle_state.phase,
            table.timestamps.shuffle_started_at,
            table.timeout_config.shuffle_timeout_ms,
        );

        if (table.shuffle_state.phase == table_constants::shuffle_phase_before_preflop()) {
            // Preflop 洗牌超时：踢掉当前洗牌者
            kick_player_internal(table, shuffler, table_events::kick_reason_timeout(), ctx);

            let active = count_active_players(&table.seats);
            if (active == 0) {
                refund_all_bets(table, ctx);
                reset_for_next_hand(table);
                table_events::emit_hand_reset(object::id(table), table_events::reset_reason_timeout(), table.round_state);
                return
            };
            if (active == 1) {
                end_without_showdown(table);
                return
            };

            // kick_player_internal 可能已触发 reset_for_next_hand（活跃玩家不足）或
            // on_shuffle_complete（最后一个 pending 玩家被踢），两者都会将
            // shuffle_state.phase 置为 shuffle_phase_none，无需再处理。
            if (table.shuffle_state.phase == table_constants::shuffle_phase_none()) {
                return
            };

            // 重新初始化牌组并重新洗牌。
            // set_initial_encrypted_deck 将 encrypted 初始化为 (identity, plaintext_i)，
            // 非空牌组（n=52）可通过 shuffle_proof::verify 的 n==0 检查。
            rebuild_deck_and_shuffle_on_timeout(table, table_constants::shuffle_phase_before_preflop());
            advance_shuffle(table);
        } else if (table.shuffle_state.phase == table_constants::shuffle_phase_reconstruct()) {
            // Reconstruct 洗牌超时：踢掉当前洗牌者
            kick_player_internal(table, shuffler, table_events::kick_reason_timeout(), ctx);

            let active = count_active_players(&table.seats);
            if (active == 0) {
                refund_all_bets(table, ctx);
                reset_for_next_hand(table);
                table_events::emit_hand_reset(object::id(table), table_events::reset_reason_timeout(), table.round_state);
                return
            };
            if (active == 1) {
                end_without_showdown(table);
                return
            };

            // kick_player_internal 可能已触发 reset_for_next_hand（活跃玩家不足）
            if (table.round_state == table_constants::round_waiting()) {
                return
            };

            // kick_player_internal 可能已触发 on_shuffle_complete（最后一个 pending 玩家被踢）。
            // on_shuffle_complete 在 shuffle_phase_reconstruct 分支会清空 reconstruct_state，
            // 启动 reveal phase。此时 deck_state.encrypted 仍有效，无需 reset。
            // C4 修复：若 phase 已不再是 reconstruct（已被 advance_shuffle 推进），
            // 说明洗牌已完成并进入下一阶段，直接返回，不再 refund/reset。
            if (table.shuffle_state.phase != table_constants::shuffle_phase_reconstruct()) {
                return
            };



            // 从 reconstruct_state.player_decks 中移除被踢玩家提交的 deck。
            // 密码学正确性（已通过 Rust 验证）：组合公式线性可加，
            // c1_final = Σ_p c1_p[j], c2_final = Σ_p c2_p[j] - (n-1) * plaintext_j，
            // 移除玩家 k 等价于 k 未参与 reconstruct，结果仍为剩余玩家的有效聚合牌组。
            let mut d = 0;
            while (d < table.reconstruct_state.player_decks.length()) {
                if (table.reconstruct_state.player_decks[d].seat_index == shuffler) {
                    table.reconstruct_state.player_decks.remove(d);
                    break
                };
                d = d + 1;
            };

            // 重新构建牌组并重新洗牌
            on_reconstruct_shuffle_failed(table);
        };
    };
}

fun on_betting_timeout(table: &mut Table) {
    // 检查下注超时
    if (table.current_turn.is_none()) {
        return
    };
    let seat_index = *table.current_turn.borrow();
    table_events::emit_player_folded(object::id(table), seat_index, table_events::fold_reason_auto_timeout(), table.round_state);
    do_fold(table, seat_index);
}


// ========== Tick 函数（链下 relayer 定期调用） ==========
// M-P4: tick 为 permissionless 设计——任何人都可以调用。
// Gas 攻击风险分析：
//   - tick 内部所有操作均基于 Clock timestamp 的超时检查，无实际状态变更除非超时；
//   - 超时处理（fold/reset）是游戏逻辑必需，不会对调用者产生收益；
//   - 调用者需支付 gas 但无法获取筹码优势，因此无经济激励滥用；
//   - 如未来需要限制调用频率，可基于 table.timestamps.last_tick_at 添加最小间隔检查。
// 当前实现接受 permissionless 模型，依赖链下 relayer 竞争调用。
public  fun tick(table: &mut Table, clock: &Clock, ctx: &mut TxContext) {
    let now = clock.timestamp_ms();

    // ===== 优先处理 interrupt（reconstruct） =====
    if (table.reconstruct_state.phase != table_constants::reconstruct_phase_none()) {
        // 先检查 reconstruct 是否完成
         if (table.timestamps.reconstruct_started_at > 0 && now >= table.timestamps.reconstruct_started_at + table.timeout_config.reconstruct_timeout_ms) {
            on_reconstruct_timeout(table, ctx);
        };
        // reconstruct 进行中，不处理其他状态
        return
    };

    if(table.shuffle_state.phase == table_constants::shuffle_phase_reconstruct() || table.shuffle_state.phase == table_constants::shuffle_phase_before_preflop()) {
        if (table.shuffle_state.pending_players.length() == 0) {
            // advance_shuffle 内部会在 pending_players == 0 时调用 on_shuffle_complete 并推进到 reveal phase
            advance_shuffle(table);
            return
        };
        // current_shuffler 为 None 时，调用 advance_shuffle 设置下一个洗牌者，避免死锁
        // （shuffle_started_at 的设置依赖 current_shuffler.is_some()，None 时永远不触发超时）
        if (table.shuffle_state.current_shuffler.is_none()) {
            advance_shuffle(table);
            return
        };
        // 首次进入洗牌等待时记录开始时间
        if (table.timestamps.shuffle_started_at == 0) {
            table.timestamps.shuffle_started_at = now;
        };
        // 检查洗牌超时
        if (table.timestamps.shuffle_started_at > 0 && now >= table.timestamps.shuffle_started_at + table.timeout_config.shuffle_timeout_ms) {
            on_shuffle_timeout(table, ctx);
        };
        return
    };

    if (table.reveal_token_state.reveal_phase != table_constants::reveal_phase_none()) {
        // 遍历检查是否所有 assignment 的 pending_players 都已为空
        //todo 这里实现很别扭，后续优化
        let mut all_completed = true;
        let mut j = 0;
        while (j < table.reveal_token_state.assignments.length()) {
            if (table.reveal_token_state.assignments[j].pending_players.length() > 0) {
                all_completed = false;
                break
            };
            j = j + 1;
        };
        if (all_completed) {
            on_reveal_complete(table);
            // 如果 check_reveal_phase_complete 已清空 reveal state，说明状态转换已完成
            if (table.reveal_token_state.reveal_phase == table_constants::reveal_phase_none()) {
                return
            };
            // 否则说明有 assignment 未解密（如玩家被踢），继续检查超时
        };

        // 首次进入揭牌等待时记录开始时间
        if (table.timestamps.reveal_started_at == 0) {
            table.timestamps.reveal_started_at = now;
        };
        // 揭牌超时
        if (table.timestamps.reveal_started_at > 0 && now >= table.timestamps.reveal_started_at + table.timeout_config.reveal_timeout_ms) {
            on_reveal_timeout(table, clock, ctx);
        };

        return 
    };

    // ===== 正常 tick 逻辑 =====
    if (table.round_state == table_constants::round_waiting()) {
        if (count_active_occupied(&table.seats) >= table_constants::min_players_to_start()){
            // 检查是否可以开始
            do_start_hand(table);
        };
    }   else if (is_betting_round(table)) {
        // 异常状态修复：betting_round 存在但 current_turn 为 none，强制推进避免死锁
        if (table.current_turn.is_none()) {
            collect_bets_to_pot(table);
            advance_round(table);
        } else {
            // 设置下注开始时间
            if (table.timestamps.betting_started_at == 0) {
                table.timestamps.betting_started_at = now;
            };
            // 填充 current_turn 变化时间戳
            if (table.timestamps.current_turn_changed_at == 0) {
                table.timestamps.current_turn_changed_at = now;
            };
            if (table.timestamps.betting_started_at > 0 && now >= table.timestamps.betting_started_at + table.timeout_config.betting_timeout_ms) {
                on_betting_timeout(table);
            };
        };
    } else if (table.round_state == table_constants::round_showdown()) {
        // 设置 showdown 开始时间
        if (table.timestamps.showdown_at == 0) {
            table.timestamps.showdown_at = now + table.timeout_config.showdown_display_ms;
        };
        if (now >= table.timestamps.showdown_at) {
            settle_hand(table);
        };
    } else {
        // Fallback：round_state 在 preflop/flop/turn/river 但无 betting_round 且无 reveal/shuffle/reconstruct
        // 说明状态不一致，强制 reset 避免永久死锁
        if (table.reveal_token_state.reveal_phase == table_constants::reveal_phase_none()
            && table.shuffle_state.phase == table_constants::shuffle_phase_none()
            && table.reconstruct_state.phase == table_constants::reconstruct_phase_none()) {
            refund_all_bets(table, ctx);
            reset_for_next_hand(table);
            table_events::emit_hand_reset(object::id(table), table_events::reset_reason_state_inconsistent(), table.round_state);
        };
    };
}

// ========== Phase 3: auto_fold / force_fold / kick_player ==========

public  fun auto_fold(table: &mut Table, seat_index: u64, clock: &Clock) {
    assert!(is_betting_round(table), EInvalidRoundState);
    assert!(is_player_turn(table, seat_index), ENotPlayerTurn);
    assert!(table.timestamps.betting_started_at > 0, ENotTimedOut);
    assert!(clock.timestamp_ms() >= table.timestamps.betting_started_at + table.timeout_config.betting_timeout_ms, ENotTimedOut);

    table_events::emit_player_folded(object::id(table), seat_index, table_events::fold_reason_auto_timeout(), table.round_state);
    do_fold(table, seat_index);
}

public  fun force_fold(table: &mut Table, _admin_cap: &AdminCap, seat_index: u64) {
    assert!(seat_index < table.max_players, EInvalidSeatIndex);
    assert!(is_betting_round(table), EInvalidRoundState);
    // M11 修复：校验目标玩家为当前行动玩家，防止破坏行动顺序
    assert!(is_player_turn(table, seat_index), ENotPlayerTurn);
    let seat = &table.seats[seat_index];
    assert!(is_seat_occupied(seat), ESeatEmpty);
    assert!(!seat.folded, EAlreadyFolded);

    table_events::emit_player_folded(object::id(table), seat_index, table_events::fold_reason_force_admin(), table.round_state);
    do_fold(table, seat_index);
}

public  fun kick_player(table: &mut Table, _admin_cap: &AdminCap, seat_index: u64, ctx: &mut TxContext) {
    assert!(seat_index < table.max_players, EInvalidSeatIndex);
    kick_player_internal(table, seat_index, table_events::kick_reason_admin(), ctx);
}

// ========== 提交洗牌结果（ZK Proof 验证） ==========
public  fun submit_shuffle(
    table: &mut Table,
    output_cards: vector<u8>,           // 序列化的 ElGamalCiphertext 数组 (flat bytes)
    shuffle_proof_bytes: vector<u8>,    // 序列化的 ShuffleProof
    ctx: &mut TxContext,
) {
    assert!(table.shuffle_state.phase != table_constants::shuffle_phase_none(), EInvalidShufflePhase);

    let sender = ctx.sender();
    assert!(is_player_seated(&table.seats, sender), EPlayerNotSeated);

    let seat_index = find_seat_index(&table.seats, sender);

    // 验证是当前洗牌者
    assert!(
        table.shuffle_state.current_shuffler.is_some() &&
        *table.shuffle_state.current_shuffler.borrow() == seat_index,
        ENotCurrentShuffler
    );

    // 验证未已完成
    assert!(!is_in_list(&table.shuffle_state.completed_players, seat_index), EShuffleAlreadyCompleted);

    // 反序列化
    let output_cts = zk_verifier::deserialize_ciphertexts(&output_cards);
    let shuffle_proof = table_serialization::deserialize_shuffle_proof(&shuffle_proof_bytes);

    // 验证 shuffle proof
    let pk = zk_verifier::deserialize_pk(&table.deck_state.aggregated_pk);
    zk_verifier::verify_shuffle_or_abort(&table.deck_state.encrypted, &output_cts, &pk, &shuffle_proof);

    // 更新牌组
    table.deck_state.encrypted = output_cts;

    // 标记为已完成
    table.shuffle_state.completed_players.push_back(seat_index);
    remove_from_pending(&mut table.shuffle_state.pending_players, seat_index);

    table_events::emit_shuffle_verified(object::id(table), seat_index, sender);

    // 推进洗牌流程
    advance_shuffle(table);
}

// ========== 提交洗牌结果（ZK Proof 验证） ==========
public  fun submit_shuffle_verified(
    table: &mut Table,
    output_cards: vector<u8>,           // 序列化的 ElGamalCiphertext 数组 (flat bytes)
    _shuffle_proof_bytes: vector<u8>,    // 序列化的 ShuffleProof
    ctx: &mut TxContext,
) {
    assert!(table.shuffle_state.phase != table_constants::shuffle_phase_none(), EInvalidShufflePhase);

    let sender = ctx.sender();
    assert!(is_player_seated(&table.seats, sender), EPlayerNotSeated);

    let seat_index = find_seat_index(&table.seats, sender);

    // 验证是当前洗牌者
    assert!(
        table.shuffle_state.current_shuffler.is_some() &&
        *table.shuffle_state.current_shuffler.borrow() == seat_index,
        ENotCurrentShuffler
    );

    // 验证未已完成
    assert!(!is_in_list(&table.shuffle_state.completed_players, seat_index), EShuffleAlreadyCompleted);

    // 反序列化
    let output_cts = zk_verifier::deserialize_ciphertexts(&output_cards);

    // 更新牌组
    table.deck_state.encrypted = output_cts;

    // 标记为已完成
    table.shuffle_state.completed_players.push_back(seat_index);
    remove_from_pending(&mut table.shuffle_state.pending_players, seat_index);

    table_events::emit_shuffle_verified(object::id(table), seat_index, sender);
    // 推进洗牌流程
    advance_shuffle(table);
}


// ========== 批量提交 Reveal Token ==========
/// 玩家一次性提交当前 phase 下所有需要揭牌的 reveal tokens
/// 对应 Rust 端 submit_player_reveal_tokens
public  fun submit_player_reveal_tokens(
    table: &mut Table,
    assignment_indices: vector<u64>,    // 该玩家需要提交的 assignment 索引列表
    reveal_tokens: vector<vector<u8>>,  // 对应每个 assignment 的 c1 * sk (G1 compressed bytes)
    proof_bytes_list: vector<vector<u8>>, // 对应每个 assignment 的 RevealTokenProof (serialized)
    ctx: &mut TxContext,
) {
    assert!(table.reveal_token_state.reveal_phase != table_constants::reveal_phase_none(), EInvalidRevealPhaseState);
    assert!(assignment_indices.length() == reveal_tokens.length(), EInvalidCardIndex);
    assert!(assignment_indices.length() == proof_bytes_list.length(), EInvalidCardIndex);

    let sender = ctx.sender();
    assert!(is_player_seated(&table.seats, sender), EPlayerNotSeated);
    let seat_index = find_seat_index(&table.seats, sender);

    let current_phase = table.reveal_token_state.reveal_phase;

    // 收集 identity 牌的 card_index，循环结束后统一处理 redeal
    let mut identity_card_indices = vector[];

    let mut idx = 0;
    while (idx < assignment_indices.length()) {
        let assignment_index = assignment_indices[idx];
        assert!(assignment_index < table.reveal_token_state.assignments.length(), EInvalidCardIndex);

        // 读取 assignment 信息
        let card_index = table.reveal_token_state.assignments[assignment_index].encrypted_card_index;
        let is_decrypted = table.reveal_token_state.assignments[assignment_index].decrypted;
        let is_pending = is_in_list(&table.reveal_token_state.assignments[assignment_index].pending_players, seat_index);

        assert!(!is_decrypted, ECardAlreadyDecrypted);
        assert!(is_pending, ENotPendingRevealer);
        assert!(card_index < table.deck_state.encrypted.length(), EInvalidCardIndex);

        // 提前计算手牌牌主（preflop 阶段需要）
        let owner_seat_index = if (current_phase == table_constants::reveal_phase_preflop()) {
            find_hand_card_owner(table, card_index)
        } else {
            0xFFFFFFFFFFFFFFFF
        };

        let reveal_token = reveal_tokens[idx];
        let proof_bytes = proof_bytes_list[idx];

        // ========== 按 phase 验证 reveal token proof ==========
        if (current_phase == table_constants::reveal_phase_showdown()) {
            let partial_ct_bytes = find_partial_ciphertext(&table.deck_state.decrypted_cards, card_index);
            let partial_ct = bls_elgamal::ciphertext_from_bytes(&partial_ct_bytes);
            let token_point = bls12381::g1_from_bytes(&reveal_token);
            let expected_pk = zk_verifier::deserialize_pk(&table.seats[seat_index].pk);
            let proof = table_serialization::deserialize_reveal_token_proof(&proof_bytes);
            zk_verifier::verify_reveal_token_or_abort(&partial_ct, &token_point, &expected_pk, &proof);
        } else {
            let encrypted_card = &table.deck_state.encrypted[card_index];
            let token_point = bls12381::g1_from_bytes(&reveal_token);
            let expected_pk = zk_verifier::deserialize_pk(&table.seats[seat_index].pk);
            let proof = table_serialization::deserialize_reveal_token_proof(&proof_bytes);
            zk_verifier::verify_reveal_token_or_abort(encrypted_card, &token_point, &expected_pk, &proof);
        };

        // 存储 reveal token
        let assignment = &mut table.reveal_token_state.assignments[assignment_index];
        assignment.reveal_tokens.push_back(RevealTokenData {
            seat_index,
            token: reveal_token,
        });

        // 从 pending 中移除
        remove_from_pending(&mut assignment.pending_players, seat_index);

        // 如果所有玩家都已提交，链上解密
        if (assignment.pending_players.length() == 0) {
            if (current_phase == table_constants::reveal_phase_preflop()) {
                // ========== PREFLOP: 部分解密 ==========
                let encrypted_card = &table.deck_state.encrypted[card_index];
                let c1_bytes = bls_elgamal::c1_bytes(encrypted_card);
                let mut result = *bls_elgamal::c2(encrypted_card);
                let mut t = 0;
                while (t < assignment.reveal_tokens.length()) {
                    let token_point = bls12381::g1_from_bytes(&assignment.reveal_tokens[t].token);
                    result = bls12381::g1_sub(&result, &token_point);
                    t = t + 1;
                };
                let mut ct_bytes = c1_bytes;
                let result_bytes = bls_scalar::g1_to_bytes(&result);
                let mut r = 0;
                while (r < result_bytes.length()) {
                    ct_bytes.push_back(result_bytes[r]);
                    r = r + 1;
                };
                table.deck_state.decrypted_cards.push_back(DecryptedCard {
                    encrypted_card_index: card_index,
                    owner_seat_index,
                    ciphertext_bytes: ct_bytes,
                    plaintext_bytes: vector[],
                });
                assignment.decrypted = true;
            } else if (current_phase == table_constants::reveal_phase_showdown()) {
                // ========== SHOWDOWN: 从部分解密密文得到明文 ==========
                let partial_ct_bytes = find_partial_ciphertext(&table.deck_state.decrypted_cards, card_index);
                let partial_ct = bls_elgamal::ciphertext_from_bytes(&partial_ct_bytes);
                let mut result = *bls_elgamal::c2(&partial_ct);
                let mut t = 0;
                while (t < assignment.reveal_tokens.length()) {
                    let token_point = bls12381::g1_from_bytes(&assignment.reveal_tokens[t].token);
                    result = bls12381::g1_sub(&result, &token_point);
                    t = t + 1;
                };
                let plaintext_bytes = bls_scalar::g1_to_bytes(&result);
                update_decrypted_card_to_plaintext(&mut table.deck_state.decrypted_cards, card_index, plaintext_bytes);
                assignment.decrypted = true;
            } else {
                // ========== COMMUNITY / REDEAL: 全部解密 ==========
                let encrypted_card = &table.deck_state.encrypted[card_index];
                let mut result = *bls_elgamal::c2(encrypted_card);
                let mut t = 0;
                while (t < assignment.reveal_tokens.length()) {
                    let token_point = bls12381::g1_from_bytes(&assignment.reveal_tokens[t].token);
                    result = bls12381::g1_sub(&result, &token_point);
                    t = t + 1;
                };
                if (bls_scalar::g1_is_identity(&result)) {
                    assignment.decrypted = true;
                    identity_card_indices.push_back(card_index);
                    table_events::emit_card_is_identity(
                        object::id(table),
                        card_index,
                        assignment_index,
                        current_phase,
                    );
                } else {
                    assignment.decrypted = true;
                    let plaintext_bytes = bls_scalar::g1_to_bytes(&result);
                    table.deck_state.decrypted_cards.push_back(DecryptedCard {
                        encrypted_card_index: card_index,
                        owner_seat_index: 0xFFFFFFFFFFFFFFFF,
                        ciphertext_bytes: vector[],
                        plaintext_bytes,
                    });
                };
            };
        };

        table_events::emit_reveal_token_submitted(
            object::id(table),
            seat_index,
            card_index,
            current_phase,
        );

        idx = idx + 1;
    };

    // 统一处理 identity redeal
    if (identity_card_indices.length() > 0) {
        // 从后往前移除 identity 的 assignments（用 remove 保持顺序）
        let mut i = table.reveal_token_state.assignments.length();
        while (i > 0) {
            i = i - 1;
            let ci = table.reveal_token_state.assignments[i].encrypted_card_index;
            if (is_in_list(&identity_card_indices, ci)) {
                table.reveal_token_state.assignments.remove(i);
            };
        };

        // 为 identity 牌创建 redeal assignments（从 cards_dealt 开始分配新牌）
        let redeal_count = identity_card_indices.length();
        let mut redeal_assignments = create_reveal_assignments_for_cards(table, redeal_count);
        while (redeal_assignments.length() > 0) {
            table.reveal_token_state.assignments.push_back(redeal_assignments.pop_back());
        };

        table_events::emit_identity_redeal(
            object::id(table),
            identity_card_indices,
            redeal_count,
            current_phase,
        );
    };

    // 批量提交完成后，检查是否所有牌都已解密
    check_reveal_phase_complete(table);
}

// ========== 批量提交 Reveal Token ==========
/// 玩家一次性提交当前 phase 下所有需要揭牌的 reveal tokens
/// 对应 Rust 端 submit_player_reveal_tokens
public  fun submit_player_reveal_tokens_verified(
    table: &mut Table,
    assignment_indices: vector<u64>,    // 该玩家需要提交的 assignment 索引列表
    reveal_tokens: vector<vector<u8>>,  // 对应每个 assignment 的 c1 * sk (G1 compressed bytes)
    proof_bytes_list: vector<vector<u8>>, // 对应每个 assignment 的 RevealTokenProof (serialized)
    ctx: &mut TxContext,
) {
    assert!(table.reveal_token_state.reveal_phase != table_constants::reveal_phase_none(), EInvalidRevealPhaseState);
    assert!(assignment_indices.length() == reveal_tokens.length(), EInvalidCardIndex);
    assert!(assignment_indices.length() == proof_bytes_list.length(), EInvalidCardIndex);

    let sender = ctx.sender();
    assert!(is_player_seated(&table.seats, sender), EPlayerNotSeated);
    let seat_index = find_seat_index(&table.seats, sender);

    let current_phase = table.reveal_token_state.reveal_phase;

    // 收集 identity 牌的 card_index，循环结束后统一处理 redeal
    let mut identity_card_indices = vector[];

    let mut idx = 0;
    while (idx < assignment_indices.length()) {
        let assignment_index = assignment_indices[idx];
        assert!(assignment_index < table.reveal_token_state.assignments.length(), EInvalidCardIndex);

        // 读取 assignment 信息
        let card_index = table.reveal_token_state.assignments[assignment_index].encrypted_card_index;
        let is_decrypted = table.reveal_token_state.assignments[assignment_index].decrypted;
        let is_pending = is_in_list(&table.reveal_token_state.assignments[assignment_index].pending_players, seat_index);

        assert!(!is_decrypted, ECardAlreadyDecrypted);
        assert!(is_pending, ENotPendingRevealer);
        assert!(card_index < table.deck_state.encrypted.length(), EInvalidCardIndex);

        // 提前计算手牌牌主（preflop 阶段需要）
        let owner_seat_index = if (current_phase == table_constants::reveal_phase_preflop()) {
            find_hand_card_owner(table, card_index)
        } else {
            0xFFFFFFFFFFFFFFFF
        };

        let reveal_token = reveal_tokens[idx];
        // 存储 reveal token
        let assignment = &mut table.reveal_token_state.assignments[assignment_index];
        assignment.reveal_tokens.push_back(RevealTokenData {
            seat_index,
            token: reveal_token,
        });

        // 从 pending 中移除
        remove_from_pending(&mut assignment.pending_players, seat_index);

        // 如果所有玩家都已提交，链上解密
        if (assignment.pending_players.length() == 0) {
            if (current_phase == table_constants::reveal_phase_preflop()) {
                // ========== PREFLOP: 部分解密 ==========
                let encrypted_card = &table.deck_state.encrypted[card_index];
                let c1_bytes = bls_elgamal::c1_bytes(encrypted_card);
                let mut result = *bls_elgamal::c2(encrypted_card);
                let mut t = 0;
                while (t < assignment.reveal_tokens.length()) {
                    let token_point = bls12381::g1_from_bytes(&assignment.reveal_tokens[t].token);
                    result = bls12381::g1_sub(&result, &token_point);
                    t = t + 1;
                };
                let mut ct_bytes = c1_bytes;
                let result_bytes = bls_scalar::g1_to_bytes(&result);
                let mut r = 0;
                while (r < result_bytes.length()) {
                    ct_bytes.push_back(result_bytes[r]);
                    r = r + 1;
                };
                table.deck_state.decrypted_cards.push_back(DecryptedCard {
                    encrypted_card_index: card_index,
                    owner_seat_index,
                    ciphertext_bytes: ct_bytes,
                    plaintext_bytes: vector[],
                });
                assignment.decrypted = true;
            } else if (current_phase == table_constants::reveal_phase_showdown()) {
                // ========== SHOWDOWN: 从部分解密密文得到明文 ==========
                let partial_ct_bytes = find_partial_ciphertext(&table.deck_state.decrypted_cards, card_index);
                let partial_ct = bls_elgamal::ciphertext_from_bytes(&partial_ct_bytes);
                let mut result = *bls_elgamal::c2(&partial_ct);
                let mut t = 0;
                while (t < assignment.reveal_tokens.length()) {
                    let token_point = bls12381::g1_from_bytes(&assignment.reveal_tokens[t].token);
                    result = bls12381::g1_sub(&result, &token_point);
                    t = t + 1;
                };
                let plaintext_bytes = bls_scalar::g1_to_bytes(&result);
                update_decrypted_card_to_plaintext(&mut table.deck_state.decrypted_cards, card_index, plaintext_bytes);
                assignment.decrypted = true;
            } else {
                // ========== COMMUNITY / REDEAL: 全部解密 ==========
                let encrypted_card = &table.deck_state.encrypted[card_index];
                let mut result = *bls_elgamal::c2(encrypted_card);
                let mut t = 0;
                while (t < assignment.reveal_tokens.length()) {
                    let token_point = bls12381::g1_from_bytes(&assignment.reveal_tokens[t].token);
                    result = bls12381::g1_sub(&result, &token_point);
                    t = t + 1;
                };
                if (bls_scalar::g1_is_identity(&result)) {
                    assignment.decrypted = true;
                    identity_card_indices.push_back(card_index);
                    table_events::emit_card_is_identity(
                        object::id(table),
                        card_index,
                        assignment_index,
                        current_phase,
                    );
                } else {
                    assignment.decrypted = true;
                    let plaintext_bytes = bls_scalar::g1_to_bytes(&result);
                    table.deck_state.decrypted_cards.push_back(DecryptedCard {
                        encrypted_card_index: card_index,
                        owner_seat_index: 0xFFFFFFFFFFFFFFFF,
                        ciphertext_bytes: vector[],
                        plaintext_bytes,
                    });
                };
            };
        };

        table_events::emit_reveal_token_submitted(
            object::id(table),
            seat_index,
            card_index,
            current_phase,
        );

        idx = idx + 1;
    };

    // 统一处理 identity redeal
    if (identity_card_indices.length() > 0) {
        // 从后往前移除 identity 的 assignments（用 remove 保持顺序）
        let mut i = table.reveal_token_state.assignments.length();
        while (i > 0) {
            i = i - 1;
            let ci = table.reveal_token_state.assignments[i].encrypted_card_index;
            if (is_in_list(&identity_card_indices, ci)) {
                table.reveal_token_state.assignments.remove(i);
            };
        };

        // 为 identity 牌创建 redeal assignments（从 cards_dealt 开始分配新牌）
        let redeal_count = identity_card_indices.length();
        let mut redeal_assignments = create_reveal_assignments_for_cards(table, redeal_count);
        while (redeal_assignments.length() > 0) {
            table.reveal_token_state.assignments.push_back(redeal_assignments.pop_back());
        };

        table_events::emit_identity_redeal(
            object::id(table),
            identity_card_indices,
            redeal_count,
            current_phase,
        );
    };

    // 批量提交完成后，检查是否所有牌都已解密
    check_reveal_phase_complete(table);
}

// ========== 提交 Reconstruct Deck ==========
public  fun submit_reconstruct_deck(
    table: &mut Table,
    output_cards: vector<u8>,           // 重建后的牌组 (serialized ciphertexts, flat bytes)
    swap_cards: vector<u8>,             // swap-out 牌 (serialized ciphertexts, flat bytes)
    user_readable_cards: vector<u8>,    // 该玩家的可读牌 (serialized ciphertexts, flat bytes)
    proof_bytes: vector<u8>,            // ReconstructProof (serialized)
    ctx: &mut TxContext,
) {
    assert!(table.reconstruct_state.phase == table_constants::reconstruct_phase_collecting(), EReconstructNotCollecting);

    let sender = ctx.sender();
    assert!(is_player_seated(&table.seats, sender), EPlayerNotSeated);

    let seat_index = find_seat_index(&table.seats, sender);
    assert!(is_in_list(&table.reconstruct_state.pending_players, seat_index), EReconstructAlreadySubmitted);

    // 反序列化
    let output_cts = zk_verifier::deserialize_ciphertexts(&output_cards);
    assert!(output_cts.length() == table.deck_state.plaintext.length(), EInvalidReconstructDeckSize);

    let swap_cts = zk_verifier::deserialize_ciphertexts(&swap_cards);
    let readable_cts = zk_verifier::deserialize_ciphertexts(&user_readable_cards);
    let reconstruct_proof = table_serialization::deserialize_reconstruct_proof(&proof_bytes);

    // 从 ReconstructState 读取明文牌点
    let mut card_points = vector[];
    let mut i = 0;
    while (i < table.deck_plaintext().length()) {
        card_points.push_back(bls12381::g1_from_bytes(&table.deck_plaintext()[i]));
        i = i + 1;
    };

    // 获取玩家公钥
    let user_pk = zk_verifier::deserialize_pk(&table.seats[seat_index].pk);

    // 验证 reconstruct proof
    zk_verifier::verify_reconstruct_or_abort(
        &card_points,
        &output_cts,
        &swap_cts,
        &readable_cts,
        &user_pk,
        &reconstruct_proof,
    );

    // 标记为已完成，存储该玩家的 output_cts
    remove_from_pending(&mut table.reconstruct_state.pending_players, seat_index);
    table.reconstruct_state.player_decks.push_back(ReconstructPlayerDeck {
        seat_index,
        output_cts,
    });

    table_events::emit_reconstruct_deck_submitted(object::id(table), seat_index);
    // 所有玩家提交后，标记为完成，由 tick 处理状态转换
    if (table.reconstruct_state.pending_players.length()==0) {
        on_complete_reconstruct(table);
    };
}


// ========== 提交 Reconstruct Deck ==========
public  fun submit_reconstruct_deck_verified(
    table: &mut Table,
    output_cards: vector<u8>,           // 重建后的牌组 (serialized ciphertexts, flat bytes)
    _swap_cards: vector<u8>,             // swap-out 牌 (serialized ciphertexts, flat bytes)
    _user_readable_cards: vector<u8>,    // 该玩家的可读牌 (serialized ciphertexts, flat bytes)
    _proof_bytes: vector<u8>,            // ReconstructProof (serialized)
    ctx: &mut TxContext,
) {
    assert!(table.reconstruct_state.phase == table_constants::reconstruct_phase_collecting(), EReconstructNotCollecting);

    let sender = ctx.sender();
    assert!(is_player_seated(&table.seats, sender), EPlayerNotSeated);

    let seat_index = find_seat_index(&table.seats, sender);
    assert!(is_in_list(&table.reconstruct_state.pending_players, seat_index), EReconstructAlreadySubmitted);

    // 反序列化
    let output_cts = zk_verifier::deserialize_ciphertexts(&output_cards);
    assert!(output_cts.length() == table.deck_state.plaintext.length(), EInvalidReconstructDeckSize);


    // 从 ReconstructState 读取明文牌点
    let mut card_points = vector[];
    let mut i = 0;
    while (i < table.deck_plaintext().length()) {
        card_points.push_back(bls12381::g1_from_bytes(&table.deck_plaintext()[i]));
        i = i + 1;
    };

    // 标记为已完成，存储该玩家的 output_cts
    remove_from_pending(&mut table.reconstruct_state.pending_players, seat_index);
    table.reconstruct_state.player_decks.push_back(ReconstructPlayerDeck {
        seat_index,
        output_cts,
    });

    table_events::emit_reconstruct_deck_submitted(object::id(table), seat_index);
    // 所有玩家提交后，标记为完成，由 tick 处理状态转换
    if (table.reconstruct_state.pending_players.length()==0) {
        on_complete_reconstruct(table);
    };
}

// ========== 下注操作 ==========
public  fun fold(table: &mut Table, seat_index: u64, ctx: &mut TxContext) {
    assert!(is_betting_round(table), EInvalidRoundState);
    assert!(is_player_turn(table, seat_index), ENotPlayerTurn);

    table.timestamps.betting_started_at = 0;  // will be set by tick for next player

    let seat = &mut table.seats[seat_index];
    assert!(is_seat_occupied(seat), ESeatEmpty);
    assert!(!seat.folded, EAlreadyFolded);
    assert!(seat.player == ctx.sender(), ENotOwner);

    seat.folded = true;
    seat.acted_this_round = true;

    if (table.betting_round.is_some()) {
        table.betting_round.borrow_mut().process_fold();
    };

    let active = count_active_players(&table.seats);
    if (active <= 1) {
        end_without_showdown(table);
    } else {
        advance_turn(table);
    };
    table_events::emit_player_folded(object::id(table), seat_index, table_events::fold_reason_manual(), table.round_state)
}

public  fun check(table: &mut Table, seat_index: u64, ctx: &mut TxContext) {
    assert!(is_betting_round(table), EInvalidRoundState);
    assert!(is_player_turn(table, seat_index), ENotPlayerTurn);

    table.timestamps.betting_started_at = 0;  // will be set by tick for next player

    let seat = &mut table.seats[seat_index];
    assert!(is_seat_occupied(seat), ESeatEmpty);
    assert!(seat.player == ctx.sender(), ENotOwner);
    // m1 修复：defense-in-depth，防止 folded/all_in 玩家行动
    assert!(!seat.folded, EAlreadyFolded);
    assert!(!seat.all_in, EAlreadyAllIn);

    if (table.betting_round.is_some()) {
        let round = table.betting_round.borrow();
        assert!(round.can_check(seat.bet), ECannotCheck);
        table.betting_round.borrow_mut().process_check(seat.bet);
    };

    seat.acted_this_round = true;
    advance_turn(table);
    table_events::emit_player_checked(object::id(table), seat_index, table.round_state)
}

public  fun call(table: &mut Table, seat_index: u64, ctx: &mut TxContext) {
    assert!(is_betting_round(table), EInvalidRoundState);
    assert!(is_player_turn(table, seat_index), ENotPlayerTurn);

    table.timestamps.betting_started_at = 0;  // will be set by tick for next player

    let seat = &mut table.seats[seat_index];
    assert!(is_seat_occupied(seat), ESeatEmpty);
    assert!(seat.player == ctx.sender(), ENotOwner);
    // m1 修复：defense-in-depth，防止 folded/all_in 玩家行动
    assert!(!seat.folded, EAlreadyFolded);
    assert!(!seat.all_in, EAlreadyAllIn);

    let mut call_amount = 0;
    if (table.betting_round.is_some()) {
        let round = table.betting_round.borrow_mut();
        call_amount = round.process_call(seat.bet, seat.stack);
        seat.stack = seat.stack - call_amount;
        seat.bet = seat.bet + call_amount;
        seat.total_bet = seat.total_bet + call_amount;
        if (seat.stack == 0) { seat.all_in = true };
    };

    let is_all_in = seat.stack == 0;
    seat.acted_this_round = true;
    advance_turn(table);
    table_events::emit_player_called(object::id(table), seat_index, call_amount, table.round_state);
    if (is_all_in && call_amount > 0) {
        table_events::emit_player_all_in(object::id(table), seat_index, 0, call_amount, table.round_state);
    };
}

public  fun raise(table: &mut Table, seat_index: u64, total_bet: u64, ctx: &mut TxContext) {
    assert!(is_betting_round(table), EInvalidRoundState);
    assert!(is_player_turn(table, seat_index), ENotPlayerTurn);

    table.timestamps.betting_started_at = 0;  // will be set by tick for next player

    let seat = &mut table.seats[seat_index];
    assert!(is_seat_occupied(seat), ESeatEmpty);
    assert!(seat.player == ctx.sender(), ENotOwner);
    // m1 修复：defense-in-depth，防止 folded/all_in 玩家行动
    assert!(!seat.folded, EAlreadyFolded);
    assert!(!seat.all_in, EAlreadyAllIn);

    let mut raise_amount = 0;
    if (table.betting_round.is_some()) {
        let round = table.betting_round.borrow_mut();
        raise_amount = round.process_raise(total_bet, seat_index, seat.bet, seat.stack);
        seat.stack = seat.stack - raise_amount;
        seat.bet = seat.bet + raise_amount;
        seat.total_bet = seat.total_bet + raise_amount;
        if (seat.stack == 0) { seat.all_in = true };
    };

    let is_all_in = seat.stack == 0;
    seat.acted_this_round = true;
    reset_other_players_acted(&mut table.seats, seat_index);
    advance_turn(table);
    table_events::emit_player_raised(object::id(table), seat_index, raise_amount, total_bet, table.round_state);
    if (is_all_in && raise_amount > 0) {
        table_events::emit_player_all_in(object::id(table), seat_index, 1, raise_amount, table.round_state);
    };
}

// ========== 结算 ==========
fun settle_hand(table: &mut Table) {
    assert!(table.round_state == table_constants::round_showdown(), EInvalidRoundState);
    assert!(table.reveal_token_state.reveal_phase == table_constants::reveal_phase_none(), EInvalidRevealPhaseState);

    // 优化: 单次遍历提取 bets/folded/all_in，避免三次循环
    let (bets, folded, all_in_flags) = extract_betting_state(&table.seats);
    let (main_pot, side_pots) = side_pot::calculate_side_pots(&bets, &folded, &all_in_flags);

    let mut all_winners = vector[];
    let main_winners = distribute_pot(table, main_pot, &folded);
    let mut mw = 0;
    while (mw < main_winners.length()) {
        if (!is_in_list(&all_winners, main_winners[mw])) {
            all_winners.push_back(main_winners[mw]);
        };
        mw = mw + 1;
    };

    let mut i = 0;
    while (i < side_pots.length()) {
        let sp = &side_pots[i];
        let side_winners = distribute_side_pot(table, sp, &folded);
        let mut sw = 0;
        while (sw < side_winners.length()) {
            if (!is_in_list(&all_winners, side_winners[sw])) {
                all_winners.push_back(side_winners[sw]);
            };
            sw = sw + 1;
        };
        i = i + 1;
    };

    let pot = table.pot;
    table_events::emit_hand_settled(object::id(table), pot, all_winners);

    // 验证 pot 分配：如有差额，容错处理而非 abort，避免桌子永久卡死
    let mut total_distributed = main_pot;
    let mut si = 0;
    while (si < side_pots.length()) {
        total_distributed = total_distributed + side_pots[si].amount();
        si = si + 1;
    };
    if (total_distributed < table.pot) {
        // 分配差额给所有未 fold 的活跃玩家
        let remaining = table.pot - total_distributed;
        let mut eligible = vector[];
        let mut e = 0;
        while (e < table.seats.length()) {
            if (is_seat_occupied(&table.seats[e]) && !folded[e] && !table.seats[e].is_waiting) {
                eligible.push_back(e);
            };
            e = e + 1;
        };
        let n = eligible.length();
        if (n > 0) {
            let share = remaining / n;
            let r = remaining % n;
            let mut i = 0;
            while (i < n) {
                let seat_id = eligible[i];
                let amount = share + if (i == 0) { r } else { 0 };
                table.seats[seat_id].stack = table.seats[seat_id].stack + amount;
                i = i + 1;
            };
        };
        // total_distributed > table.pot 不应发生；若发生则筹码已分配，无法撤回，仅记录
    };

    reset_for_next_hand(table);
    table.timestamps.hand_complete_at = 0;
}

// ========== 内部函数 ==========

fun is_player_seated(seats: &vector<Seat>, player: address): bool {
    let mut i = 0;
    while (i < seats.length()) {
        if (is_seat_occupied(&seats[i]) && seats[i].player == player) { return true };
        i = i + 1;
    };
    false
}

fun is_pk_registered(seats: &vector<Seat>, pk: &vector<u8>): bool {
    let mut i = 0;
    while (i < seats.length()) {
        if (is_seat_occupied(&seats[i]) && seats[i].pk == *pk) { return true };
        i = i + 1;
    };
    false
}

fun find_seat_index(seats: &vector<Seat>, player: address): u64 {
    let mut i = 0;
    while (i < seats.length()) {
        if (is_seat_occupied(&seats[i]) && seats[i].player == player) { return i };
        i = i + 1;
    };
    abort EPlayerNotSeated
}

/// 根据 card_index 找到手牌的牌主 seat_index
/// Preflop 手牌按 active_seats 顺序分配：active_seats[0] 的牌在 card_index [0,1]，active_seats[1] 在 [2,3]，...
fun find_hand_card_owner(table: &Table, card_index: u64): u64 {
    let active_seats = get_active_seat_indices(&table.seats);
    let hand_start = table.deck_state.cards_dealt - active_seats.length() * table_constants::cards_per_player();
    let offset = card_index - hand_start;
    let seat_offset = offset / table_constants::cards_per_player();
    active_seats[seat_offset]
}

/// 从 decrypted_cards 中查找指定 card_index 的部分解密密文
fun find_partial_ciphertext(decrypted_cards: &vector<DecryptedCard>, card_index: u64): vector<u8> {
    let mut i = 0;
    while (i < decrypted_cards.length()) {
        if (decrypted_cards[i].encrypted_card_index == card_index
            && decrypted_cards[i].ciphertext_bytes.length() > 0) {
            return decrypted_cards[i].ciphertext_bytes
        };
        i = i + 1;
    };
    vector[]
}

/// 将 decrypted_card 从部分解密密文更新为完全解密明文
fun update_decrypted_card_to_plaintext(
    decrypted_cards: &mut vector<DecryptedCard>,
    card_index: u64,
    plaintext_bytes: vector<u8>,
) {
    let mut i = 0;
    while (i < decrypted_cards.length()) {
        if (decrypted_cards[i].encrypted_card_index == card_index
            && decrypted_cards[i].ciphertext_bytes.length() > 0) {
            decrypted_cards[i].ciphertext_bytes = vector[];
            decrypted_cards[i].plaintext_bytes = plaintext_bytes;
        };
        i = i + 1;
    };
}

fun count_active_players(seats: &vector<Seat>): u64 {
    let mut count = 0;
    let mut i = 0;
    while (i < seats.length()) {
        if (is_seat_occupied(&seats[i]) && !seats[i].folded && !seats[i].is_waiting) { count = count + 1 };
        i = i + 1;
    };
    count
}

fun count_active_occupied(seats: &vector<Seat>): u64 {
    let mut count = 0;
    let mut i = 0;
    while (i < seats.length()) {
        if (is_seat_occupied(&seats[i]) && !seats[i].is_waiting) { count = count + 1 };
        i = i + 1;
    };
    count
}

fun get_active_seat_indices(seats: &vector<Seat>): vector<u64> {
    let mut result = vector[];
    let mut i = 0;
    while (i < seats.length()) {
        if (is_seat_occupied(&seats[i]) && !seats[i].is_waiting) { result.push_back(i) };
        i = i + 1;
    };
    result
}

fun get_pending_seat_indices(completed_players: &vector<u64>, seats: &vector<Seat>): vector<u64> {
    let mut result = vector[];
    let mut i = 0;
    while (i < seats.length()) {
        if (is_seat_occupied(&seats[i]) && !seats[i].is_waiting && !is_in_list(completed_players, i)) {
            result.push_back(i)
        };
        i = i + 1;
    };
    result
}

fun is_in_list(list: &vector<u64>, value: u64): bool {
    let mut i = 0;
    while (i < list.length()) {
        if (list[i] == value) { return true };
        i = i + 1;
    };
    false
}

fun remove_from_pending(list: &mut vector<u64>, value: u64) {
    let mut i = 0;
    while (i < list.length()) {
        if (list[i] == value) {
            list.remove(i);
            return
        };
        i = i + 1;
    };
}

fun move_button(table: &mut Table) {
    let mut next = table.button + 1;
    let mut count = 0;
    while (count < table.max_players) {
        if (next >= table.max_players) { next = 0 };
        if (is_seat_occupied(&table.seats[next])) {
            table.button = next;
            return
        };
        next = next + 1;
        count = count + 1;
    };
}

fun post_blinds(table: &mut Table) {
    let n = table.max_players;
    let active = count_active_occupied(&table.seats);
    let is_heads_up = active == 2;

    let sb_seat = if (is_heads_up) {
        table.button
    } else {
        find_next_active_seat(&table.seats, table.button, n)
    };
    let bb_seat = find_next_active_seat(&table.seats, sb_seat, n);

    // 小盲
    let sb_seat_ref = &mut table.seats[sb_seat];
    let sb_amount = if (sb_seat_ref.stack < table.small_blind) { sb_seat_ref.stack } else { table.small_blind };
    sb_seat_ref.stack = sb_seat_ref.stack - sb_amount;
    sb_seat_ref.bet = sb_amount;
    sb_seat_ref.total_bet = sb_amount;
    if (sb_seat_ref.stack == 0) { sb_seat_ref.all_in = true };

    // 大盲
    let bb_seat_ref = &mut table.seats[bb_seat];
    let bb_amount = if (bb_seat_ref.stack < table.big_blind) { bb_seat_ref.stack } else { table.big_blind };
    bb_seat_ref.stack = bb_seat_ref.stack - bb_amount;
    bb_seat_ref.bet = bb_amount;
    bb_seat_ref.total_bet = bb_amount;
    if (bb_seat_ref.stack == 0) { bb_seat_ref.all_in = true };

    // Pre-flop: first to act is after BB (UTG); heads-up: first to act is SB/button
    let first_to_act = if (is_heads_up) {
        sb_seat
    } else {
        find_next_active_seat(&table.seats, bb_seat, n)
    };
    set_current_turn(table, option::some(first_to_act));
    table_events::emit_blinds_posted(
        object::id(table),
        sb_seat, bb_seat,
        table.small_blind, table.big_blind,
        first_to_act,
    );
}

fun start_betting_round(table: &mut Table, is_preflop: bool) {
    let round = if (is_preflop) {
        betting::new_preflop(table.big_blind)
    } else {
        betting::new_postflop(table.big_blind)
    };
    table.betting_round = option::some(round);

    let mut i = 0;
    while (i < table.seats.length()) {
        let seat = &mut table.seats[i];
        seat.acted_this_round = false;
        if (!is_preflop) {
            seat.bet = 0;
        };
        i = i + 1;
    };

    if (!is_preflop) {
        // C5 修复：当所有活跃玩家已 all-in 时，find_next_active_seat 会 abort。
        // 此时下注轮立即完成，直接收集下注并推进到下一阶段。
        if (has_actionable_player(&table.seats)) {
            let first = find_next_active_seat(&table.seats, table.button, table.max_players);
            set_current_turn(table, option::some(first));
        } else {
            // 所有玩家 all-in，跳过下注轮
            collect_bets_to_pot(table);
            advance_round(table);
            return
        };
    } else {
        // Preflop：post_blinds 已设置 current_turn，但全员 all-in 时需跳过下注轮
        if (!has_actionable_player(&table.seats)) {
            set_current_turn(table, option::none());
            collect_bets_to_pot(table);
            advance_round(table);
            return
        };
    };

    let first_to_act = if (table.current_turn.is_some()) { *table.current_turn.borrow() } else { 0 };
    table_events::emit_betting_round_started(
        object::id(table),
        table.round_state,
        table.betting_round.borrow().current_bet(),
        table.betting_round.borrow().min_raise(),
        first_to_act,
        table.pot,
    );
}

fun is_betting_round(table: &Table): bool {
    table.betting_round.is_some() && (
        table.round_state == table_constants::round_preflop() ||
        table.round_state == table_constants::round_flop() ||
        table.round_state == table_constants::round_turn() ||
        table.round_state == table_constants::round_river()
    )
}

/// 是否处于进行中的游戏阶段（非等待）
public fun is_playing(table: &Table): bool {
    table.round_state != table_constants::round_waiting() ||
    table.shuffle_state.phase != table_constants::shuffle_phase_none() ||
    table.reveal_token_state.reveal_phase != table_constants::reveal_phase_none() ||
    table.reconstruct_state.phase != table_constants::reconstruct_phase_none()
}

fun can_leave_state(table: &Table): bool {
    table.round_state == table_constants::round_waiting() 
}

fun can_join_state(table: &Table): bool {
    table.round_state == table_constants::round_waiting() 
}


fun is_player_turn(table: &Table, seat_index: u64): bool {
    table.current_turn.is_some() && *table.current_turn.borrow() == seat_index
}

/// 设置 current_turn 并重置变化时间戳（由 tick 填充实际时间），同时发出事件
fun set_current_turn(table: &mut Table, turn: Option<u64>) {
    let old_turn = table.current_turn;
    table.current_turn = turn;
    table.timestamps.current_turn_changed_at = 0;
    table_events::emit_current_turn_changed(object::id(table), old_turn, turn, table.round_state);
}

fun advance_turn(table: &mut Table) {
    if (is_betting_complete(table)) {
        collect_bets_to_pot(table);
        advance_round(table);
        return
    };

    let current = *table.current_turn.borrow();
    let next = find_next_active_seat(&table.seats, current, table.max_players);
    set_current_turn(table, option::some(next));
}

fun is_betting_complete(table: &Table): bool {
    if (table.betting_round.is_none()) { return true };

    let round = table.betting_round.borrow();
    let current_bet = round.current_bet();
    let mut all_acted = true;
    let mut all_matched = true;

    let mut i = 0;
    while (i < table.seats.length()) {
        let seat = &table.seats[i];
        if (is_seat_occupied(seat) && !seat.folded && !seat.all_in && !seat.is_waiting) {
            if (!seat.acted_this_round) { all_acted = false };
            if (seat.bet < current_bet) { all_matched = false };
        };
        i = i + 1;
    };

    all_acted && all_matched
}

fun collect_bets_to_pot(table: &mut Table) {
    let mut collected_seats = vector[];
    let mut i = 0;
    while (i < table.seats.length()) {
        if (table.seats[i].bet > 0) {
            table.pot = table.pot + table.seats[i].bet;
            collected_seats.push_back(i);
        };
        table.seats[i].bet = 0;
        i = i + 1;
    };
    table_events::emit_pot_collected(
        object::id(table),
        table.round_state,
        table.pot,
        collected_seats,
    );
}

fun advance_round(table: &mut Table) {
    let from_round = table.round_state;
    table.betting_round = option::none();
    set_current_turn(table, option::none());

    // 下注轮结束后进入对应的 Reveal 阶段
    if (from_round == table_constants::round_preflop()) {
        table.round_state = table_constants::round_flop();
        table.timestamps.reveal_started_at = 0;
        start_community_reveal_phase(table, 3,table_constants::reveal_phase_flop());
    } else if (from_round == table_constants::round_flop()) {
        table.round_state = table_constants::round_turn();
        table.timestamps.reveal_started_at = 0;
        start_community_reveal_phase(table, 1,table_constants::reveal_phase_turn());
    } else if (from_round == table_constants::round_turn()) {
        table.round_state = table_constants::round_river();
        table.timestamps.reveal_started_at = 0;
        start_community_reveal_phase(table, 1,table_constants::reveal_phase_river());
    } else if (from_round == table_constants::round_river()) {
        table.round_state = table_constants::round_showdown();
        table.timestamps.showdown_at = 0;
        start_showdown_reveal_phase(table);
    };

    table_events::emit_round_advanced(
        object::id(table),
        from_round,
        table.round_state,
        table.pot,
        table.community_cards.length(),
    );
}



fun end_without_showdown(table: &mut Table) {
    collect_bets_to_pot(table);

    // 使用 MAX_U64 作为无效标记，避免默认 seat 0 错误分配底池
    let mut winner_idx = 0xFFFFFFFFFFFFFFFF;
    let mut i = 0;
    while (i < table.seats.length()) {
        if (is_seat_occupied(&table.seats[i]) && !table.seats[i].folded && !table.seats[i].is_waiting) {
            winner_idx = i;
            break
        };
        i = i + 1;
    };
    assert!(winner_idx != 0xFFFFFFFFFFFFFFFF, ENotEnoughPlayers);

    let pot = table.pot;
    let winner_player = table.seats[winner_idx].player;
    table.seats[winner_idx].stack = table.seats[winner_idx].stack + pot;
    table.timestamps.hand_complete_at = 0;  // will be set by tick
    reset_for_next_hand(table);
    table_events::emit_hand_ended_without_showdown(
        object::id(table),
        winner_idx,
        winner_player,
        pot,
    );
}

// ========== 洗牌推进 ==========

fun advance_shuffle(table: &mut Table) {
    if (table.shuffle_state.phase != table_constants::shuffle_phase_reconstruct() && table.shuffle_state.phase != table_constants::shuffle_phase_before_preflop()) {
        return
    };
    // 检查活跃人数是否足够
    if (table.shuffle_state.pending_players.length() == 0 ) {
        // 所有玩家完成洗牌
        let curr_phase = table.shuffle_state.phase;
        on_shuffle_complete(table);
        if (curr_phase == table_constants::shuffle_phase_before_preflop()) {
            table.timestamps.reveal_started_at = 0;
            table.round_state = table_constants::round_preflop();
            start_preflop_reveal_phase(table);
        }else if (curr_phase == table_constants::shuffle_phase_reconstruct()) {
            // reconstruct 后牌组已重新洗牌
            // reconstruct_deck 的 ZK 约束：owner 把已解密的牌（手牌+公共牌）替换成 identity card
            // 因此保留旧公共牌条目（plaintext_bytes 非空），明文不会重复
            // 保留旧手牌条目（ciphertext_bytes 非空），用于 showdown 完成解密
            table.reconstruct_state = empty_reconstruct_state();
            table.reveal_token_state = empty_reveal_token_state();
            table.timestamps.reveal_started_at = 0;
            // 下注轮结束后进入对应的 Reveal 阶段
            if (table.round_state == table_constants::round_preflop()) {
                start_preflop_reveal_phase(table);
            } else if (table.round_state == table_constants::round_flop()) {
                // 发剩余的公共牌（FLOP 需3张，减去已解密未写入的数量）
                let already_dealt = count_pending_community_cards(table);
                start_community_reveal_phase(table, 3 - already_dealt, table_constants::reveal_phase_flop());
            } else if (table.round_state == table_constants::round_turn()) {
                let already_dealt = count_pending_community_cards(table);
                start_community_reveal_phase(table, 1 - already_dealt, table_constants::reveal_phase_turn());
            } else if (table.round_state == table_constants::round_river()) {
                let already_dealt = count_pending_community_cards(table);
                start_community_reveal_phase(table, 1 - already_dealt, table_constants::reveal_phase_river());
            } else if (table.round_state == table_constants::round_showdown()) {
                table.timestamps.showdown_at = 0;
                start_showdown_reveal_phase(table);
            };
        }
    } else if (table.shuffle_state.pending_players.length() > 0) {
        // 设置下一个洗牌者
        table.shuffle_state.current_shuffler = option::some(table.shuffle_state.pending_players[0]);
        table.timestamps.shuffle_started_at = 0;  // will be set by tick when relayer calls
        table_events::emit_shuffle_turn(
            object::id(table),
            table.shuffle_state.pending_players[0],
            table.shuffle_state.pending_players.length(),
            table.shuffle_state.completed_players.length(),
        );
    };
}

// ========== Reveal Phase 启动 ==========

fun start_preflop_reveal_phase(table: &mut Table) {
    // 发牌：每个玩家 2 张牌，从 cards_dealt 开始
    // 手牌的 pending_players 排除牌主（牌主不需要为自己的牌提交 reveal token）
    let mut card_index = table.deck_state.cards_dealt;
    let mut assignments = vector[];
    let active_seats = get_active_seat_indices(&table.seats);

    let mut s = 0;
    while (s < active_seats.length()) {
        let seat_idx = active_seats[s];
        // 优化: 每个玩家只构建一次 pending 列表（排除牌主），复用给该玩家的所有手牌
        let mut pending = vector[];
        let mut a = 0;
        while (a < active_seats.length()) {
            if (active_seats[a] != seat_idx) {
                pending.push_back(active_seats[a]);
            };
            a = a + 1;
        };
        let mut c = 0;
        while (c < table_constants::cards_per_player()) {
            // 复制 pending（vector<bool> 有 copy）
            let pending_copy = copy pending;
            assignments.push_back(RevealAssignment {
                encrypted_card_index: card_index,
                pending_players: pending_copy,
                reveal_tokens: vector[],
                decrypted: false,
            });
            card_index = card_index + 1;
            c = c + 1;
        };
        s = s + 1;
    };

    // 更新已发牌数量
    table.deck_state.cards_dealt = card_index;

    table.reveal_token_state = RevealTokenState {
        reveal_phase: table_constants::reveal_phase_preflop(),
        assignments,
    };
    table_events::emit_reveal_phase(object::id(table), table_constants::reveal_phase_preflop());
}

fun start_community_reveal_phase(table: &mut Table, count: u64, phase: u8) {
    // 公共牌从 cards_dealt 开始
    let start_index = table.deck_state.cards_dealt;
    let mut assignments = vector[];
    let active_seats = get_active_seat_indices(&table.seats);

    let mut c = 0;
    while (c < count) {
        assignments.push_back(RevealAssignment {
            encrypted_card_index: start_index + c,
            pending_players: active_seats,
            reveal_tokens: vector[],
            decrypted: false,
        });
        c = c + 1;
    };

    // 更新已发牌数量
    table.deck_state.cards_dealt = start_index + count;

    table.reveal_token_state = RevealTokenState {
        reveal_phase: phase,
        assignments,
    };
    table_events::emit_reveal_phase(object::id(table), phase);
}

fun start_showdown_reveal_phase(table: &mut Table) {
    // Showdown: 需要揭示未 fold 玩家的手牌
    // 从 decrypted_cards 中找到部分解密的手牌密文，只要求牌主提交 reveal token
    let mut assignments = vector[];

    let mut s = 0;
    while (s < table.seats.length()) {
        let seat = &table.seats[s];
        if (is_seat_occupied(seat) && !seat.folded && !seat.is_waiting) {
            // 在 decrypted_cards 中查找属于该玩家的手牌（部分解密密文）
            let mut c = 0;
            while (c < table.deck_state.decrypted_cards.length()) {
                let dc = &table.deck_state.decrypted_cards[c];
                if (dc.owner_seat_index == s && dc.ciphertext_bytes.length() > 0) {
                    // 只有牌主需要提交 reveal token
                    let pending = vector[s];
                    assignments.push_back(RevealAssignment {
                        encrypted_card_index: dc.encrypted_card_index,
                        pending_players: pending,
                        reveal_tokens: vector[],
                        decrypted: false,
                    });
                };
                c = c + 1;
            };
        };
        s = s + 1;
    };

    table.reveal_token_state = RevealTokenState {
        reveal_phase: table_constants::reveal_phase_showdown(),
        assignments,
    };
    table_events::emit_reveal_phase(object::id(table), table_constants::reveal_phase_showdown());
}

fun create_reveal_assignments_for_cards(table: &mut Table, count: u64): vector<RevealAssignment> {
    // 从 cards_dealt 开始分配新牌（与发牌逻辑一致）
    let mut assignments = vector[];
    let active_seats = get_active_seat_indices(&table.seats);
    let start_index = table.deck_state.cards_dealt;
    // 校验牌组边界，避免多次 redeal 后越界
    assert!(start_index + count <= table.deck_state.encrypted.length(), EInvalidCardIndex);
    let mut i = 0;
    while (i < count) {
        assignments.push_back(RevealAssignment {
            encrypted_card_index: start_index + i,
            pending_players: active_seats,
            reveal_tokens: vector[],
            decrypted: false,
        });
        i = i + 1;
    };
    // 更新已发牌数量
    table.deck_state.cards_dealt = start_index + count;
    assignments
}

// ========== Reveal Phase 完成检查 ==========

fun check_reveal_phase_complete(table: &mut Table) {
    let mut all_decrypted = true;
    let mut i = 0;
    while (i < table.reveal_token_state.assignments.length()) {
        if (!table.reveal_token_state.assignments[i].decrypted) {
            all_decrypted = false;
        };
        i = i + 1;
    };

    if (!all_decrypted) { return };

    // 所有牌已解密，根据当前阶段推进
    let phase = table.reveal_token_state.reveal_phase;

    table_events::emit_reveal_phase_complete(object::id(table), phase);

    // 先清空 reveal state，再触发状态转换（settle_hand 等函数会检查 reveal phase == none）
    table.reveal_token_state = empty_reveal_token_state();

    if (phase == table_constants::reveal_phase_preflop()) {
        // Preflop 手牌仅部分解密（其他玩家提交了 reveal token，牌主尚未提交）
        // 不写入 seat.hand，等 showdown 时牌主提交后才能得到明文
        // 进入 PreFlop 下注
        table.timestamps.betting_started_at = 0;
        post_blinds(table);
        start_betting_round(table, true);
    } else if (phase == table_constants::reveal_phase_flop()) {
        // 公共牌解密完成，写入 community_cards
        // round_state 已在 advance_round 中设为 table_constants::round_flop()
        write_decrypted_cards_to_community(table);
        table.timestamps.betting_started_at = 0;
        start_betting_round(table, false);
    } else if (phase == table_constants::reveal_phase_turn()) {
        // round_state 已在 advance_round 中设为 table_constants::round_turn()
        write_decrypted_cards_to_community(table);
        table.timestamps.betting_started_at = 0;
        start_betting_round(table, false);
    } else if (phase == table_constants::reveal_phase_river()) {
        // round_state 已在 advance_round 中设为 table_constants::round_river()
        write_decrypted_cards_to_community(table);
        table.timestamps.betting_started_at = 0;
        start_betting_round(table, false);
    } else if (phase == table_constants::reveal_phase_showdown()) {
        // 摊牌牌面解密完成，将手牌写入 seat.hand
        // round_state 已在 advance_round 中设为 table_constants::round_showdown()
        write_decrypted_cards_to_hands(table);
        table.timestamps.showdown_at = 0;
        settle_hand(table);
    };
}

// ========== 解密牌写入 ==========

/// 统计 decrypted_cards 中已解密但未写入 community_cards 的公共牌数量
/// 用于 reconstruct 后计算还需发多少张公共牌
fun count_pending_community_cards(table: &Table): u64 {
    let mut count = 0;
    let mut i = 0;
    while (i < table.deck_state.decrypted_cards.length()) {
        let dc = &table.deck_state.decrypted_cards[i];
        if (dc.plaintext_bytes.length() > 0 && dc.owner_seat_index == 0xFFFFFFFFFFFFFFFF) {
            count = count + 1;
        };
        i = i + 1;
    };
    count
}

/// 将 decrypted_cards 中完全解密的公共牌写入 table.community_cards
/// 处理后清除 plaintext_bytes，避免后续阶段重复写入
fun write_decrypted_cards_to_community(table: &mut Table) {
    let mut card_indices = vector[];
    let mut card_ranks = vector[];
    let mut card_suits = vector[];
    let mut processed_indices = vector[];
    let mut i = 0;
    while (i < table.deck_state.decrypted_cards.length()) {
        let dc = &table.deck_state.decrypted_cards[i];
        // 只处理完全解密的公共牌（owner_seat_index 为 MAX_U64 且有 plaintext_bytes）
        if (dc.plaintext_bytes.length() > 0 && dc.owner_seat_index == 0xFFFFFFFFFFFFFFFF) {
            let playing_card = plaintext_to_playing_card(&table.deck_state.plaintext, &dc.plaintext_bytes);
            let card = card::new(playing_card_suit_to_card_suit(card_suit(&playing_card)), card_rank(&playing_card));
            table.community_cards.push_back(card);
            card_indices.push_back(dc.encrypted_card_index);
            card_ranks.push_back(card_rank(&playing_card));
            card_suits.push_back(card_suit(&playing_card));
            processed_indices.push_back(i);
        };
        i = i + 1;
    };
    // 清除已处理公共牌的 plaintext_bytes，避免下次调用重复写入
    let mut p = 0;
    while (p < processed_indices.length()) {
        let idx = processed_indices[p];
        table.deck_state.decrypted_cards[idx].plaintext_bytes = vector[];
        p = p + 1;
    };
    if (card_indices.length() > 0) {
        table_events::emit_community_card_revealed(
            object::id(table),
            table.reveal_token_state.reveal_phase,
            card_indices,
            card_ranks,
            card_suits,
        );
    };
}

/// 将 decrypted_cards 中完全解密的手牌写入对应 seat.hand（showdown 阶段使用）
fun write_decrypted_cards_to_hands(table: &mut Table) {
    // 按座位遍历，收集每位玩家的手牌并写入，同时对非弃牌玩家发射 ShowdownHoleCardsRevealed 事件
    let num_seats = table.seats.length();
    let mut seat = 0;
    while (seat < num_seats) {
        let mut card_indices = vector[];
        let mut card_ranks = vector[];
        let mut card_suits = vector[];

        let mut i = 0;
        while (i < table.deck_state.decrypted_cards.length()) {
            let dc = &table.deck_state.decrypted_cards[i];
            // 只处理完全解密的手牌（有 plaintext_bytes 且 owner_seat_index 为当前座位）
            if (dc.plaintext_bytes.length() > 0 && dc.owner_seat_index == seat) {
                let playing_card = plaintext_to_playing_card(&table.deck_state.plaintext, &dc.plaintext_bytes);
                let card = card::new(playing_card_suit_to_card_suit(card_suit(&playing_card)), card_rank(&playing_card));
                table.seats[seat].hand.push_back(card);
                card_indices.push_back(dc.encrypted_card_index);
                card_ranks.push_back(card_rank(&playing_card));
                card_suits.push_back(card_suit(&playing_card));
            };
            i = i + 1;
        };

        // 只对非弃牌玩家发射摊牌手牌揭示事件
        if (card_indices.length() > 0 && !table.seats[seat].folded) {
            table_events::emit_showdown_hole_cards_revealed(
                object::id(table),
                seat,
                table.seats[seat].player,
                card_indices,
                card_ranks,
                card_suits,
            );
        };

        seat = seat + 1;
    };
}

// ========== 结算相关 ==========

fun distribute_pot(table: &mut Table, pot_amount: u64, folded: &vector<bool>): vector<u64> {
    if (pot_amount == 0) { return vector[] };

    let (winners, best_rank) = find_winners(&table.seats, &table.community_cards, folded);
    // 将 HandRank 序列化为 u64 用于事件传递（None 表示无摊牌直接获胜）
    let hand_rank_u64: Option<u64> = if (best_rank.is_some()) {
        option::some(hand_evaluator::to_u64(best_rank.borrow()))
    } else {
        option::none()
    };

    let winner_count = winners.length();
    if (winner_count > 0) {
        let share = pot_amount / winner_count;
        let remainder = pot_amount % winner_count;
        // M-P2: 余数分配策略——remainder 统一分配给 winners[0]。
        // 这是有意设计：winners[0] 是首个发现的最优手牌持有者（按座位顺序），
        // 余数金额极小（< winner_count，通常 < 9 chip），不影响公平性。
        // 替代方案（按座位顺序/随机分配）会增加复杂度而无实质收益。
        let mut w = 0;
        while (w < winner_count) {
            let idx = winners[w];
            let amount = share + if (w == 0) { remainder } else { 0 };
            table.seats[idx].stack = table.seats[idx].stack + amount;
            table_events::emit_winner_awarded(
                object::id(table),
                idx,
                table.seats[idx].player,
                amount,
                0,
                hand_rank_u64,
            );
            w = w + 1;
        };
    } else {
        // Fallback: 无赢家时将筹码均分给所有未 fold 的活跃玩家
        // M9 修复：排除 waiting 玩家（未参与本局，未下注）
        let mut eligible_seats = vector[];
        let mut e = 0;
        while (e < table.seats.length()) {
            if (is_seat_occupied(&table.seats[e]) && !folded[e] && !table.seats[e].is_waiting) {
                eligible_seats.push_back(e);
            };
            e = e + 1;
        };
        let n = eligible_seats.length();
        if (n > 0) {
            let share = pot_amount / n;
            let remainder = pot_amount % n;
            let mut i = 0;
            while (i < n) {
                let seat_id = eligible_seats[i];
                let amount = share + if (i == 0) { remainder } else { 0 };
                table.seats[seat_id].stack = table.seats[seat_id].stack + amount;
                i = i + 1;
            };
        };
    };
    winners
}

fun distribute_side_pot(table: &mut Table, sp: &SidePot, folded: &vector<bool>): vector<u64> {
    let eligible = sp.eligible_seats();
    let pot_amount = sp.amount();

    let (winners, best_rank) = find_winners_in_eligible(
        &table.seats, &table.community_cards, folded, eligible
    );
    // 将 HandRank 序列化为 u64 用于事件传递（None 表示无摊牌直接获胜）
    let hand_rank_u64: Option<u64> = if (best_rank.is_some()) {
        option::some(hand_evaluator::to_u64(best_rank.borrow()))
    } else {
        option::none()
    };

    let winner_count = winners.length();
    if (winner_count > 0) {
        let share = pot_amount / winner_count;
        let remainder = pot_amount % winner_count;
        let mut w = 0;
        while (w < winner_count) {
            let idx = winners[w];
            let amount = share + if (w == 0) { remainder } else { 0 };
            table.seats[idx].stack = table.seats[idx].stack + amount;
            table_events::emit_winner_awarded(
                object::id(table),
                idx,
                table.seats[idx].player,
                amount,
                1,
                hand_rank_u64,
            );
            w = w + 1;
        };
    } else {
        // Fallback: 无赢家时将筹码均分给该 side pot 中未 fold 的 eligible 玩家
        let mut eligible_unfolded = vector[];
        let mut e = 0;
        while (e < eligible.length()) {
            let seat_id = eligible[e];
            if (is_seat_occupied(&table.seats[seat_id]) && !folded[seat_id]) {
                eligible_unfolded.push_back(seat_id);
            };
            e = e + 1;
        };
        let n = eligible_unfolded.length();
        if (n > 0) {
            let share = pot_amount / n;
            let remainder = pot_amount % n;
            let mut i = 0;
            while (i < n) {
                let seat_id = eligible_unfolded[i];
                let amount = share + if (i == 0) { remainder } else { 0 };
                table.seats[seat_id].stack = table.seats[seat_id].stack + amount;
                i = i + 1;
            };
        };
    };
    winners
}

fun find_winners(
    seats: &vector<Seat>,
    community_cards: &vector<Card>,
    folded: &vector<bool>,
): (vector<u64>, Option<HandRank>) {
    let mut best_rank = option::none<HandRank>();
    let mut winners = vector[];

    let mut i = 0;
    while (i < seats.length()) {
        let seat = &seats[i];
        if (is_seat_occupied(seat) && !folded[i] && seat.total_bet > 0 && seat.hand.length() == table_constants::cards_per_player()) {
            let all_cards = combine_cards(&seat.hand, community_cards);
            // M-P5: best_hand 断言 cards.length() == 7，这里必须用 == 7 而非 >= 5
            if (all_cards.length() == 7) {
                let rank = hand_evaluator::best_hand(&all_cards);
                if (best_rank.is_none()) {
                    best_rank = option::some(rank);
                    winners.push_back(i);
                } else {
                    let cmp = hand_evaluator::compare(&rank, best_rank.borrow());
                    if (cmp == 2) {
                        best_rank = option::some(rank);
                        winners = vector[i];
                    } else if (cmp == 1) {
                        winners.push_back(i);
                    };
                };
            };
        };
        i = i + 1;
    };
    (winners, best_rank)
}

fun find_winners_in_eligible(
    seats: &vector<Seat>,
    community_cards: &vector<Card>,
    folded: &vector<bool>,
    eligible: &vector<u64>,
): (vector<u64>, Option<HandRank>) {
    let mut best_rank = option::none<HandRank>();
    let mut winners = vector[];

    let mut i = 0;
    while (i < eligible.length()) {
        let idx = eligible[i];
        let seat = &seats[idx];
        if (is_seat_occupied(seat) && !folded[idx] && seat.hand.length() == table_constants::cards_per_player()) {
            let all_cards = combine_cards(&seat.hand, community_cards);
            // M-P5: best_hand 断言 cards.length() == 7，这里必须用 == 7 而非 >= 5
            if (all_cards.length() == 7) {
                let rank = hand_evaluator::best_hand(&all_cards);
                if (best_rank.is_none()) {
                    best_rank = option::some(rank);
                    winners.push_back(idx);
                } else {
                    let cmp = hand_evaluator::compare(&rank, best_rank.borrow());
                    if (cmp == 2) {
                        best_rank = option::some(rank);
                        winners = vector[idx];
                    } else if (cmp == 1) {
                        winners.push_back(idx);
                    };
                };
            };
        };
        i = i + 1;
    };
    (winners, best_rank)
}

fun combine_cards(hand: &vector<Card>, community: &vector<Card>): vector<Card> {
    let mut all = vector[];
    let mut i = 0;
    while (i < hand.length()) {
        all.push_back(hand[i]);
        i = i + 1;
    };
    let mut j = 0;
    while (j < community.length()) {
        all.push_back(community[j]);
        j = j + 1;
    };
    all
}

// 优化: 合并三个 extract 函数为单次遍历
fun extract_betting_state(seats: &vector<Seat>): (vector<u64>, vector<bool>, vector<bool>) {
    let mut bets = vector[];
    let mut folded = vector[];
    let mut all_in_flags = vector[];
    let mut i = 0;
    while (i < seats.length()) {
        let seat = &seats[i];
        // bets: player != @0x0 的座位（活跃或被踢）都返回 total_bet
        let bet = if (seat.player != @0x0) { seat.total_bet } else { 0 };
        bets.push_back(bet);
        // folded: 未占座（包括中途离开）都视为 folded
        folded.push_back(!is_seat_occupied(seat) || seat.folded);
        // all_in: 只有活跃座位的座位才可能 all_in
        all_in_flags.push_back(is_seat_occupied(seat) && seat.all_in);
        i = i + 1;
    };
    (bets, folded, all_in_flags)
}

fun find_next_active_seat(seats: &vector<Seat>, from: u64, max: u64): u64 {
    let mut i = from + 1;
    let mut count = 0;
    while (count < max) {
        if (i >= max) { i = 0 };
        let seat = &seats[i];
        // 必须排除 is_waiting 玩家，他们不参与本局
        if (is_seat_occupied(seat) && !seat.folded && !seat.all_in && !seat.is_waiting) {
            return i
        };
        i = i + 1;
        count = count + 1;
    };
    abort ENotEnoughPlayers
}

/// C5 修复：检查是否存在可行动的玩家（非 fold、非 all_in、非 waiting）
fun has_actionable_player(seats: &vector<Seat>): bool {
    let mut i = 0;
    while (i < seats.length()) {
        let seat = &seats[i];
        if (is_seat_occupied(seat) && !seat.folded && !seat.all_in && !seat.is_waiting) {
            return true
        };
        i = i + 1;
    };
    false
}


fun reset_other_players_acted(seats: &mut vector<Seat>, raiser_index: u64) {
    let mut i = 0;
    while (i < seats.length()) {
        // 只重置未 fold 且未 all_in 的玩家
        if (i != raiser_index && is_seat_occupied(&seats[i]) && !seats[i].folded && !seats[i].all_in && !seats[i].is_waiting) {
            seats[i].acted_this_round = false;
        };
        i = i + 1;
    };
}

// ========== Tick 辅助函数 ==========

fun do_fold(table: &mut Table, seat_index: u64) {
    let seat = &mut table.seats[seat_index];
    assert!(is_seat_occupied(seat), ESeatEmpty);
    assert!(!seat.folded, EAlreadyFolded);

    seat.folded = true;
    seat.acted_this_round = true;
    table.timestamps.betting_started_at = 0;  // reset for next player

    if (table.betting_round.is_some()) {
        table.betting_round.borrow_mut().process_fold();
    };

    let active = count_active_players(&table.seats);
    if (active <= 1) {
        end_without_showdown(table);
    } else {
        advance_turn(table);
    };
}

fun reset_for_next_hand(table: &mut Table) {
    // Reset all seats' hand state
    let mut i = 0;
    while (i < table.seats.length()) {
        let seat = &mut table.seats[i];
        seat.hand = vector[];
        seat.bet = 0;
        seat.total_bet = 0;
        seat.folded = false;
        seat.all_in = false;
        seat.acted_this_round = false;
        if (seat.is_waiting){
            let new_aggregated_pk = table_serialization::add_pk_to_aggregated(&table.deck_state.aggregated_pk, &seat.pk);
            table.deck_state.aggregated_pk = new_aggregated_pk;
        };
        seat.is_waiting = false;
        seat.left_during_hand = false;
        i = i + 1;
    };

    // 清理筹码为 0 的玩家：从 aggregated_pk 移除其公钥，重置座位，发出 PlayerLeft 事件
    // 必须在上方 waiting 玩家 pk 合并之后执行，确保所有活跃玩家的 pk 都已在 aggregated_pk 中
    // 注意：被踢玩家 (left_during_hand) 在上方第一轮循环中已被重置 left_during_hand=false，
    // 且 kick_player_internal 已设 stack=0、pk=[]，因此此处 is_seat_occupied 返回 true &&
    // stack==0 会被正确清理，修复了之前 occupied=false 导致的僵尸座位问题
    let mut j = 0;
    while (j < table.seats.length()) {
        if (is_seat_occupied(&table.seats[j]) && table.seats[j].stack == 0) {
            let pk = table.seats[j].pk;
            let player = table.seats[j].player;
            if (pk.length() > 0) {
                table.deck_state.aggregated_pk = table_serialization::remove_pk_from_aggregated(
                    &table.deck_state.aggregated_pk, &pk);
            };
            reset_seat(&mut table.seats[j]);
            table_events::emit_player_left(object::id(table), j, player);
        };
        j = j + 1;
    };

    // 无活跃玩家时，重置 aggregated_pk 为空，避免残留 identity bytes
    // （所有玩家被踢出后 remove_pk_from_aggregated 会将 aggregated_pk 变为 identity，
    //  而非初始的 vector[]，导致后续 add_pk_to_aggregated 走 g1_from_bytes 分支而非 g1_identity 分支）
    if (count_active_occupied(&table.seats) == 0) {
        table.deck_state.aggregated_pk = vector[];
    };

    table.pot = 0;
    table.side_pots = vector[];
    table.community_cards = vector[];
    table.betting_round = option::none();
    set_current_turn(table, option::none());
    table.round_state = table_constants::round_waiting();
    table.deck_state.encrypted = vector[];
    table.deck_state.cards_dealt = 0;
    table.deck_state.decrypted_cards = vector[];
    table.shuffle_state = empty_shuffle_state();
    table.reveal_token_state = empty_reveal_token_state();
    table.reconstruct_state = empty_reconstruct_state();
    table.timestamps = Timestamps {
        ready_at: 0,
        shuffle_started_at: 0,
        reveal_started_at: 0,
        betting_started_at: 0,
        reconstruct_started_at: 0,
        showdown_at: 0,
        hand_complete_at: 0,
        current_turn_changed_at: 0,
    };
    set_initial_encrypted_deck(table);
    // shuffle_state 已通过 empty_shuffle_state() 重置为 NONE，
    // join_and_shuffle 通过 can_join_state() (round_state == WAITING) 校验，无需额外 phase 标记
}



fun kick_player_internal(table: &mut Table, seat_index: u64, reason: u8, ctx: &mut TxContext) {
    let seat = &mut table.seats[seat_index];
    assert!(is_seat_occupied(seat), ESeatEmpty);

    let pk = seat.pk;
    let player = seat.player;
    // 只退 stack, total_bet 不退
    let refund_amount = seat.stack;
    // 只加当前轮未收取的下注到 pot（前几轮已通过 collect_bets_to_pot 收取）
    table.pot = table.pot + seat.bet;
    // waiting 玩家的 pk 未加入 aggregated_pk，踢出时不应移除
    let was_waiting = seat.is_waiting;
    let is_current_shuffler = table.shuffle_state.current_shuffler.is_some() &&
        *table.shuffle_state.current_shuffler.borrow() == seat_index;
    let is_current_turn = table.current_turn.is_some() &&
        *table.current_turn.borrow() == seat_index;

    // Mark seat as left_during_hand, but keep player/total_bet for side pot / refund
    // occupied 判断已改为 player != @0x0 && !left_during_hand，无需再设 occupied
    seat.stack = 0;
    seat.hand = vector[];
    seat.bet = 0;
    // total_bet 保留不清零，供 settle_hand 的 side pot 计算
    seat.left_during_hand = true;
    seat.folded = true;  // 标记为 folded，不能赢
    seat.all_in = false;
    seat.acted_this_round = false;
    seat.is_waiting = false;  // 必须重置，避免 reset_for_next_hand 用空 pk 调用 add_pk_to_aggregated
    seat.pk = vector[];
    
    // Update aggregated PK: 仅当玩家非 waiting 时才移除（waiting 玩家 pk 未加入过）
    if (pk.length() > 0 && !was_waiting) {
        table.deck_state.aggregated_pk = table_serialization::remove_pk_from_aggregated(&table.deck_state.aggregated_pk, &pk);
    };

    // 退还 stack：将 stack chips 兑换回 SUI 并转给玩家
    if (refund_amount > 0) {
        refund_sui_to_player(table, player, refund_amount, ctx);
        table_events::emit_player_refund(object::id(table), seat_index, player, refund_amount, table_events::refund_type_stack_only());
    };

    // Remove from shuffle state
    remove_from_pending(&mut table.shuffle_state.pending_players, seat_index);
    remove_from_pending(&mut table.shuffle_state.completed_players, seat_index);

    // Remove from reveal token state
    let mut a = 0;
    while (a < table.reveal_token_state.assignments.length()) {
        remove_from_pending(&mut table.reveal_token_state.assignments[a].pending_players, seat_index);
        a = a + 1;
    };

    // Remove from reconstruct state
    remove_from_pending(&mut table.reconstruct_state.pending_players, seat_index);

    // If kicked player was current shuffler, advance
    if (is_current_shuffler) {
        table.shuffle_state.current_shuffler = option::none();
        advance_shuffle(table);
    };

    // If kicked player was current turn, advance to next player
    if (is_current_turn && is_betting_round(table)) {
        let active = count_active_players(&table.seats);
        if (active <= 1) {
            end_without_showdown(table);
        } else {
            // 复用 advance_turn，内部会检查 is_betting_complete 并正确推进
            advance_turn(table);
        };
    };
    table_events::emit_player_kicked(object::id(table), seat_index, player, reason);

    // Check if enough players remain (用 count_active_players 排除已 fold 玩家)
    if (count_active_players(&table.seats) < table_constants::min_players_to_start()) {
        reset_for_next_hand(table);
    };
}

// ========== 访问器 ==========
public fun table_id(table: &Table): ID { object::id(table) }
public fun name(table: &Table): &String { &table.name }
public fun max_players(table: &Table): u64 { table.max_players }
public fun round_state(table: &Table): u8 { table.round_state }
public fun pot(table: &Table): u64 { table.pot }
public fun side_pots_count(table: &Table): u64 { table.side_pots.length() }
public fun community_cards(table: &Table): &vector<Card> { &table.community_cards }
public fun community_cards_count(table: &Table): u64 { table.community_cards.length() }
public fun current_turn(table: &Table): Option<u64> { table.current_turn }
public fun active_count(table: &Table): u64 { count_active_occupied(&table.seats) }
public fun button(table: &Table): u64 { table.button }
public fun small_blind(table: &Table): u64 { table.small_blind }
public fun big_blind(table: &Table): u64 { table.big_blind }

public fun seat_player(table: &Table, index: u64): address { table.seats[index].player }
public fun seat_stack(table: &Table, index: u64): u64 { table.seats[index].stack }
public fun seat_bet(table: &Table, index: u64): u64 { table.seats[index].bet }
public fun seat_total_bet(table: &Table, index: u64): u64 { table.seats[index].total_bet }
public fun seat_folded(table: &Table, index: u64): bool { table.seats[index].folded }
public fun seat_all_in(table: &Table, index: u64): bool { table.seats[index].all_in }
public fun seat_hand(table: &Table, index: u64): &vector<Card> { &table.seats[index].hand }
public fun seat_occupied(table: &Table, index: u64): bool { is_seat_occupied(&table.seats[index]) }
public fun seat_pk(table: &Table, index: u64): &vector<u8> { &table.seats[index].pk }

public fun deck_encrypted(table: &Table): &vector<ElGamalCiphertext> { &table.deck_state.encrypted }
public fun deck_size(table: &Table): u64 { table.deck_state.encrypted.length() }
public fun aggregated_pk(table: &Table): &vector<u8> { &table.deck_state.aggregated_pk }
public fun deck_plaintext(table: &Table): &vector<vector<u8>> { &table.deck_state.plaintext }

public fun shuffle_current_shuffler(table: &Table): Option<u64> { table.shuffle_state.current_shuffler }
public fun shuffle_pending_players(table: &Table): &vector<u64> { &table.shuffle_state.pending_players }
public fun shuffle_completed_players(table: &Table): &vector<u64> { &table.shuffle_state.completed_players }
public fun shuffle_pending_count(table: &Table): u64 { table.shuffle_state.pending_players.length() }
public fun shuffle_completed_count(table: &Table): u64 { table.shuffle_state.completed_players.length() }

public fun reveal_phase(table: &Table): u8 { table.reveal_token_state.reveal_phase }
public fun reveal_assignments(table: &Table): &vector<RevealAssignment> { &table.reveal_token_state.assignments }
public fun reveal_assignment_count(table: &Table): u64 { table.reveal_token_state.assignments.length() }

public fun reconstruct_phase(table: &Table): u8 { table.reconstruct_state.phase }
public fun shuffle_phase(table: &Table): u8 { table.shuffle_state.phase }
public fun reconstruct_player_decks_count(table: &Table): u64 { table.reconstruct_state.player_decks.length() }


// ========== BettingRound 访问器 ==========
public fun betting_round_exists(table: &Table): bool { table.betting_round.is_some() }
public fun betting_round_current_bet(table: &Table): u64 {
    if (table.betting_round.is_some()) { table.betting_round.borrow().current_bet() } else { 0 }
}
public fun betting_round_min_raise(table: &Table): u64 {
    if (table.betting_round.is_some()) { table.betting_round.borrow().min_raise() } else { 0 }
}
public fun betting_round_big_blind(table: &Table): u64 {
    if (table.betting_round.is_some()) { table.betting_round.borrow().big_blind() } else { 0 }
}
public fun betting_round_last_raiser_seat(table: &Table): Option<u64> {
    if (table.betting_round.is_some()) { table.betting_round.borrow().last_raiser_seat() } else { option::none() }
}
public fun betting_round_actions_taken(table: &Table): u64 {
    if (table.betting_round.is_some()) { table.betting_round.borrow().actions_taken() } else { 0 }
}

// ========== 超时配置访问器 ==========
public fun shuffle_timeout_ms(table: &Table): u64 { table.timeout_config.shuffle_timeout_ms }
public fun reveal_timeout_ms(table: &Table): u64 { table.timeout_config.reveal_timeout_ms }
public fun betting_timeout_ms(table: &Table): u64 { table.timeout_config.betting_timeout_ms }
public fun reconstruct_timeout_ms(table: &Table): u64 { table.timeout_config.reconstruct_timeout_ms }
public fun ready_at(table: &Table): u64 { table.timestamps.ready_at }
public fun shuffle_started_at(table: &Table): u64 { table.timestamps.shuffle_started_at }
public fun reveal_started_at(table: &Table): u64 { table.timestamps.reveal_started_at }
public fun betting_started_at(table: &Table): u64 { table.timestamps.betting_started_at }
public fun reconstruct_started_at(table: &Table): u64 { table.timestamps.reconstruct_started_at }
public fun showdown_at(table: &Table): u64 { table.timestamps.showdown_at }
public fun hand_complete_at(table: &Table): u64 { table.timestamps.hand_complete_at }
public fun current_turn_changed_at(table: &Table): u64 { table.timestamps.current_turn_changed_at }

// ========== 超时配置设置 ==========
// m2 修复：校验超时参数不为 0，防止 0 超时导致玩家无法行动
const MIN_TIMEOUT_MS: u64 = 1000;

public  fun set_timeout_config(
    table: &mut Table,
    _admin_cap: &AdminCap,
    shuffle_timeout_ms: u64,
    reveal_timeout_ms: u64,
    betting_timeout_ms: u64,
    reconstruct_timeout_ms: u64,
    showdown_display_ms: u64,
    hand_complete_wait_ms: u64,
    ready_wait_ms: u64,
) {
    assert!(shuffle_timeout_ms >= MIN_TIMEOUT_MS, EInvalidBetAmount);
    assert!(reveal_timeout_ms >= MIN_TIMEOUT_MS, EInvalidBetAmount);
    assert!(betting_timeout_ms >= MIN_TIMEOUT_MS, EInvalidBetAmount);
    assert!(reconstruct_timeout_ms >= MIN_TIMEOUT_MS, EInvalidBetAmount);
    table.timeout_config.shuffle_timeout_ms = shuffle_timeout_ms;
    table.timeout_config.reveal_timeout_ms = reveal_timeout_ms;
    table.timeout_config.betting_timeout_ms = betting_timeout_ms;
    table.timeout_config.reconstruct_timeout_ms = reconstruct_timeout_ms;
    table.timeout_config.showdown_display_ms = showdown_display_ms;
    table.timeout_config.hand_complete_wait_ms = hand_complete_wait_ms;
    table.timeout_config.ready_wait_ms = ready_wait_ms;
    table_events::emit_timeout_config_updated(
        object::id(table),
        betting_timeout_ms,
        shuffle_timeout_ms,
        reveal_timeout_ms,
        reconstruct_timeout_ms,
        showdown_display_ms,
    );
}

// ========== 阶段常量 ==========
public fun round_waiting(): u8 { table_constants::round_waiting() }
public fun round_preflop(): u8 { table_constants::round_preflop() }
public fun round_flop(): u8 { table_constants::round_flop() }
public fun round_turn(): u8 { table_constants::round_turn() }
public fun round_river(): u8 { table_constants::round_river() }
public fun round_showdown(): u8 { table_constants::round_showdown() }

// ========== 测试辅助 ==========
#[test_only]
public fun create_table_for_test(
    name: String,
    small_blind: u64,
    big_blind: u64,
    max_players: u64,
    ctx: &mut TxContext,
): Table {
    assert!(max_players <= table_constants::max_players(), ETableFull);
    let mut seats = vector[];
    let mut i = 0;
    while (i < max_players) {
        seats.push_back(empty_seat());
        i = i + 1;
    };
    let id = object::new(ctx);
    Table {
        id,
        name,
        max_players,
        small_blind,
        big_blind,
        seats,
        button: 0,
        pot: 0,
        side_pots: vector[],
        community_cards: vector[],
        round_state: table_constants::round_waiting(),
        betting_round: option::none(),
        current_turn: option::none(),
        deck_state: DeckState {
            encrypted: vector[],
            aggregated_pk: vector[],
            plaintext: table_serialization::generate_plaintext_bytes(),
            cards_dealt: 0,
            decrypted_cards: vector[],
        },
        shuffle_state: empty_shuffle_state(),
        reveal_token_state: empty_reveal_token_state(),
        reconstruct_state: empty_reconstruct_state(),
        timeout_config: TimeoutConfig {
            shuffle_timeout_ms: 10000,
            reveal_timeout_ms: 10000,
            betting_timeout_ms: 30000,
            reconstruct_timeout_ms: 10000,
            showdown_display_ms: 3000,
            hand_complete_wait_ms: 5000,
            ready_wait_ms: 5000,
        },
        timestamps: Timestamps {
            ready_at: 0,
            shuffle_started_at: 0,
            reveal_started_at: 0,
            betting_started_at: 0,
            reconstruct_started_at: 0,
            showdown_at: 0,
            hand_complete_at: 0,
            current_turn_changed_at: 0,
        },
        sui_balance: balance::zero(),
    }
}

#[test_only]
public fun join_table_for_test(table: &mut Table, seat_index: u64, player: address, buy_in: u64) {
    assert!(seat_index < table.max_players, EInvalidSeatIndex);
    assert!(buy_in > 0, EInvalidBetAmount);
    assert!(!is_seat_occupied(&table.seats[seat_index]), ESeatOccupied);
    assert!(!is_player_seated(&table.seats, player), EPlayerAlreadySeated);
    // 测试环境下铸造 SUI 存入牌桌资金池，确保 leave/kick 时有 SUI 可退
    // 向上取整计算所需 SUI 数量，保证余额足够覆盖后续退款
    let mut sui_amount = buy_in * STACK_TO_SUI_RATIO;
    if (sui_amount == 0) { sui_amount = 1 };
    let sui_balance = balance::create_for_testing<SUI>(sui_amount);
    table.sui_balance.join(sui_balance);
    init_seat(&mut table.seats[seat_index], player, buy_in, vector[], false);
}

#[test_only]
public fun destroy_table(table: Table) {
    let Table { id, seats: _, name: _, max_players: _, small_blind: _, big_blind: _,
        button: _, pot: _, side_pots: _, community_cards: _,
        round_state: _, betting_round: _, current_turn: _,
        deck_state: _, shuffle_state: _, reveal_token_state: _, reconstruct_state: _,
        timeout_config: _, timestamps: _, sui_balance } = table;
    sui::test_utils::destroy(sui_balance);
    id.delete();
}

// ========== 测试辅助: 绕过 ZK 验证的状态推进 ==========

/// 绕过 ZK 验证，直接完成所有玩家的洗牌并推进
#[test_only]
public fun advance_shuffle_for_test(table: &mut Table, _ctx: &mut TxContext) {
    // 生成 mock 加密牌组（52 张 placeholder）
    if (table.deck_state.encrypted.length() == 0) {
        let mut mock_deck = vector[];
        let mut i = 0;
        while (i < table_constants::n_cards()) {
            mock_deck.push_back(bls_elgamal::new_placeholder_card());
            i = i + 1;
        };
        table.deck_state.encrypted = mock_deck;
        // 设置 mock 聚合公钥
        if (table.deck_state.aggregated_pk.length() == 0) {
            let g = bls12381::g1_generator();
            table.deck_state.aggregated_pk = bls_scalar::g1_to_bytes(&g);
        };
    };

    // 标记所有 pending 玩家为已完成
    let pending = &mut table.shuffle_state.pending_players;
    while (pending.length() > 0) {
        let p = pending.remove(0);
        table.shuffle_state.completed_players.push_back(p);
    };
    table.shuffle_state.current_shuffler = option::none();

    // 推进洗牌
    advance_shuffle(table);
}

/// 绕过 ZK 验证，直接完成当前 reveal 阶段
#[test_only]
public fun complete_reveal_phase_for_test(table: &mut Table) {
    let phase = table.reveal_token_state.reveal_phase;
    let plaintext_len = table.deck_state.plaintext.length();

    // 标记所有 assignment 为已解密
    let mut i = 0;
    while (i < table.reveal_token_state.assignments.length()) {
        let assignment = &mut table.reveal_token_state.assignments[i];
        if (!assignment.decrypted) {
            assignment.decrypted = true;
            // 写入 mock 解密数据
            let card_idx = assignment.encrypted_card_index;
            let owner = if (phase == table_constants::reveal_phase_preflop()) {
                (i / table_constants::cards_per_player()) as u64
            } else if (phase == table_constants::reveal_phase_showdown()) {
                if (assignment.pending_players.length() > 0) {
                    *assignment.pending_players.borrow(0)
                } else {
                    0xFFFFFFFFFFFFFFFF
                }
            } else {
                0xFFFFFFFFFFFFFFFF
            };

            // 获取明文（先读取再 push，避免借用冲突）
            let plaintext = table.deck_state.plaintext[card_idx % plaintext_len];

            table.deck_state.decrypted_cards.push_back(DecryptedCard {
                encrypted_card_index: card_idx,
                owner_seat_index: owner,
                ciphertext_bytes: vector[],
                plaintext_bytes: plaintext,
            });
        };
        i = i + 1;
    };

    // 检查 reveal phase 完成并推进
    check_reveal_phase_complete(table);
}

/// 设置玩家公钥（测试用）
#[test_only]
public fun set_player_pk_for_test(table: &mut Table, seat_index: u64, pk: vector<u8>) {
    assert!(seat_index < table.seats.length(), EInvalidSeatIndex);
    table.seats[seat_index].pk = pk;
}

/// 直接设置 round_state（测试用，仅用于验证状态机）
#[test_only]
public fun set_round_state_for_test(table: &mut Table, state: u8) {
    table.round_state = state;
}

/// 获取 seat 的 left_during_hand 标志（测试用）
#[test_only]
public fun seat_left_during_hand(table: &Table, index: u64): bool {
    table.seats[index].left_during_hand
}

/// 获取 seat 的 is_waiting 标志（测试用）
#[test_only]
public fun seat_is_waiting(table: &Table, index: u64): bool {
    table.seats[index].is_waiting
}

/// 直接调用 reset_for_next_hand（测试用）
#[test_only]
public fun reset_for_next_hand_for_test(table: &mut Table) {
    reset_for_next_hand(table);
}

/// 直接调用 kick_player_internal（测试用，绕过 AdminCap）
#[test_only]
public fun kick_player_for_test(table: &mut Table, seat_index: u64, reason: u8, ctx: &mut TxContext) {
    kick_player_internal(table, seat_index, reason, ctx);
}

/// 直接设置 aggregated_pk（测试用，用于初始化场景）
#[test_only]
public fun set_aggregated_pk_for_test(table: &mut Table, pk: vector<u8>) {
    table.deck_state.aggregated_pk = pk;
}

/// 直接设置 seat 的 is_waiting 标志（测试用，模拟中途加入）
#[test_only]
public fun set_is_waiting_for_test(table: &mut Table, seat_index: u64, is_waiting: bool) {
    table.seats[seat_index].is_waiting = is_waiting;
}

/// 直接设置 seat 的 stack（测试用，模拟筹码为 0 的破产玩家）
#[test_only]
public fun set_stack_for_test(table: &mut Table, seat_index: u64, stack: u64) {
    table.seats[seat_index].stack = stack;
}

/// 直接调用 on_shuffle_timeout（测试用，绕过 tick/Clock 依赖）
#[test_only]
public fun force_on_shuffle_timeout_for_test(table: &mut Table, ctx: &mut TxContext) {
    on_shuffle_timeout(table, ctx);
}

/// 直接设置 shuffle_state（测试用，用于构造特定洗牌阶段）
#[test_only]
public fun set_shuffle_state_for_test(
    table: &mut Table,
    phase: u8,
    current_shuffler: Option<u64>,
    pending_players: vector<u64>,
    completed_players: vector<u64>,
) {
    table.shuffle_state = ShuffleState {
        phase,
        current_shuffler,
        pending_players,
        completed_players,
    };
}

/// 直接设置 shuffle_started_at 时间戳（测试用）
#[test_only]
public fun set_shuffle_started_at_for_test(table: &mut Table, ts: u64) {
    table.timestamps.shuffle_started_at = ts;
}

/// 直接向 reconstruct_state.player_decks 添加一条玩家 deck（测试用）
#[test_only]
public fun add_reconstruct_player_deck_for_test(
    table: &mut Table,
    seat_index: u64,
    output_cts: vector<ElGamalCiphertext>,
) {
    table.reconstruct_state.player_decks.push_back(ReconstructPlayerDeck {
        seat_index,
        output_cts,
    });
}

/// 直接设置 reconstruct_state.phase（测试用）
#[test_only]
public fun set_reconstruct_phase_for_test(table: &mut Table, phase: u8) {
    table.reconstruct_state.phase = phase;
}

/// 直接调用 on_reconstruct_timeout（测试用，绕过 tick/Clock 依赖）
#[test_only]
public fun force_on_reconstruct_timeout_for_test(table: &mut Table, ctx: &mut TxContext) {
    on_reconstruct_timeout(table, ctx);
}

/// 直接调用 on_betting_timeout（测试用，绕过 tick/Clock 依赖）
#[test_only]
public fun force_on_betting_timeout_for_test(table: &mut Table) {
    on_betting_timeout(table);
}

/// 直接调用 on_reveal_timeout（测试用，需要 Clock）
#[test_only]
public fun force_on_reveal_timeout_for_test(table: &mut Table, clock: &Clock, ctx: &mut TxContext) {
    on_reveal_timeout(table, clock, ctx);
}

/// 直接调用 tick（测试用，需要 Clock）
#[test_only]
public fun force_tick_for_test(table: &mut Table, clock: &Clock, ctx: &mut TxContext) {
    tick(table, clock, ctx);
}

/// 直接设置 reveal_started_at 时间戳（测试用）
#[test_only]
public fun set_reveal_started_at_for_test(table: &mut Table, ts: u64) {
    table.timestamps.reveal_started_at = ts;
}

/// 直接设置 betting_started_at 时间戳（测试用）
#[test_only]
public fun set_betting_started_at_for_test(table: &mut Table, ts: u64) {
    table.timestamps.betting_started_at = ts;
}

/// 直接设置 reconstruct_started_at 时间戳（测试用）
#[test_only]
public fun set_reconstruct_started_at_for_test(table: &mut Table, ts: u64) {
    table.timestamps.reconstruct_started_at = ts;
}

/// 直接设置 showdown_at 时间戳（测试用）
#[test_only]
public fun set_showdown_at_for_test(table: &mut Table, ts: u64) {
    table.timestamps.showdown_at = ts;
}

/// 获取 current_turn（测试用）
#[test_only]
public fun current_turn_for_test(table: &Table): Option<u64> {
    table.current_turn
}

/// 检查是否有可行动玩家（测试用）
#[test_only]
public fun has_actionable_player_for_test(table: &Table): bool {
    has_actionable_player(&table.seats)
}
