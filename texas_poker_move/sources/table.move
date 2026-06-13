module texas_poker::table;

use sui::event;
use sui::clock::Clock;
use sui::bls12381;
use std::string::String;
use texas_poker::card::Card;
use texas_poker::hand_evaluator::{Self, HandRank};
use texas_poker::betting::{Self, BettingRound};
use texas_poker::side_pot::{Self, SidePot};
use texas_poker::bls_elgamal::ElGamalCiphertext;
use texas_poker::bls_scalar;
use texas_poker::zk_verifier;
use texas_poker::shuffle_proof::ShuffleProof;
use texas_poker::schnorr_proof::GeneralizedSchnorrProof;
use texas_poker::remask_proof::RemaskProof;
use texas_poker::leave_proof::LeaveProof;
use texas_poker::reveal_token_proof::RevealTokenProof;
use texas_poker::reconstruct_proof::ReconstructProof;

// ========== 常量 ==========
const MIN_PLAYERS_TO_START: u64 = 3;
const MAX_PLAYERS: u64 = 9;
const CARDS_PER_PLAYER: u64 = 2;

// ========== Round State 常量 ==========
const ROUND_WAITING: u8 = 0;
const ROUND_SHUFFLING: u8 = 1;
const ROUND_PREFLOP: u8 = 2;
const ROUND_FLOP: u8 = 3;
const ROUND_TURN: u8 = 4;
const ROUND_RIVER: u8 = 5;
const ROUND_SHOWDOWN: u8 = 6;
const ROUND_HAND_COMPLETE: u8 = 7;
const ROUND_SHUFFLE_COMPLETE: u8 = 8;
const ROUND_PREFLOP_REVEAL: u8 = 9;
const ROUND_FLOP_REVEAL: u8 = 10;
const ROUND_TURN_REVEAL: u8 = 11;
const ROUND_RIVER_REVEAL: u8 = 12;
const ROUND_SHOWDOWN_REVEAL: u8 = 13;

// ========== Reveal Phase 常量 ==========
const REVEAL_PHASE_NONE: u8 = 0;
const REVEAL_PHASE_HAND: u8 = 1;
const REVEAL_PHASE_COMMUNITY: u8 = 2;
const REVEAL_PHASE_SHOWDOWN: u8 = 3;
const REVEAL_PHASE_REDEAL: u8 = 4;

// ========== Reconstruct Phase 常量 ==========
const RECONSTRUCT_PHASE_NONE: u8 = 0;
const RECONSTRUCT_PHASE_VOTING: u8 = 1;
const RECONSTRUCT_PHASE_COLLECTING: u8 = 2;
const RECONSTRUCT_PHASE_COMPLETE: u8 = 3;

// ========== 错误码 ==========
#[error]
const ETableFull: vector<u8> = b"Table is full";
#[error]
const ENotPlayerTurn: vector<u8> = b"Not this player's turn";
#[error]
const EInvalidRoundState: vector<u8> = b"Invalid round state for this action";
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
const EPkAlreadyRegistered: vector<u8> = b"Player PK already registered";
#[error]
const ENotAdmin: vector<u8> = b"Only admin can perform this action";
#[error]
const ENotTimedOut: vector<u8> = b"Player has not timed out yet";

// ========== 座位 ==========
public struct Seat has store, drop {
    occupied: bool,
    player: address,
    stack: u64,
    hand: vector<Card>,
    bet: u64,
    total_bet: u64,
    folded: bool,
    all_in: bool,
    acted_this_round: bool,
    pk: vector<u8>,                     // 玩家 ElGamal 公钥 (G1 compressed bytes)
}

// ========== 洗牌状态 ==========
public struct ShuffleState has store, drop {
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
public struct ReconstructState has store, drop {
    phase: u8,                          // None / Voting / Collecting / Complete
    votes_yes: u64,
    votes_no: u64,
    voted_players: vector<u64>,         // 已投票的玩家 seat_index
    pending_players: vector<u64>,       // 待提交 reconstruct deck 的玩家
    completed_players: vector<u64>,     // 已提交的玩家
    coefficient: vector<u8>,            // 随机系数 (scalar bytes)
    readable_cards: vector<vector<u8>>, // 玩家可读牌 (G1 compressed bytes each)
    cards: vector<vector<u8>>,          // 明文牌点 (G1 compressed bytes each, 用于 verify)
}

// ========== 事件 ==========
public struct TableCreated has copy, drop {
    table_id: ID,
    name: String,
    admin: address,
}

public struct PlayerJoined has copy, drop {
    table_id: ID,
    seat_index: u64,
    player: address,
    buy_in: u64,
}

public struct PlayerLeft has copy, drop {
    table_id: ID,
    seat_index: u64,
    player: address,
}

public struct HandStarted has copy, drop {
    table_id: ID,
    button: u64,
}

public struct ShuffleVerified has copy, drop {
    table_id: ID,
    seat_index: u64,
    player: address,
}

public struct ShuffleCompleteEvt has copy, drop {
    table_id: ID,
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

public struct PlayerFolded has copy, drop {
    table_id: ID,
    seat_index: u64,
}

public struct PlayerChecked has copy, drop {
    table_id: ID,
    seat_index: u64,
}

public struct PlayerCalled has copy, drop {
    table_id: ID,
    seat_index: u64,
    amount: u64,
}

public struct PlayerRaised has copy, drop {
    table_id: ID,
    seat_index: u64,
    total_bet: u64,
}

public struct HandSettled has copy, drop {
    table_id: ID,
    pot: u64,
}

public struct ReconstructInitiated has copy, drop {
    table_id: ID,
}

public struct ReconstructVote has copy, drop {
    table_id: ID,
    seat_index: u64,
    vote: bool,
}

public struct ReconstructDeckSubmitted has copy, drop {
    table_id: ID,
    seat_index: u64,
}

public struct ReconstructCompleteEvt has copy, drop {
    table_id: ID,
}

public struct RedealRequested has copy, drop {
    table_id: ID,
    seat_index: u64,
    card_indices: vector<u64>,
}

public struct PlayerKicked has copy, drop {
    table_id: ID,
    seat_index: u64,
}

public struct AutoFolded has copy, drop {
    table_id: ID,
    seat_index: u64,
}

public struct ForceFolded has copy, drop {
    table_id: ID,
    seat_index: u64,
}

public struct ShuffleTimeout has copy, drop {
    table_id: ID,
    seat_index: u64,
}

public struct RevealTimeout has copy, drop {
    table_id: ID,
    phase: u8,
}

public struct HandReset has copy, drop {
    table_id: ID,
}

public struct ReadyToStart has copy, drop {
    table_id: ID,
    ready_at: u64,
}

public struct HandCleanedUp has copy, drop {
    table_id: ID,
}

// ========== 牌桌（共享对象） ==========
public struct Table has key {
    id: UID,
    name: String,
    admin: address,
    max_players: u64,
    small_blind: u64,
    big_blind: u64,

    seats: vector<Seat>,
    active_count: u64,
    button: u64,

    pot: u64,
    side_pots: vector<SidePot>,
    community_cards: vector<Card>,

    round_state: u8,
    betting_round: Option<BettingRound>,
    current_turn: Option<u64>,

    // 加密牌组
    deck_encrypted: vector<ElGamalCiphertext>,
    aggregated_pk: vector<u8>,          // 聚合公钥 (G1 compressed bytes)

    // 协议状态
    shuffle_state: ShuffleState,
    reveal_token_state: RevealTokenState,
    reconstruct_state: ReconstructState,

    // 超时控制
    shuffle_timeout_ms: u64,            // 洗牌超时 (默认 10000)
    reveal_timeout_ms: u64,             // 揭牌超时 (默认 10000)
    betting_timeout_ms: u64,            // 下注超时 (默认 30000)
    reconstruct_timeout_ms: u64,        // 重构投票超时 (默认 10000)
    showdown_display_ms: u64,           // 摊牌展示时间 (默认 3000)
    hand_complete_wait_ms: u64,         // 一手结束后等待时间 (默认 5000)
    ready_wait_ms: u64,                 // 开始倒计时 (默认 5000)
    ready_at: u64,                      // 准备好开始的时间戳 (0=未设置)
    shuffle_started_at: u64,            // 当前洗牌者开始时间
    reveal_started_at: u64,             // 当前 reveal 阶段开始时间
    betting_started_at: u64,            // 当前下注者开始时间
    reconstruct_started_at: u64,        // reconstruct 投票开始时间
    showdown_at: u64,                   // 摊牌展示结束时间
    hand_complete_at: u64,              // 一手结束时间
}

// ========== 创建空座位 ==========
fun empty_seat(): Seat {
    Seat {
        occupied: false,
        player: @0x0,
        stack: 0,
        hand: vector[],
        bet: 0,
        total_bet: 0,
        folded: false,
        all_in: false,
        acted_this_round: false,
        pk: vector[],
    }
}

fun init_seat(seat: &mut Seat, player: address, stack: u64, pk: vector<u8>) {
    seat.occupied = true;
    seat.player = player;
    seat.stack = stack;
    seat.hand = vector[];
    seat.bet = 0;
    seat.total_bet = 0;
    seat.folded = false;
    seat.all_in = false;
    seat.acted_this_round = false;
    seat.pk = pk;
}

fun reset_seat(seat: &mut Seat) {
    seat.occupied = false;
    seat.player = @0x0;
    seat.stack = 0;
    seat.hand = vector[];
    seat.bet = 0;
    seat.total_bet = 0;
    seat.folded = false;
    seat.all_in = false;
    seat.acted_this_round = false;
    seat.pk = vector[];
}

// ========== 创建空协议状态 ==========
fun empty_shuffle_state(): ShuffleState {
    ShuffleState {
        current_shuffler: option::none(),
        pending_players: vector[],
        completed_players: vector[],
    }
}

fun empty_reveal_token_state(): RevealTokenState {
    RevealTokenState {
        reveal_phase: REVEAL_PHASE_NONE,
        assignments: vector[],
    }
}

fun empty_reconstruct_state(): ReconstructState {
    ReconstructState {
        phase: RECONSTRUCT_PHASE_NONE,
        votes_yes: 0,
        votes_no: 0,
        voted_players: vector[],
        pending_players: vector[],
        completed_players: vector[],
        coefficient: vector[],
        readable_cards: vector[],
        cards: vector[],
    }
}

// ========== 创建牌桌 ==========
public entry fun create_table(
    name: String,
    small_blind: u64,
    big_blind: u64,
    max_players: u64,
    ctx: &mut TxContext,
) {
    assert!(max_players <= MAX_PLAYERS, ETableFull);
    assert!(big_blind >= small_blind * 2, EInvalidBetAmount);

    let mut seats = vector[];
    let mut i = 0;
    while (i < max_players) {
        seats.push_back(empty_seat());
        i = i + 1;
    };

    let id = object::new(ctx);
    let table = Table {
        id,
        name,
        admin: ctx.sender(),
        max_players,
        small_blind,
        big_blind,
        seats,
        active_count: 0,
        button: 0,
        pot: 0,
        side_pots: vector[],
        community_cards: vector[],
        round_state: ROUND_WAITING,
        betting_round: option::none(),
        current_turn: option::none(),
        deck_encrypted: vector[],
        aggregated_pk: vector[],
        shuffle_state: empty_shuffle_state(),
        reveal_token_state: empty_reveal_token_state(),
        reconstruct_state: empty_reconstruct_state(),
        shuffle_timeout_ms: 10000,
        reveal_timeout_ms: 10000,
        betting_timeout_ms: 30000,
        reconstruct_timeout_ms: 10000,
        showdown_display_ms: 3000,
        hand_complete_wait_ms: 5000,
        ready_wait_ms: 5000,
        ready_at: 0,
        shuffle_started_at: 0,
        reveal_started_at: 0,
        betting_started_at: 0,
        reconstruct_started_at: 0,
        showdown_at: 0,
        hand_complete_at: 0,
    };
    let table_id = object::id(&table);
    transfer::share_object(table);
    event::emit(TableCreated { table_id, name, admin: ctx.sender() })
}

// ========== 玩家加入（带密码学验证） ==========
public entry fun join_and_shuffle(
    table: &mut Table,
    seat_index: u64,
    buy_in: u64,
    pk: vector<u8>,                     // 玩家 ElGamal 公钥 (G1 compressed bytes)
    _pk_ownership_proof: vector<u8>,    // PK ownership Schnorr proof (serialized, 80 bytes: 48 commitment + 32 response)
    output_cards: vector<u8>,           // remask + shuffle 后的牌组 (serialized ciphertexts, flat bytes)
    remask_proof_bytes: vector<u8>,     // RemaskProof (serialized)
    shuffle_proof_bytes: vector<u8>,    // ShuffleProof (serialized)
    ctx: &mut TxContext,
) {
    assert!(seat_index < table.max_players, EInvalidSeatIndex);
    assert!(buy_in > 0, EInvalidBetAmount);
    assert!(!table.seats[seat_index].occupied, ESeatOccupied);

    let sender = ctx.sender();
    assert!(!is_player_seated(&table.seats, sender), EPlayerAlreadySeated);

    // 验证 PK 未被注册
    assert!(!is_pk_registered(&table.seats, &pk), EPkAlreadyRegistered);

    // 验证 PK 所有权证明（证明玩家拥有 pk 对应的私钥 sk）
    let pk_point = zk_verifier::deserialize_pk(&pk);
    zk_verifier::verify_pk_ownership_or_abort(&pk_point, &_pk_ownership_proof);

    // 反序列化牌组
    let output_cts = zk_verifier::deserialize_ciphertexts(&output_cards);

    // 如果已有加密牌组，验证 remask + shuffle
    if (table.deck_encrypted.length() > 0) {
        // 反序列化 proof
        let remask_proof = deserialize_remask_proof(&remask_proof_bytes);
        let shuffle_proof = deserialize_shuffle_proof(&shuffle_proof_bytes);

        // 计算新的聚合公钥
        let new_aggregated_pk = add_pk_to_aggregated(&table.aggregated_pk, &pk);

        // 验证 remask proof（同一 sk 用于所有牌）
        // 注意：remask 后的中间牌组由客户端计算并验证，链上只验证最终结果
        let pk_point = zk_verifier::deserialize_pk(&pk);
        zk_verifier::verify_remask_or_abort(&table.deck_encrypted, &output_cts, &pk_point, &remask_proof);

        // 验证 shuffle proof
        let new_pk_point = zk_verifier::deserialize_pk(&new_aggregated_pk);
        zk_verifier::verify_shuffle_or_abort(&table.deck_encrypted, &output_cts, &new_pk_point, &shuffle_proof);

        // 更新聚合公钥
        table.aggregated_pk = new_aggregated_pk;
    } else {
        // 第一个玩家，直接设置牌组
        table.aggregated_pk = pk;
    };

    // 初始化座位
    init_seat(&mut table.seats[seat_index], sender, buy_in, pk);
    table.active_count = table.active_count + 1;

    // 更新牌组
    table.deck_encrypted = output_cts;

    // 如果在洗牌阶段，标记为已完成
    if (table.round_state == ROUND_SHUFFLING) {
        table.shuffle_state.completed_players.push_back(seat_index);
        remove_from_pending(&mut table.shuffle_state.pending_players, seat_index);
        advance_shuffle(table);
    };

    event::emit(PlayerJoined { table_id: object::id(table), seat_index, player: sender, buy_in })
}

// ========== 玩家离开（带密码学验证） ==========
public entry fun leave_with_proof(
    table: &mut Table,
    seat_index: u64,
    output_cards: vector<u8>,           // leave 后的牌组 (serialized ciphertexts, flat bytes)
    leave_proof_bytes: vector<u8>,      // LeaveProof (serialized)
    ctx: &mut TxContext,
) {
    assert!(seat_index < table.max_players, EInvalidSeatIndex);
    assert!(table.seats[seat_index].occupied, ESeatEmpty);
    assert!(table.seats[seat_index].player == ctx.sender(), ENotOwner);

    let player_pk = table.seats[seat_index].pk;

    // 反序列化
    let output_cts = zk_verifier::deserialize_ciphertexts(&output_cards);
    let leave_proof = deserialize_leave_proof(&leave_proof_bytes);

    // 验证 leave proof
    zk_verifier::verify_leave_or_abort(
        &table.deck_encrypted,
        &output_cts,
        &zk_verifier::deserialize_pk(&player_pk),
        &leave_proof,
    );

    // 更新聚合公钥（移除该玩家 pk）
    table.aggregated_pk = remove_pk_from_aggregated(&table.aggregated_pk, &player_pk);

    // 更新牌组
    table.deck_encrypted = output_cts;

    // 从协议状态中移除该玩家
    remove_from_pending(&mut table.shuffle_state.pending_players, seat_index);
    remove_from_pending(&mut table.shuffle_state.completed_players, seat_index);
    // 如果离开的是当前洗牌者，推进到下一个
    if (table.shuffle_state.current_shuffler.is_some() &&
        *table.shuffle_state.current_shuffler.borrow() == seat_index) {
        table.shuffle_state.current_shuffler = option::none();
        advance_shuffle(table);
    };
    // 从 reveal assignments 中移除
    let mut a = 0;
    while (a < table.reveal_token_state.assignments.length()) {
        remove_from_pending(&mut table.reveal_token_state.assignments[a].pending_players, seat_index);
        a = a + 1;
    };
    // 从 reconstruct state 中移除
    remove_from_pending(&mut table.reconstruct_state.pending_players, seat_index);
    remove_from_pending(&mut table.reconstruct_state.voted_players, seat_index);
    remove_from_pending(&mut table.reconstruct_state.completed_players, seat_index);

    let player = table.seats[seat_index].player;
    let seat_folded = table.seats[seat_index].folded;
    let seat_bet = table.seats[seat_index].bet;
    let is_betting = is_betting_round(table);

    if (is_betting && !seat_folded) {
        table.pot = table.pot + seat_bet;
    };

    reset_seat(&mut table.seats[seat_index]);
    table.active_count = table.active_count - 1;

    if (is_betting) {
        let active = count_active_players(&table.seats);
        if (active <= 1) {
            end_without_showdown(table);
        };
    };

    // 如果离开后活跃人数不足，重置牌桌
    if (count_active_occupied(&table.seats) < MIN_PLAYERS_TO_START) {
        reset_for_next_hand(table);
    };

    event::emit(PlayerLeft { table_id: object::id(table), seat_index, player })
}

// ========== 简单加入（无密码学验证，用于测试或初始阶段） ==========
public entry fun join_table(
    table: &mut Table,
    seat_index: u64,
    buy_in: u64,
    ctx: &mut TxContext,
) {
    assert!(seat_index < table.max_players, EInvalidSeatIndex);
    assert!(buy_in > 0, EInvalidBetAmount);
    assert!(!table.seats[seat_index].occupied, ESeatOccupied);

    let sender = ctx.sender();
    assert!(!is_player_seated(&table.seats, sender), EPlayerAlreadySeated);

    init_seat(&mut table.seats[seat_index], sender, buy_in, vector[]);
    table.active_count = table.active_count + 1;
    event::emit(PlayerJoined { table_id: object::id(table), seat_index, player: sender, buy_in })
}

// ========== 简单离开 ==========
public entry fun leave_table(
    table: &mut Table,
    seat_index: u64,
    ctx: &mut TxContext,
) {
    assert!(seat_index < table.max_players, EInvalidSeatIndex);
    assert!(table.seats[seat_index].occupied, ESeatEmpty);
    assert!(table.seats[seat_index].player == ctx.sender(), ENotOwner);

    let player = table.seats[seat_index].player;
    let seat_folded = table.seats[seat_index].folded;
    let seat_bet = table.seats[seat_index].bet;
    let is_betting = is_betting_round(table);

    if (is_betting && !seat_folded) {
        table.pot = table.pot + seat_bet;
    };

    reset_seat(&mut table.seats[seat_index]);
    table.active_count = table.active_count - 1;

    if (is_betting) {
        let active = count_active_players(&table.seats);
        if (active <= 1) {
            end_without_showdown(table);
        };
    };
    event::emit(PlayerLeft { table_id: object::id(table), seat_index, player })
}

// ========== 开始新一手 ==========
public entry fun start_hand(table: &mut Table, _ctx: &mut TxContext) {
    do_start_hand(table);
}

fun do_start_hand(table: &mut Table) {
    assert!(
        table.round_state == ROUND_WAITING || table.round_state == ROUND_HAND_COMPLETE,
        EInvalidRoundState
    );
    assert!(table.active_count >= MIN_PLAYERS_TO_START, ENotEnoughPlayers);

    reset_hand_state(table);
    move_button(table);

    // 初始化洗牌状态
    table.round_state = ROUND_SHUFFLING;
    table.shuffle_started_at = 0;  // will be set when first shuffler starts
    table.shuffle_state = ShuffleState {
        current_shuffler: option::none(),
        pending_players: get_active_seat_indices(&table.seats),
        completed_players: vector[],
    };

    // 设置第一个洗牌者
    if (table.shuffle_state.pending_players.length() > 0) {
        table.shuffle_state.current_shuffler = option::some(table.shuffle_state.pending_players[0]);
    };

    event::emit(HandStarted { table_id: object::id(table), button: table.button })
}

// ========== Tick 函数（链下 relayer 定期调用） ==========
public entry fun tick(table: &mut Table, clock: &Clock) {
    let now = clock.timestamp_ms();

    if (table.round_state == ROUND_WAITING) {
        // 检查是否可以开始
        if (table.ready_at > 0 && now >= table.ready_at) {
            do_start_hand(table);
        } else if (table.ready_at == 0 && count_active_occupied(&table.seats) >= MIN_PLAYERS_TO_START) {
            // 设置开始倒计时
            table.ready_at = now + table.ready_wait_ms;
            event::emit(ReadyToStart { table_id: object::id(table), ready_at: table.ready_at });
        };
    } else if (table.round_state == ROUND_SHUFFLING) {
        // 设置洗牌开始时间（如果还没设置）
        if (table.shuffle_started_at == 0) {
            table.shuffle_started_at = now;
        };
        // 检查洗牌超时
        if (table.shuffle_state.current_shuffler.is_some()) {
            let shuffler = *table.shuffle_state.current_shuffler.borrow();
            if (now >= table.shuffle_started_at + table.shuffle_timeout_ms) {
                event::emit(ShuffleTimeout { table_id: object::id(table), seat_index: shuffler });
                kick_player_internal(table, shuffler);
            };
        };
    } else if (table.round_state == ROUND_SHUFFLE_COMPLETE) {
        // 自动推进到 PreFlopReveal
        table.round_state = ROUND_PREFLOP_REVEAL;
        table.reveal_started_at = now;
        start_preflop_reveal_phase(table);
    } else if (is_reveal_phase(table)) {
        // 设置 reveal 开始时间
        if (table.reveal_started_at == 0) {
            table.reveal_started_at = now;
        };
        // 检查 reveal 超时
        if (now >= table.reveal_started_at + table.reveal_timeout_ms) {
            event::emit(RevealTimeout { table_id: object::id(table), phase: table.round_state });
            if (table.round_state == ROUND_PREFLOP_REVEAL) {
                // PreFlop reveal 超时：重开整手
                reset_for_next_hand(table);
                event::emit(HandReset { table_id: object::id(table) });
            } else {
                // 其他阶段超时：启动 reconstruct
                // 先检查是否已经在 reconstruct
                if (table.reconstruct_state.phase == RECONSTRUCT_PHASE_NONE) {
                    table.reconstruct_state = ReconstructState {
                        phase: RECONSTRUCT_PHASE_VOTING,
                        votes_yes: 0,
                        votes_no: 0,
                        voted_players: vector[],
                        pending_players: get_active_seat_indices(&table.seats),
                        completed_players: vector[],
                        coefficient: vector[],
                        readable_cards: vector[],
                        cards: vector[],
                    };
                    table.reconstruct_started_at = now;
                    event::emit(ReconstructInitiated { table_id: object::id(table) });
                };
            };
        };
    } else if (is_betting_round(table)) {
        // 设置下注开始时间
        if (table.betting_started_at == 0 && table.current_turn.is_some()) {
            table.betting_started_at = now;
        };
        // 检查下注超时
        if (table.betting_started_at > 0 && now >= table.betting_started_at + table.betting_timeout_ms) {
            if (table.current_turn.is_some()) {
                let seat_index = *table.current_turn.borrow();
                event::emit(AutoFolded { table_id: object::id(table), seat_index });
                do_fold(table, seat_index);
            };
        };
    } else if (table.round_state == ROUND_SHOWDOWN) {
        // 设置 showdown 开始时间
        if (table.showdown_at == 0) {
            table.showdown_at = now + table.showdown_display_ms;
        };
        if (now >= table.showdown_at) {
            settle_hand(table);
        };
    } else if (table.round_state == ROUND_HAND_COMPLETE) {
        // 设置 hand_complete 时间
        if (table.hand_complete_at == 0) {
            table.hand_complete_at = now + table.hand_complete_wait_ms;
        };
        if (now >= table.hand_complete_at) {
            cleanup_hand(table);
        };
    };
}

// ========== Phase 3: auto_fold / force_fold / kick_player ==========

public entry fun auto_fold(table: &mut Table, seat_index: u64, clock: &Clock) {
    assert!(is_betting_round(table), EInvalidRoundState);
    assert!(is_player_turn(table, seat_index), ENotPlayerTurn);
    assert!(clock.timestamp_ms() >= table.betting_started_at + table.betting_timeout_ms, ENotTimedOut);

    event::emit(AutoFolded { table_id: object::id(table), seat_index });
    do_fold(table, seat_index);
}

public entry fun force_fold(table: &mut Table, seat_index: u64) {
    assert!(is_betting_round(table), EInvalidRoundState);
    let seat = &table.seats[seat_index];
    assert!(seat.occupied, ESeatEmpty);
    assert!(!seat.folded, EAlreadyFolded);

    event::emit(ForceFolded { table_id: object::id(table), seat_index });
    do_fold(table, seat_index);
}

public entry fun kick_player(table: &mut Table, seat_index: u64) {
    kick_player_internal(table, seat_index);
}

// ========== 提交洗牌结果（ZK Proof 验证） ==========
public entry fun submit_shuffle(
    table: &mut Table,
    output_cards: vector<u8>,           // 序列化的 ElGamalCiphertext 数组 (flat bytes)
    shuffle_proof_bytes: vector<u8>,    // 序列化的 ShuffleProof
    ctx: &mut TxContext,
) {
    assert!(table.round_state == ROUND_SHUFFLING, EInvalidRoundState);

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
    let shuffle_proof = deserialize_shuffle_proof(&shuffle_proof_bytes);

    // 验证 shuffle proof
    let pk = zk_verifier::deserialize_pk(&table.aggregated_pk);
    zk_verifier::verify_shuffle_or_abort(&table.deck_encrypted, &output_cts, &pk, &shuffle_proof);

    // 更新牌组
    table.deck_encrypted = output_cts;

    // 标记为已完成
    table.shuffle_state.completed_players.push_back(seat_index);
    remove_from_pending(&mut table.shuffle_state.pending_players, seat_index);

    event::emit(ShuffleVerified { table_id: object::id(table), seat_index, player: sender });

    // 推进洗牌流程
    advance_shuffle(table);
}

// ========== 提交 Reveal Token ==========
public entry fun submit_reveal_token(
    table: &mut Table,
    assignment_index: u64,              // reveal_token_state.assignments 中的索引
    reveal_token: vector<u8>,           // c1 * sk (G1 compressed bytes)
    proof_bytes: vector<u8>,            // RevealTokenProof (serialized)
    ctx: &mut TxContext,
) {
    assert!(is_reveal_phase(table), EInvalidRoundState);

    table.reveal_started_at = 0;  // reset on each token submission

    let sender = ctx.sender();
    assert!(is_player_seated(&table.seats, sender), EPlayerNotSeated);

    let seat_index = find_seat_index(&table.seats, sender);
    assert!(assignment_index < table.reveal_token_state.assignments.length(), EInvalidCardIndex);

    // 读取 assignment 信息（不可变借用）
    let card_index = table.reveal_token_state.assignments[assignment_index].encrypted_card_index;
    let is_decrypted = table.reveal_token_state.assignments[assignment_index].decrypted;
    let is_pending = is_in_list(&table.reveal_token_state.assignments[assignment_index].pending_players, seat_index);

    assert!(!is_decrypted, ECardAlreadyDecrypted);
    assert!(is_pending, ENotPendingRevealer);
    assert!(card_index < table.deck_encrypted.length(), EInvalidCardIndex);

    // 验证 reveal token proof
    let encrypted_card = &table.deck_encrypted[card_index];
    let token_point = bls12381::g1_from_bytes(&reveal_token);
    let expected_pk = zk_verifier::deserialize_pk(&table.seats[seat_index].pk);
    let proof = deserialize_reveal_token_proof(&proof_bytes);

    zk_verifier::verify_reveal_token_or_abort(encrypted_card, &token_point, &expected_pk, &proof);

    // 记录当前 phase 用于事件
    let current_phase = table.reveal_token_state.reveal_phase;

    // 存储 reveal token（可变借用）
    let assignment = &mut table.reveal_token_state.assignments[assignment_index];
    assignment.reveal_tokens.push_back(RevealTokenData {
        seat_index,
        token: reveal_token,
    });

    // 从 pending 中移除
    remove_from_pending(&mut assignment.pending_players, seat_index);

    // 如果所有玩家都已提交，标记为已解密
    if (assignment.pending_players.length() == 0) {
        assignment.decrypted = true;
    };

    event::emit(RevealTokenSubmitted {
        table_id: object::id(table),
        seat_index,
        card_index,
        phase: current_phase,
    });

    // 检查是否所有牌都已解密
    check_reveal_phase_complete(table);
}

// ========== 发起 Reconstruct 投票 ==========
public entry fun initiate_reconstruct(
    table: &mut Table,
    coefficient: vector<u8>,            // 随机系数 (scalar bytes)
    readable_cards: vector<vector<u8>>, // 玩家可读牌 (G1 compressed bytes each)
    cards: vector<vector<u8>>,          // 明文牌点 (G1 compressed bytes each)
    ctx: &mut TxContext,
) {
    let sender = ctx.sender();
    assert!(is_player_seated(&table.seats, sender), EPlayerNotSeated);

    table.reconstruct_state = ReconstructState {
        phase: RECONSTRUCT_PHASE_VOTING,
        votes_yes: 0,
        votes_no: 0,
        voted_players: vector[],
        pending_players: get_active_seat_indices(&table.seats),
        completed_players: vector[],
        coefficient,
        readable_cards,
        cards,
    };

    table.reconstruct_started_at = 0;

    event::emit(ReconstructInitiated { table_id: object::id(table) })
}

// ========== Reconstruct 投票 ==========
public entry fun vote_reconstruct(
    table: &mut Table,
    vote: bool,                         // true = 同意, false = 反对
    ctx: &mut TxContext,
) {
    assert!(table.reconstruct_state.phase == RECONSTRUCT_PHASE_VOTING, EReconstructNotVoting);

    let sender = ctx.sender();
    assert!(is_player_seated(&table.seats, sender), EPlayerNotSeated);

    let seat_index = find_seat_index(&table.seats, sender);
    assert!(!is_in_list(&table.reconstruct_state.voted_players, seat_index), EAlreadyVoted);

    // 记录投票
    if (vote) {
        table.reconstruct_state.votes_yes = table.reconstruct_state.votes_yes + 1;
    } else {
        table.reconstruct_state.votes_no = table.reconstruct_state.votes_no + 1;
    };
    table.reconstruct_state.voted_players.push_back(seat_index);

    event::emit(ReconstructVote { table_id: object::id(table), seat_index, vote });

    // 检查投票结果
    let active_count = count_active_occupied(&table.seats);
    if (table.reconstruct_state.voted_players.length() >= active_count) {
        if (table.reconstruct_state.votes_no == 0) {
            // 全部同意，进入 Collecting 阶段
            table.reconstruct_state.phase = RECONSTRUCT_PHASE_COLLECTING;
            table.reconstruct_state.pending_players = get_active_seat_indices(&table.seats);
        } else {
            // 有人反对，重置
            table.reconstruct_state = empty_reconstruct_state();
        };
    };
}

// ========== 提交 Reconstruct Deck ==========
public entry fun submit_reconstruct_deck(
    table: &mut Table,
    output_cards: vector<u8>,           // 重建后的牌组 (serialized ciphertexts, flat bytes)
    swap_cards: vector<u8>,             // swap-out 牌 (serialized ciphertexts, flat bytes)
    user_readable_cards: vector<u8>,    // 该玩家的可读牌 (serialized ciphertexts, flat bytes)
    proof_bytes: vector<u8>,            // ReconstructProof (serialized)
    ctx: &mut TxContext,
) {
    assert!(table.reconstruct_state.phase == RECONSTRUCT_PHASE_COLLECTING, EReconstructNotCollecting);

    let sender = ctx.sender();
    assert!(is_player_seated(&table.seats, sender), EPlayerNotSeated);

    let seat_index = find_seat_index(&table.seats, sender);
    assert!(!is_in_list(&table.reconstruct_state.completed_players, seat_index), EReconstructAlreadySubmitted);

    // 反序列化
    let output_cts = zk_verifier::deserialize_ciphertexts(&output_cards);
    let swap_cts = zk_verifier::deserialize_ciphertexts(&swap_cards);
    let readable_cts = zk_verifier::deserialize_ciphertexts(&user_readable_cards);
    let reconstruct_proof = deserialize_reconstruct_proof(&proof_bytes);

    // 从 ReconstructState 读取明文牌点
    let mut card_points = vector[];
    let mut i = 0;
    while (i < table.reconstruct_state.cards.length()) {
        card_points.push_back(bls12381::g1_from_bytes(&table.reconstruct_state.cards[i]));
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

    // 标记为已完成
    table.reconstruct_state.completed_players.push_back(seat_index);
    remove_from_pending(&mut table.reconstruct_state.pending_players, seat_index);

    event::emit(ReconstructDeckSubmitted { table_id: object::id(table), seat_index });

    // 所有玩家提交后，重新开始洗牌
    let active_count = count_active_occupied(&table.seats);
    if (table.reconstruct_state.completed_players.length() >= active_count) {
        table.reconstruct_state.phase = RECONSTRUCT_PHASE_COMPLETE;
        event::emit(ReconstructCompleteEvt { table_id: object::id(table) });

        // 重新开始洗牌
        table.round_state = ROUND_SHUFFLING;
        table.shuffle_state = ShuffleState {
            current_shuffler: option::none(),
            pending_players: get_active_seat_indices(&table.seats),
            completed_players: vector[],
        };
        if (table.shuffle_state.pending_players.length() > 0) {
            table.shuffle_state.current_shuffler = option::some(table.shuffle_state.pending_players[0]);
        };
        table.reconstruct_state = empty_reconstruct_state();
    };
}

// ========== 请求 Redeal ==========
public entry fun request_redeal(
    table: &mut Table,
    card_indices: vector<u64>,          // 需要重新发的牌索引
    ctx: &mut TxContext,
) {
    let sender = ctx.sender();
    assert!(is_player_seated(&table.seats, sender), EPlayerNotSeated);

    let seat_index = find_seat_index(&table.seats, sender);

    // 设置 redeal reveal phase
    // redeal reveal 的 pending_players 排除请求者自身（请求者不需要提交 reveal token）
    let mut assignments = create_reveal_assignments_for_cards(&card_indices, &table.seats);
    let mut a = 0;
    while (a < assignments.length()) {
        remove_from_pending(&mut assignments[a].pending_players, seat_index);
        a = a + 1;
    };

    table.reveal_token_state = RevealTokenState {
        reveal_phase: REVEAL_PHASE_REDEAL,
        assignments,
    };

    event::emit(RedealRequested { table_id: object::id(table), seat_index, card_indices })
}

// ========== 下注操作 ==========
public entry fun fold(table: &mut Table, seat_index: u64, ctx: &mut TxContext) {
    assert!(is_betting_round(table), EInvalidRoundState);
    assert!(is_player_turn(table, seat_index), ENotPlayerTurn);

    table.betting_started_at = 0;  // will be set by tick for next player

    let seat = &mut table.seats[seat_index];
    assert!(seat.occupied, ESeatEmpty);
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
    event::emit(PlayerFolded { table_id: object::id(table), seat_index })
}

public entry fun check(table: &mut Table, seat_index: u64, ctx: &mut TxContext) {
    assert!(is_betting_round(table), EInvalidRoundState);
    assert!(is_player_turn(table, seat_index), ENotPlayerTurn);

    table.betting_started_at = 0;  // will be set by tick for next player

    let seat = &mut table.seats[seat_index];
    assert!(seat.occupied, ESeatEmpty);
    assert!(seat.player == ctx.sender(), ENotOwner);

    if (table.betting_round.is_some()) {
        let round = table.betting_round.borrow();
        assert!(round.can_check(seat.bet), ECannotCheck);
        table.betting_round.borrow_mut().process_check(seat.bet);
    };

    seat.acted_this_round = true;
    advance_turn(table);
    event::emit(PlayerChecked { table_id: object::id(table), seat_index })
}

public entry fun call(table: &mut Table, seat_index: u64, ctx: &mut TxContext) {
    assert!(is_betting_round(table), EInvalidRoundState);
    assert!(is_player_turn(table, seat_index), ENotPlayerTurn);

    table.betting_started_at = 0;  // will be set by tick for next player

    let seat = &mut table.seats[seat_index];
    assert!(seat.occupied, ESeatEmpty);
    assert!(seat.player == ctx.sender(), ENotOwner);

    if (table.betting_round.is_some()) {
        let round = table.betting_round.borrow_mut();
        let call_amount = round.process_call(seat.bet, seat.stack);
        seat.stack = seat.stack - call_amount;
        seat.bet = seat.bet + call_amount;
        seat.total_bet = seat.total_bet + call_amount;
        if (seat.stack == 0) { seat.all_in = true };
    };

    seat.acted_this_round = true;
    advance_turn(table);
    event::emit(PlayerCalled { table_id: object::id(table), seat_index, amount: table.seats[seat_index].bet })
}

public entry fun raise(table: &mut Table, seat_index: u64, total_bet: u64, ctx: &mut TxContext) {
    assert!(is_betting_round(table), EInvalidRoundState);
    assert!(is_player_turn(table, seat_index), ENotPlayerTurn);

    table.betting_started_at = 0;  // will be set by tick for next player

    let seat = &mut table.seats[seat_index];
    assert!(seat.occupied, ESeatEmpty);
    assert!(seat.player == ctx.sender(), ENotOwner);

    if (table.betting_round.is_some()) {
        let round = table.betting_round.borrow_mut();
        let raise_amount = round.process_raise(total_bet, seat_index, seat.bet, seat.stack);
        seat.stack = seat.stack - raise_amount;
        seat.bet = seat.bet + raise_amount;
        seat.total_bet = seat.total_bet + raise_amount;
        if (seat.stack == 0) { seat.all_in = true };
    };

    seat.acted_this_round = true;
    reset_other_players_acted(&mut table.seats, seat_index);
    advance_turn(table);
    event::emit(PlayerRaised { table_id: object::id(table), seat_index, total_bet })
}

// ========== 摊牌 ==========
public entry fun showdown(table: &mut Table, _ctx: &mut TxContext) {
    assert!(table.round_state == ROUND_RIVER, EInvalidRoundState);
    collect_bets_to_pot(table);

    // 进入 ShowdownReveal 阶段（而非直接 SHOWDOWN）
    table.round_state = ROUND_SHOWDOWN_REVEAL;
    start_showdown_reveal_phase(table);
}

// ========== 结算 ==========
public fun settle_hand(table: &mut Table) {
    assert!(table.round_state == ROUND_SHOWDOWN, EInvalidRoundState);

    let bets = extract_bets(&table.seats);
    let folded = extract_folded(&table.seats);
    let all_in_flags = extract_all_in(&table.seats);
    let (main_pot, side_pots) = side_pot::calculate_side_pots(&bets, &folded, &all_in_flags);

    distribute_pot(table, main_pot, &folded);

    let mut i = 0;
    while (i < side_pots.length()) {
        let sp = &side_pots[i];
        distribute_side_pot(table, sp, &folded);
        i = i + 1;
    };

    let pot = table.pot;
    table.round_state = ROUND_HAND_COMPLETE;
    table.hand_complete_at = 0;  // will be set by tick
    event::emit(HandSettled { table_id: object::id(table), pot })
}

// ========== 内部函数 ==========

fun is_player_seated(seats: &vector<Seat>, player: address): bool {
    let mut i = 0;
    while (i < seats.length()) {
        if (seats[i].occupied && seats[i].player == player) { return true };
        i = i + 1;
    };
    false
}

fun is_pk_registered(seats: &vector<Seat>, pk: &vector<u8>): bool {
    let mut i = 0;
    while (i < seats.length()) {
        if (seats[i].occupied && seats[i].pk == *pk) { return true };
        i = i + 1;
    };
    false
}

fun find_seat_index(seats: &vector<Seat>, player: address): u64 {
    let mut i = 0;
    while (i < seats.length()) {
        if (seats[i].occupied && seats[i].player == player) { return i };
        i = i + 1;
    };
    abort EPlayerNotSeated
}

fun count_active_players(seats: &vector<Seat>): u64 {
    let mut count = 0;
    let mut i = 0;
    while (i < seats.length()) {
        if (seats[i].occupied && !seats[i].folded) { count = count + 1 };
        i = i + 1;
    };
    count
}

fun count_active_occupied(seats: &vector<Seat>): u64 {
    let mut count = 0;
    let mut i = 0;
    while (i < seats.length()) {
        if (seats[i].occupied) { count = count + 1 };
        i = i + 1;
    };
    count
}

fun get_active_seat_indices(seats: &vector<Seat>): vector<u64> {
    let mut result = vector[];
    let mut i = 0;
    while (i < seats.length()) {
        if (seats[i].occupied) { result.push_back(i) };
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
        if (table.seats[next].occupied) {
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
    table.current_turn = option::some(first_to_act);
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
        let first = find_next_active_seat(&table.seats, table.button, table.max_players);
        table.current_turn = option::some(first);
    };
}

fun is_betting_round(table: &Table): bool {
    table.round_state == ROUND_PREFLOP ||
    table.round_state == ROUND_FLOP ||
    table.round_state == ROUND_TURN ||
    table.round_state == ROUND_RIVER
}

fun is_reveal_phase(table: &Table): bool {
    table.round_state == ROUND_PREFLOP_REVEAL ||
    table.round_state == ROUND_FLOP_REVEAL ||
    table.round_state == ROUND_TURN_REVEAL ||
    table.round_state == ROUND_RIVER_REVEAL ||
    table.round_state == ROUND_SHOWDOWN_REVEAL
}

fun is_player_turn(table: &Table, seat_index: u64): bool {
    table.current_turn.is_some() && *table.current_turn.borrow() == seat_index
}

fun advance_turn(table: &mut Table) {
    if (is_betting_complete(table)) {
        collect_bets_to_pot(table);
        advance_round(table);
        return
    };

    let current = *table.current_turn.borrow();
    let next = find_next_active_seat(&table.seats, current, table.max_players);
    table.current_turn = option::some(next);
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
        if (seat.occupied && !seat.folded && !seat.all_in) {
            if (!seat.acted_this_round) { all_acted = false };
            if (seat.bet < current_bet) { all_matched = false };
        };
        i = i + 1;
    };

    all_acted && all_matched
}

fun collect_bets_to_pot(table: &mut Table) {
    let mut i = 0;
    while (i < table.seats.length()) {
        table.pot = table.pot + table.seats[i].bet;
        table.seats[i].bet = 0;
        i = i + 1;
    };
}

fun advance_round(table: &mut Table) {
    table.betting_round = option::none();
    table.current_turn = option::none();

    // 下注轮结束后进入对应的 Reveal 阶段
    if (table.round_state == ROUND_PREFLOP) {
        table.round_state = ROUND_FLOP_REVEAL;
        table.reveal_started_at = 0;
        start_community_reveal_phase(table, 3);
    } else if (table.round_state == ROUND_FLOP) {
        table.round_state = ROUND_TURN_REVEAL;
        table.reveal_started_at = 0;
        start_community_reveal_phase(table, 1);
    } else if (table.round_state == ROUND_TURN) {
        table.round_state = ROUND_RIVER_REVEAL;
        table.reveal_started_at = 0;
        start_community_reveal_phase(table, 1);
    } else if (table.round_state == ROUND_RIVER) {
        table.round_state = ROUND_SHOWDOWN_REVEAL;
        table.showdown_at = 0;
        start_showdown_reveal_phase(table);
    };
}

fun end_without_showdown(table: &mut Table) {
    collect_bets_to_pot(table);

    let mut winner_idx = 0;
    let mut i = 0;
    while (i < table.seats.length()) {
        if (table.seats[i].occupied && !table.seats[i].folded) {
            winner_idx = i;
        };
        i = i + 1;
    };

    table.seats[winner_idx].stack = table.seats[winner_idx].stack + table.pot;
    table.pot = 0;
    table.round_state = ROUND_HAND_COMPLETE;
    table.hand_complete_at = 0;  // will be set by tick
    table.betting_round = option::none();
    table.current_turn = option::none();
}

// ========== 洗牌推进 ==========

fun advance_shuffle(table: &mut Table) {
    // 检查活跃人数是否足够
    if (count_active_occupied(&table.seats) < MIN_PLAYERS_TO_START) {
        reset_for_next_hand(table);
        return
    };

    if (table.shuffle_state.pending_players.length() == 0 &&
        table.shuffle_state.completed_players.length() >= MIN_PLAYERS_TO_START) {
        // 所有玩家完成洗牌
        table.round_state = ROUND_SHUFFLE_COMPLETE;
        table.shuffle_state.current_shuffler = option::none();
        event::emit(ShuffleCompleteEvt { table_id: object::id(table) });

        // 自动推进到 PreFlopReveal
        table.round_state = ROUND_PREFLOP_REVEAL;
        table.reveal_started_at = 0;
        start_preflop_reveal_phase(table);
    } else if (table.shuffle_state.pending_players.length() > 0) {
        // 设置下一个洗牌者
        table.shuffle_state.current_shuffler = option::some(table.shuffle_state.pending_players[0]);
        table.shuffle_started_at = 0;  // will be set by tick when relayer calls
    };
}

// ========== Reveal Phase 启动 ==========

fun start_preflop_reveal_phase(table: &mut Table) {
    // 发牌：每个玩家 2 张牌
    let mut card_index = 0;
    let mut assignments = vector[];
    let active_seats = get_active_seat_indices(&table.seats);

    let mut s = 0;
    while (s < active_seats.length()) {
        let _seat_idx = active_seats[s];
        let mut c = 0;
        while (c < CARDS_PER_PLAYER) {
            let all_seats = get_active_seat_indices(&table.seats);
            assignments.push_back(RevealAssignment {
                encrypted_card_index: card_index,
                pending_players: all_seats,
                reveal_tokens: vector[],
                decrypted: false,
            });
            card_index = card_index + 1;
            c = c + 1;
        };
        s = s + 1;
    };

    table.reveal_token_state = RevealTokenState {
        reveal_phase: REVEAL_PHASE_HAND,
        assignments,
    };
}

fun start_community_reveal_phase(table: &mut Table, count: u64) {
    // 公共牌从手牌之后开始
    let start_index = count_active_occupied(&table.seats) * CARDS_PER_PLAYER + table.community_cards.length();
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

    table.reveal_token_state = RevealTokenState {
        reveal_phase: REVEAL_PHASE_COMMUNITY,
        assignments,
    };
}

fun start_showdown_reveal_phase(table: &mut Table) {
    // Showdown: 需要揭示未 fold 玩家的手牌
    let mut assignments = vector[];
    let active_seats = get_active_seat_indices(&table.seats);
    let mut card_index = 0;

    let mut s = 0;
    while (s < table.seats.length()) {
        let seat = &table.seats[s];
        if (seat.occupied && !seat.folded) {
            let mut c = 0;
            while (c < CARDS_PER_PLAYER) {
                assignments.push_back(RevealAssignment {
                    encrypted_card_index: card_index,
                    pending_players: active_seats,
                    reveal_tokens: vector[],
                    decrypted: false,
                });
                card_index = card_index + 1;
                c = c + 1;
            };
        } else if (seat.occupied) {
            card_index = card_index + CARDS_PER_PLAYER;
        };
        s = s + 1;
    };

    table.reveal_token_state = RevealTokenState {
        reveal_phase: REVEAL_PHASE_SHOWDOWN,
        assignments,
    };
}

fun create_reveal_assignments_for_cards(card_indices: &vector<u64>, seats: &vector<Seat>): vector<RevealAssignment> {
    let mut assignments = vector[];
    let active_seats = get_active_seat_indices(seats);
    let mut i = 0;
    while (i < card_indices.length()) {
        assignments.push_back(RevealAssignment {
            encrypted_card_index: card_indices[i],
            pending_players: active_seats,
            reveal_tokens: vector[],
            decrypted: false,
        });
        i = i + 1;
    };
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

    event::emit(RevealPhaseComplete { table_id: object::id(table), phase });

    if (phase == REVEAL_PHASE_HAND && table.round_state == ROUND_PREFLOP_REVEAL) {
        // 手牌解密完成，进入 PreFlop 下注
        table.round_state = ROUND_PREFLOP;
        table.betting_started_at = 0;
        post_blinds(table);
        start_betting_round(table, true);
    } else if (phase == REVEAL_PHASE_COMMUNITY) {
        // 公共牌解密完成
        if (table.round_state == ROUND_FLOP_REVEAL) {
            table.round_state = ROUND_FLOP;
            table.betting_started_at = 0;
            start_betting_round(table, false);
        } else if (table.round_state == ROUND_TURN_REVEAL) {
            table.round_state = ROUND_TURN;
            table.betting_started_at = 0;
            start_betting_round(table, false);
        } else if (table.round_state == ROUND_RIVER_REVEAL) {
            table.round_state = ROUND_RIVER;
            table.betting_started_at = 0;
            start_betting_round(table, false);
        };
    } else if (phase == REVEAL_PHASE_SHOWDOWN && table.round_state == ROUND_SHOWDOWN_REVEAL) {
        // 摊牌牌面解密完成，进入 Showdown
        table.round_state = ROUND_SHOWDOWN;
        table.showdown_at = 0;
        settle_hand(table);
    } else if (phase == REVEAL_PHASE_REDEAL) {
        // Redeal 完成，不改变 round_state，保持当前下注阶段继续
        // Rust 端参考：redeal reveal 完成后保持 PreFlop，通过 reveal_token_state 追踪进度
        // round_state 不变，只需重置 reveal state（在函数末尾执行）
    };

    // 重置 reveal state
    table.reveal_token_state = empty_reveal_token_state();
}

// ========== PK 聚合计算 ==========

fun add_pk_to_aggregated(aggregated: &vector<u8>, pk: &vector<u8>): vector<u8> {
    let agg_point = if (aggregated.length() == 0) {
        bls12381::g1_identity()
    } else {
        bls12381::g1_from_bytes(aggregated)
    };
    let pk_point = bls12381::g1_from_bytes(pk);
    let new_agg = bls12381::g1_add(&agg_point, &pk_point);
    bls_scalar::g1_to_bytes(&new_agg)
}

fun remove_pk_from_aggregated(aggregated: &vector<u8>, pk: &vector<u8>): vector<u8> {
    let agg_point = bls12381::g1_from_bytes(aggregated);
    let pk_point = bls12381::g1_from_bytes(pk);
    let new_agg = bls12381::g1_sub(&agg_point, &pk_point);
    bls_scalar::g1_to_bytes(&new_agg)
}

// ========== Proof 反序列化辅助 ==========

const G1_POINT_SIZE: u64 = 48;
const SCALAR_SIZE: u64 = 32;
const CIPHERTEXT_SIZE: u64 = 96;

fun read_bytes(data: &vector<u8>, offset: u64, len: u64): vector<u8> {
    let mut result = vector[];
    let mut i = 0;
    while (i < len) {
        result.push_back(*vector::borrow(data, offset + i));
        i = i + 1;
    };
    result
}

fun read_u16(data: &vector<u8>, offset: u64): u64 {
    let lo = (*vector::borrow(data, offset) as u64);
    let hi = (*vector::borrow(data, offset + 1) as u64);
    lo + (hi << 8)
}

fun read_g1_point(data: &vector<u8>, offset: u64): vector<u8> {
    read_bytes(data, offset, G1_POINT_SIZE)
}

fun read_scalar(data: &vector<u8>, offset: u64): vector<u8> {
    read_bytes(data, offset, SCALAR_SIZE)
}

fun deserialize_schnorr_proof(data: &vector<u8>, mut offset: u64): (GeneralizedSchnorrProof, u64) {
    let commitment = read_g1_point(data, offset);
    offset = offset + G1_POINT_SIZE;
    let count = read_u16(data, offset);
    offset = offset + 2;
    let mut responses = vector[];
    let mut i = 0;
    while (i < count) {
        responses.push_back(read_scalar(data, offset));
        offset = offset + SCALAR_SIZE;
        i = i + 1;
    };
    (texas_poker::schnorr_proof::new(commitment, responses), offset)
}

fun deserialize_shuffle_proof(data: &vector<u8>): ShuffleProof {
    let mut offset = 0;
    let sum_c1_commit = read_g1_point(data, offset);
    offset = offset + G1_POINT_SIZE;
    let sum_c2_commit = read_g1_point(data, offset);
    offset = offset + G1_POINT_SIZE;
    let nonce = read_scalar(data, offset);
    offset = offset + SCALAR_SIZE;
    let (combined_schnorr_proof, offset) = deserialize_schnorr_proof(data, offset);
    let (sum_c1_schnorr_proof, offset) = deserialize_schnorr_proof(data, offset);
    let (sum_c2_schnorr_proof, _offset) = deserialize_schnorr_proof(data, offset);
    texas_poker::shuffle_proof::new(
        sum_c1_commit,
        sum_c2_commit,
        combined_schnorr_proof,
        sum_c1_schnorr_proof,
        sum_c2_schnorr_proof,
        nonce,
    )
}

fun deserialize_remask_proof(data: &vector<u8>): RemaskProof {
    let mut offset = 0;
    let count = read_u16(data, offset);
    offset = offset + 2;
    let mut per_card_commitments = vector[];
    let mut i = 0;
    while (i < count) {
        per_card_commitments.push_back(read_g1_point(data, offset));
        offset = offset + G1_POINT_SIZE;
        i = i + 1;
    };
    let commitment_pk = read_g1_point(data, offset);
    offset = offset + G1_POINT_SIZE;
    let response = read_scalar(data, offset);
    offset = offset + SCALAR_SIZE;
    let nonce = read_scalar(data, offset);
    texas_poker::remask_proof::new(per_card_commitments, commitment_pk, response, nonce)
}

fun deserialize_leave_proof(data: &vector<u8>): LeaveProof {
    let mut offset = 0;
    let count = read_u16(data, offset);
    offset = offset + 2;
    let mut per_card_commitments = vector[];
    let mut i = 0;
    while (i < count) {
        per_card_commitments.push_back(read_g1_point(data, offset));
        offset = offset + G1_POINT_SIZE;
        i = i + 1;
    };
    let commitment_pk = read_g1_point(data, offset);
    offset = offset + G1_POINT_SIZE;
    let response = read_scalar(data, offset);
    offset = offset + SCALAR_SIZE;
    let nonce = read_scalar(data, offset);
    texas_poker::leave_proof::new(per_card_commitments, commitment_pk, response, nonce)
}

fun deserialize_reveal_token_proof(data: &vector<u8>): RevealTokenProof {
    let mut offset = 0;
    let user_public_key = read_g1_point(data, offset);
    offset = offset + G1_POINT_SIZE;
    let commitment_t1 = read_g1_point(data, offset);
    offset = offset + G1_POINT_SIZE;
    let commitment_t2 = read_g1_point(data, offset);
    offset = offset + G1_POINT_SIZE;
    let response_s = read_scalar(data, offset);
    texas_poker::reveal_token_proof::new(user_public_key, commitment_t1, commitment_t2, response_s)
}

fun deserialize_reconstruct_proof(data: &vector<u8>): ReconstructProof {
    let mut offset = 0;
    // swap_out_cards_proofs
    let swap_out_count = read_u16(data, offset);
    offset = offset + 2;
    let mut swap_out_proofs = vector[];
    let mut i = 0;
    while (i < swap_out_count) {
        // user_readable_card: 96 bytes
        let user_readable_card = read_bytes(data, offset, CIPHERTEXT_SIZE);
        offset = offset + CIPHERTEXT_SIZE;
        // swap_out_card: 96 bytes
        let swap_out_card = read_bytes(data, offset, CIPHERTEXT_SIZE);
        offset = offset + CIPHERTEXT_SIZE;
        // chaum_pedersen: commitment_a(48) + commitment_b(48) + response(32)
        let cp_commitment_a = read_g1_point(data, offset);
        offset = offset + G1_POINT_SIZE;
        let cp_commitment_b = read_g1_point(data, offset);
        offset = offset + G1_POINT_SIZE;
        let cp_response = read_scalar(data, offset);
        offset = offset + SCALAR_SIZE;
        let cp_proof = texas_poker::chaum_pedersen::new(cp_commitment_a, cp_commitment_b, cp_response);
        swap_out_proofs.push_back(
            texas_poker::reconstruct_proof::new_swap_out_card_proof(user_readable_card, swap_out_card, cp_proof)
        );
        i = i + 1;
    };
    let sum_c1_r_commit = read_g1_point(data, offset);
    offset = offset + G1_POINT_SIZE;
    let sum_c2_r_commit = read_g1_point(data, offset);
    offset = offset + G1_POINT_SIZE;
    let swap_sum_c1_commit = read_g1_point(data, offset);
    offset = offset + G1_POINT_SIZE;
    let swap_sum_c2_commit = read_g1_point(data, offset);
    offset = offset + G1_POINT_SIZE;
    let nonce = read_scalar(data, offset);
    offset = offset + SCALAR_SIZE;
    // blind_dleq_proof: commitment(48) + response(32) + nonce(32)
    let blind_commitment = read_g1_point(data, offset);
    offset = offset + G1_POINT_SIZE;
    let blind_response = read_scalar(data, offset);
    offset = offset + SCALAR_SIZE;
    let blind_nonce = read_scalar(data, offset);
    offset = offset + SCALAR_SIZE;
    let blind_dleq_proof = texas_poker::reconstruct_proof::new_reconstruction_dleq_proof(
        blind_commitment, blind_response, blind_nonce
    );
    // total_dleq_proof: commitment_a(48) + commitment_b(48) + response(32)
    let total_commitment_a = read_g1_point(data, offset);
    offset = offset + G1_POINT_SIZE;
    let total_commitment_b = read_g1_point(data, offset);
    offset = offset + G1_POINT_SIZE;
    let total_response = read_scalar(data, offset);
    offset = offset + SCALAR_SIZE;
    let total_dleq_proof = texas_poker::chaum_pedersen::new(total_commitment_a, total_commitment_b, total_response);
    // schnorr proofs
    let (swap_combined_schnorr_proof, offset) = deserialize_schnorr_proof(data, offset);
    let (sum_swap_out_c1_schnorr_proof, offset) = deserialize_schnorr_proof(data, offset);
    let (sum_swap_out_c2_schnorr_proof, _offset) = deserialize_schnorr_proof(data, offset);
    texas_poker::reconstruct_proof::new(
        swap_out_proofs,
        sum_c1_r_commit,
        sum_c2_r_commit,
        swap_sum_c1_commit,
        swap_sum_c2_commit,
        nonce,
        blind_dleq_proof,
        total_dleq_proof,
        swap_combined_schnorr_proof,
        sum_swap_out_c1_schnorr_proof,
        sum_swap_out_c2_schnorr_proof,
    )
}

// ========== 结算相关 ==========

fun distribute_pot(table: &mut Table, pot_amount: u64, folded: &vector<bool>) {
    if (pot_amount == 0) { return };

    let (winners, _best_rank) = find_winners(&table.seats, &table.community_cards, folded);

    let winner_count = winners.length();
    if (winner_count > 0) {
        let share = pot_amount / winner_count;
        let remainder = pot_amount % winner_count;
        let mut w = 0;
        while (w < winner_count) {
            let idx = winners[w];
            table.seats[idx].stack = table.seats[idx].stack + share + if (w == 0) { remainder } else { 0 };
            w = w + 1;
        };
    };
}

fun distribute_side_pot(table: &mut Table, sp: &SidePot, folded: &vector<bool>) {
    let eligible = sp.eligible_seats();
    let pot_amount = sp.amount();

    let (winners, _best_rank) = find_winners_in_eligible(
        &table.seats, &table.community_cards, folded, eligible
    );

    let winner_count = winners.length();
    if (winner_count > 0) {
        let share = pot_amount / winner_count;
        let remainder = pot_amount % winner_count;
        let mut w = 0;
        while (w < winner_count) {
            let idx = winners[w];
            table.seats[idx].stack = table.seats[idx].stack + share + if (w == 0) { remainder } else { 0 };
            w = w + 1;
        };
    };
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
        if (seat.occupied && !folded[i] && seat.hand.length() == CARDS_PER_PLAYER) {
            let all_cards = combine_cards(&seat.hand, community_cards);
            if (all_cards.length() >= 5) {
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
        if (seat.occupied && !folded[idx] && seat.hand.length() == CARDS_PER_PLAYER) {
            let all_cards = combine_cards(&seat.hand, community_cards);
            if (all_cards.length() >= 5) {
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

fun extract_bets(seats: &vector<Seat>): vector<u64> {
    let mut bets = vector[];
    let mut i = 0;
    while (i < seats.length()) {
        if (seats[i].occupied) {
            bets.push_back(seats[i].total_bet);
        } else {
            bets.push_back(0);
        };
        i = i + 1;
    };
    bets
}

fun extract_folded(seats: &vector<Seat>): vector<bool> {
    let mut folded = vector[];
    let mut i = 0;
    while (i < seats.length()) {
        if (seats[i].occupied) {
            folded.push_back(seats[i].folded);
        } else {
            folded.push_back(true);
        };
        i = i + 1;
    };
    folded
}

fun extract_all_in(seats: &vector<Seat>): vector<bool> {
    let mut all_in_flags = vector[];
    let mut i = 0;
    while (i < seats.length()) {
        if (seats[i].occupied) {
            all_in_flags.push_back(seats[i].all_in);
        } else {
            all_in_flags.push_back(false);
        };
        i = i + 1;
    };
    all_in_flags
}

fun find_next_active_seat(seats: &vector<Seat>, from: u64, max: u64): u64 {
    let mut i = from + 1;
    let mut count = 0;
    while (count < max) {
        if (i >= max) { i = 0 };
        let seat = &seats[i];
        if (seat.occupied && !seat.folded && !seat.all_in) {
            return i
        };
        i = i + 1;
        count = count + 1;
    };
    from
}

fun reset_hand_state(table: &mut Table) {
    table.pot = 0;
    table.side_pots = vector[];
    table.community_cards = vector[];
    table.betting_round = option::none();
    table.current_turn = option::none();
    table.deck_encrypted = vector[];
    table.shuffle_state = empty_shuffle_state();
    table.reveal_token_state = empty_reveal_token_state();
    table.reconstruct_state = empty_reconstruct_state();

    let mut i = 0;
    while (i < table.seats.length()) {
        let seat = &mut table.seats[i];
        seat.hand = vector[];
        seat.bet = 0;
        seat.total_bet = 0;
        seat.folded = false;
        seat.all_in = false;
        seat.acted_this_round = false;
        i = i + 1;
    };
}

fun reset_other_players_acted(seats: &mut vector<Seat>, raiser_index: u64) {
    let mut i = 0;
    while (i < seats.length()) {
        // 只重置未 fold 且未 all_in 的玩家
        if (i != raiser_index && seats[i].occupied && !seats[i].folded && !seats[i].all_in) {
            seats[i].acted_this_round = false;
        };
        i = i + 1;
    };
}

// ========== Tick 辅助函数 ==========

fun do_fold(table: &mut Table, seat_index: u64) {
    let seat = &mut table.seats[seat_index];
    assert!(seat.occupied, ESeatEmpty);
    assert!(!seat.folded, EAlreadyFolded);

    seat.folded = true;
    seat.acted_this_round = true;
    table.betting_started_at = 0;  // reset for next player

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
        i = i + 1;
    };
    table.pot = 0;
    table.side_pots = vector[];
    table.community_cards = vector[];
    table.betting_round = option::none();
    table.current_turn = option::none();
    table.round_state = ROUND_WAITING;
    table.deck_encrypted = vector[];
    table.shuffle_state = empty_shuffle_state();
    table.reveal_token_state = empty_reveal_token_state();
    table.reconstruct_state = empty_reconstruct_state();
    table.ready_at = 0;
    table.shuffle_started_at = 0;
    table.reveal_started_at = 0;
    table.betting_started_at = 0;
    table.reconstruct_started_at = 0;
    table.showdown_at = 0;
    table.hand_complete_at = 0;
}

fun cleanup_hand(table: &mut Table) {
    // Remove busted players (stack == 0)
    let mut i = 0;
    while (i < table.seats.length()) {
        if (table.seats[i].occupied && table.seats[i].stack == 0) {
            // Reset seat (player is busted)
            table.seats[i].occupied = false;
            table.seats[i].player = @0x0;
            table.seats[i].stack = 0;
            table.seats[i].hand = vector[];
            table.seats[i].bet = 0;
            table.seats[i].total_bet = 0;
            table.seats[i].folded = false;
            table.seats[i].all_in = false;
            table.seats[i].acted_this_round = false;
            table.seats[i].pk = vector[];
            table.active_count = table.active_count - 1;
        };
        i = i + 1;
    };

    reset_for_next_hand(table);
    event::emit(HandCleanedUp { table_id: object::id(table) });
}

fun kick_player_internal(table: &mut Table, seat_index: u64) {
    let seat = &mut table.seats[seat_index];
    assert!(seat.occupied, ESeatEmpty);

    let pk = seat.pk;
    let is_current_shuffler = table.shuffle_state.current_shuffler.is_some() &&
        *table.shuffle_state.current_shuffler.borrow() == seat_index;
    let is_current_turn = table.current_turn.is_some() &&
        *table.current_turn.borrow() == seat_index;

    // Mark seat as empty
    seat.occupied = false;
    seat.player = @0x0;
    seat.stack = 0;
    seat.hand = vector[];
    seat.bet = 0;
    seat.total_bet = 0;
    seat.folded = false;
    seat.all_in = false;
    seat.acted_this_round = false;
    seat.pk = vector[];
    table.active_count = table.active_count - 1;

    // Update aggregated PK
    if (pk.length() > 0) {
        table.aggregated_pk = remove_pk_from_aggregated(&table.aggregated_pk, &pk);
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
    remove_from_pending(&mut table.reconstruct_state.voted_players, seat_index);
    remove_from_pending(&mut table.reconstruct_state.completed_players, seat_index);

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
            let next = find_next_active_seat(&table.seats, seat_index, table.max_players);
            table.current_turn = option::some(next);
            table.betting_started_at = 0;
        };
    };

    // Check if enough players remain
    if (count_active_occupied(&table.seats) < MIN_PLAYERS_TO_START) {
        reset_for_next_hand(table);
    };

    event::emit(PlayerKicked { table_id: object::id(table), seat_index });
}

// ========== 访问器 ==========
public fun round_state(table: &Table): u8 { table.round_state }
public fun pot(table: &Table): u64 { table.pot }
public fun community_cards(table: &Table): &vector<Card> { &table.community_cards }
public fun current_turn(table: &Table): Option<u64> { table.current_turn }
public fun active_count(table: &Table): u64 { table.active_count }
public fun button(table: &Table): u64 { table.button }
public fun small_blind(table: &Table): u64 { table.small_blind }
public fun big_blind(table: &Table): u64 { table.big_blind }

public fun seat_player(table: &Table, index: u64): address { table.seats[index].player }
public fun seat_stack(table: &Table, index: u64): u64 { table.seats[index].stack }
public fun seat_bet(table: &Table, index: u64): u64 { table.seats[index].bet }
public fun seat_folded(table: &Table, index: u64): bool { table.seats[index].folded }
public fun seat_hand(table: &Table, index: u64): &vector<Card> { &table.seats[index].hand }
public fun seat_occupied(table: &Table, index: u64): bool { table.seats[index].occupied }
public fun seat_pk(table: &Table, index: u64): &vector<u8> { &table.seats[index].pk }

public fun deck_encrypted(table: &Table): &vector<ElGamalCiphertext> { &table.deck_encrypted }
public fun aggregated_pk(table: &Table): &vector<u8> { &table.aggregated_pk }

public fun shuffle_current_shuffler(table: &Table): Option<u64> { table.shuffle_state.current_shuffler }
public fun shuffle_pending_players(table: &Table): &vector<u64> { &table.shuffle_state.pending_players }
public fun shuffle_completed_players(table: &Table): &vector<u64> { &table.shuffle_state.completed_players }

public fun reveal_phase(table: &Table): u8 { table.reveal_token_state.reveal_phase }
public fun reveal_assignments(table: &Table): &vector<RevealAssignment> { &table.reveal_token_state.assignments }

public fun reconstruct_phase(table: &Table): u8 { table.reconstruct_state.phase }
public fun reconstruct_votes(table: &Table): (u64, u64) {
    (table.reconstruct_state.votes_yes, table.reconstruct_state.votes_no)
}

// ========== 超时配置访问器 ==========
public fun shuffle_timeout_ms(table: &Table): u64 { table.shuffle_timeout_ms }
public fun reveal_timeout_ms(table: &Table): u64 { table.reveal_timeout_ms }
public fun betting_timeout_ms(table: &Table): u64 { table.betting_timeout_ms }
public fun reconstruct_timeout_ms(table: &Table): u64 { table.reconstruct_timeout_ms }
public fun ready_at(table: &Table): u64 { table.ready_at }
public fun shuffle_started_at(table: &Table): u64 { table.shuffle_started_at }
public fun reveal_started_at(table: &Table): u64 { table.reveal_started_at }
public fun betting_started_at(table: &Table): u64 { table.betting_started_at }
public fun reconstruct_started_at(table: &Table): u64 { table.reconstruct_started_at }
public fun showdown_at(table: &Table): u64 { table.showdown_at }
public fun hand_complete_at(table: &Table): u64 { table.hand_complete_at }

// ========== 超时配置设置 ==========
public entry fun set_timeout_config(
    table: &mut Table,
    shuffle_timeout_ms: u64,
    reveal_timeout_ms: u64,
    betting_timeout_ms: u64,
    reconstruct_timeout_ms: u64,
    showdown_display_ms: u64,
    hand_complete_wait_ms: u64,
    ready_wait_ms: u64,
    ctx: &TxContext,
) {
    assert!(ctx.sender() == table.admin, ENotAdmin);
    table.shuffle_timeout_ms = shuffle_timeout_ms;
    table.reveal_timeout_ms = reveal_timeout_ms;
    table.betting_timeout_ms = betting_timeout_ms;
    table.reconstruct_timeout_ms = reconstruct_timeout_ms;
    table.showdown_display_ms = showdown_display_ms;
    table.hand_complete_wait_ms = hand_complete_wait_ms;
    table.ready_wait_ms = ready_wait_ms;
}

// ========== 阶段常量 ==========
public fun round_waiting(): u8 { ROUND_WAITING }
public fun round_shuffling(): u8 { ROUND_SHUFFLING }
public fun round_preflop(): u8 { ROUND_PREFLOP }
public fun round_flop(): u8 { ROUND_FLOP }
public fun round_turn(): u8 { ROUND_TURN }
public fun round_river(): u8 { ROUND_RIVER }
public fun round_showdown(): u8 { ROUND_SHOWDOWN }
public fun round_hand_complete(): u8 { ROUND_HAND_COMPLETE }
public fun round_shuffle_complete(): u8 { ROUND_SHUFFLE_COMPLETE }
public fun round_preflop_reveal(): u8 { ROUND_PREFLOP_REVEAL }
public fun round_flop_reveal(): u8 { ROUND_FLOP_REVEAL }
public fun round_turn_reveal(): u8 { ROUND_TURN_REVEAL }
public fun round_river_reveal(): u8 { ROUND_RIVER_REVEAL }
public fun round_showdown_reveal(): u8 { ROUND_SHOWDOWN_REVEAL }

// ========== 测试辅助 ==========
#[test_only]
public fun create_table_for_test(
    name: String,
    small_blind: u64,
    big_blind: u64,
    max_players: u64,
    ctx: &mut TxContext,
): Table {
    assert!(max_players <= MAX_PLAYERS, ETableFull);
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
        admin: ctx.sender(),
        max_players,
        small_blind,
        big_blind,
        seats,
        active_count: 0,
        button: 0,
        pot: 0,
        side_pots: vector[],
        community_cards: vector[],
        round_state: ROUND_WAITING,
        betting_round: option::none(),
        current_turn: option::none(),
        deck_encrypted: vector[],
        aggregated_pk: vector[],
        shuffle_state: empty_shuffle_state(),
        reveal_token_state: empty_reveal_token_state(),
        reconstruct_state: empty_reconstruct_state(),
        shuffle_timeout_ms: 10000,
        reveal_timeout_ms: 10000,
        betting_timeout_ms: 30000,
        reconstruct_timeout_ms: 10000,
        showdown_display_ms: 3000,
        hand_complete_wait_ms: 5000,
        ready_wait_ms: 5000,
        ready_at: 0,
        shuffle_started_at: 0,
        reveal_started_at: 0,
        betting_started_at: 0,
        reconstruct_started_at: 0,
        showdown_at: 0,
        hand_complete_at: 0,
    }
}

#[test_only]
public fun join_table_for_test(table: &mut Table, seat_index: u64, player: address, buy_in: u64) {
    assert!(seat_index < table.max_players, EInvalidSeatIndex);
    assert!(buy_in > 0, EInvalidBetAmount);
    assert!(!table.seats[seat_index].occupied, ESeatOccupied);
    assert!(!is_player_seated(&table.seats, player), EPlayerAlreadySeated);
    init_seat(&mut table.seats[seat_index], player, buy_in, vector[]);
    table.active_count = table.active_count + 1;
}

#[test_only]
public fun destroy_table(table: Table) {
    let Table { id, seats: _, name: _, admin: _, max_players: _, small_blind: _, big_blind: _,
        active_count: _, button: _, pot: _, side_pots: _, community_cards: _,
        round_state: _, betting_round: _, current_turn: _,
        deck_encrypted: _, aggregated_pk: _,
        shuffle_state: _, reveal_token_state: _, reconstruct_state: _,
        shuffle_timeout_ms: _, reveal_timeout_ms: _, betting_timeout_ms: _,
        reconstruct_timeout_ms: _, showdown_display_ms: _, hand_complete_wait_ms: _,
        ready_wait_ms: _, ready_at: _, shuffle_started_at: _, reveal_started_at: _,
        betting_started_at: _, reconstruct_started_at: _, showdown_at: _, hand_complete_at: _ } = table;
    id.delete();
}
