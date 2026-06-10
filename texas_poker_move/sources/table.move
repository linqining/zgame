module texas_poker::table;

use sui::event;
use std::string::String;
use texas_poker::card::Card;
use texas_poker::hand_evaluator::{Self, HandRank};
use texas_poker::betting::{Self, BettingRound};
use texas_poker::side_pot::{Self, SidePot};

// ========== 常量 ==========
const MIN_PLAYERS_TO_START: u64 = 3;
const MAX_PLAYERS: u64 = 9;
const CARDS_PER_PLAYER: u64 = 2;

const ROUND_WAITING: u8 = 0;
const ROUND_SHUFFLING: u8 = 1;
const ROUND_PREFLOP: u8 = 2;
const ROUND_FLOP: u8 = 3;
const ROUND_TURN: u8 = 4;
const ROUND_RIVER: u8 = 5;
const ROUND_SHOWDOWN: u8 = 6;
const ROUND_HAND_COMPLETE: u8 = 7;

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
const ENotAdmin: vector<u8> = b"Only admin can perform this action";
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
}

// ========== 洗牌承诺（需要 drop 以便替换） ==========
public struct ShuffleCommitment has store, drop {
    player: address,
    commitment: vector<u8>,
    submitted: bool,
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

public struct ShuffleCommitted has copy, drop {
    table_id: ID,
    player: address,
}

public struct CardsDealt has copy, drop {
    table_id: ID,
}

public struct CommunityRevealed has copy, drop {
    table_id: ID,
    round: u8,
    count: u64,
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

    shuffle_commitments: vector<ShuffleCommitment>,
    deck_commitment: vector<u8>,
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
    }
}

fun init_seat(seat: &mut Seat, player: address, stack: u64) {
    seat.occupied = true;
    seat.player = player;
    seat.stack = stack;
    seat.hand = vector[];
    seat.bet = 0;
    seat.total_bet = 0;
    seat.folded = false;
    seat.all_in = false;
    seat.acted_this_round = false;
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
        shuffle_commitments: vector[],
        deck_commitment: vector[],
    };
    let table_id = object::id(&table);
    transfer::share_object(table);
    event::emit(TableCreated { table_id, name, admin: ctx.sender() })
}

// ========== 玩家加入 ==========
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

    init_seat(&mut table.seats[seat_index], sender, buy_in);

    table.active_count = table.active_count + 1;
    event::emit(PlayerJoined { table_id: object::id(table), seat_index, player: sender, buy_in })
}

// ========== 玩家离开 ==========
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
    assert!(
        table.round_state == ROUND_WAITING || table.round_state == ROUND_HAND_COMPLETE,
        EInvalidRoundState
    );
    assert!(table.active_count >= MIN_PLAYERS_TO_START, ENotEnoughPlayers);

    reset_hand_state(table);
    move_button(table);

    table.round_state = ROUND_SHUFFLING;
    table.shuffle_commitments = vector[];
    event::emit(HandStarted { table_id: object::id(table), button: table.button })
}

// ========== 提交洗牌承诺 ==========
public entry fun submit_shuffle_commitment(
    table: &mut Table,
    commitment: vector<u8>,
    ctx: &mut TxContext,
) {
    assert!(table.round_state == ROUND_SHUFFLING, EInvalidRoundState);
    let sender = ctx.sender();
    assert!(is_player_seated(&table.seats, sender), EPlayerNotSeated);

    let mut already_submitted = false;
    let mut i = 0;
    while (i < table.shuffle_commitments.length()) {
        if (table.shuffle_commitments[i].player == sender) {
            already_submitted = true;
        };
        i = i + 1;
    };
    assert!(!already_submitted, EPlayerAlreadySeated);

    table.shuffle_commitments.push_back(ShuffleCommitment {
        player: sender,
        commitment,
        submitted: true,
    });

    if (table.shuffle_commitments.length() >= table.active_count) {
        table.round_state = ROUND_PREFLOP;
        post_blinds(table);
        start_betting_round(table, true);
    };
    event::emit(ShuffleCommitted { table_id: object::id(table), player: sender })
}

// ========== 发牌（public fun，非 entry，因为参数含非原始类型） ==========
public fun deal_hole_cards(
    table: &mut Table,
    hands: vector<vector<Card>>,
    deck_proof: vector<u8>,
    ctx: &mut TxContext,
) {
    assert!(table.round_state == ROUND_PREFLOP, EInvalidRoundState);
    assert!(ctx.sender() == table.admin, ENotAdmin);

    let mut i = 0;
    while (i < hands.length() && i < table.seats.length()) {
        let seat = &mut table.seats[i];
        if (seat.occupied && !seat.folded) {
            seat.hand = hands[i];
        };
        i = i + 1;
    };

    table.deck_commitment = deck_proof;
    event::emit(CardsDealt { table_id: object::id(table) })
}

// ========== 揭示公共牌（public fun，非 entry） ==========
public fun reveal_community_cards(
    table: &mut Table,
    cards: vector<Card>,
    ctx: &mut TxContext,
) {
    assert!(ctx.sender() == table.admin, ENotAdmin);

    let num_cards = cards.length();
    if (table.round_state == ROUND_PREFLOP && num_cards == 3) {
        append_community_cards(table, cards);
        table.round_state = ROUND_FLOP;
        start_betting_round(table, false);
        event::emit(CommunityRevealed { table_id: object::id(table), round: ROUND_FLOP, count: 3 });
    } else if (table.round_state == ROUND_FLOP && num_cards == 1) {
        append_community_cards(table, cards);
        table.round_state = ROUND_TURN;
        start_betting_round(table, false);
        event::emit(CommunityRevealed { table_id: object::id(table), round: ROUND_TURN, count: 1 });
    } else if (table.round_state == ROUND_TURN && num_cards == 1) {
        append_community_cards(table, cards);
        table.round_state = ROUND_RIVER;
        start_betting_round(table, false);
        event::emit(CommunityRevealed { table_id: object::id(table), round: ROUND_RIVER, count: 1 });
    } else {
        abort EInvalidRoundState
    };
}

// ========== 下注操作 ==========
public entry fun fold(table: &mut Table, seat_index: u64, ctx: &mut TxContext) {
    assert!(is_betting_round(table), EInvalidRoundState);
    assert!(is_player_turn(table, seat_index), ENotPlayerTurn);

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
    table.round_state = ROUND_SHOWDOWN;
    settle_hand(table);
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

fun count_active_players(seats: &vector<Seat>): u64 {
    let mut count = 0;
    let mut i = 0;
    while (i < seats.length()) {
        if (seats[i].occupied && !seats[i].folded) { count = count + 1 };
        i = i + 1;
    };
    count
}

// Count all occupied seats (including folded), used for heads-up detection at blind posting.
fun count_active_occupied(seats: &vector<Seat>): u64 {
    let mut count = 0;
    let mut i = 0;
    while (i < seats.length()) {
        if (seats[i].occupied) { count = count + 1 };
        i = i + 1;
    };
    count
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

    // Heads-up: button = SB, next = BB
    // Normal (3+): button+1 = SB, button+2 = BB
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
        // Only check non-folded, non-all-in players (they can still act)
        if (seat.occupied && !seat.folded && !seat.all_in) {
            if (!seat.acted_this_round) { all_acted = false };
            // A player who hasn't matched the current bet must still act
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
    table.betting_round = option::none();
    table.current_turn = option::none();
}

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

// 分离 extract_seat_info 为三个独立函数，避免借用冲突
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

fun append_community_cards(table: &mut Table, cards: vector<Card>) {
    let mut i = 0;
    while (i < cards.length()) {
        table.community_cards.push_back(cards[i]);
        i = i + 1;
    };
}

fun reset_hand_state(table: &mut Table) {
    table.pot = 0;
    table.side_pots = vector[];
    table.community_cards = vector[];
    table.betting_round = option::none();
    table.current_turn = option::none();
    table.deck_commitment = vector[];

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
        if (i != raiser_index) {
            seats[i].acted_this_round = false;
        };
        i = i + 1;
    };
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

// ========== 阶段常量 ==========
public fun round_waiting(): u8 { ROUND_WAITING }
public fun round_shuffling(): u8 { ROUND_SHUFFLING }
public fun round_preflop(): u8 { ROUND_PREFLOP }
public fun round_flop(): u8 { ROUND_FLOP }
public fun round_turn(): u8 { ROUND_TURN }
public fun round_river(): u8 { ROUND_RIVER }
public fun round_showdown(): u8 { ROUND_SHOWDOWN }
public fun round_hand_complete(): u8 { ROUND_HAND_COMPLETE }

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
        shuffle_commitments: vector[],
        deck_commitment: vector[],
    }
}

#[test_only]
public fun join_table_for_test(table: &mut Table, seat_index: u64, player: address, buy_in: u64) {
    assert!(seat_index < table.max_players, EInvalidSeatIndex);
    assert!(buy_in > 0, EInvalidBetAmount);
    assert!(!table.seats[seat_index].occupied, ESeatOccupied);
    assert!(!is_player_seated(&table.seats, player), EPlayerAlreadySeated);
    init_seat(&mut table.seats[seat_index], player, buy_in);
    table.active_count = table.active_count + 1;
}

#[test_only]
public fun destroy_table(table: Table) {
    let Table { id, seats: _, name: _, admin: _, max_players: _, small_blind: _, big_blind: _,
        active_count: _, button: _, pot: _, side_pots: _, community_cards: _,
        round_state: _, betting_round: _, current_turn: _, shuffle_commitments: _, deck_commitment: _ } = table;
    id.delete();
}
