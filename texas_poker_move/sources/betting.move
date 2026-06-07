module texas_poker::betting;

// ========== 错误码 ==========
#[error]
const ECannotCheck: vector<u8> = b"Cannot check when there is a bet to call";
#[error]
const ECannotCall: vector<u8> = b"Cannot call when nothing to call";
#[error]
const ECannotRaise: vector<u8> = b"Cannot raise: insufficient stack";
#[error]
const EInvalidRaiseAmount: vector<u8> = b"Raise amount is less than minimum raise";

// ========== 动作常量 ==========
const ACTION_FOLD: u8 = 1;
const ACTION_CHECK: u8 = 2;
const ACTION_CALL: u8 = 4;
const ACTION_RAISE: u8 = 8;

// ========== 下注轮 ==========
public struct BettingRound has store, drop {
    current_bet: u64,
    min_raise: u64,
    big_blind: u64,
    last_raiser_seat: Option<u64>,
    actions_taken: u64,
}

// ========== 构造函数 ==========
public fun new_preflop(big_blind: u64): BettingRound {
    BettingRound {
        current_bet: big_blind,
        min_raise: big_blind,
        big_blind,
        last_raiser_seat: option::none(),
        actions_taken: 0,
    }
}

public fun new_postflop(big_blind: u64): BettingRound {
    BettingRound {
        current_bet: 0,
        min_raise: big_blind,
        big_blind,
        last_raiser_seat: option::none(),
        actions_taken: 0,
    }
}

// ========== 访问器 ==========
public fun current_bet(round: &BettingRound): u64 { round.current_bet }
public fun min_raise(round: &BettingRound): u64 { round.min_raise }
public fun big_blind(round: &BettingRound): u64 { round.big_blind }
public fun actions_taken(round: &BettingRound): u64 { round.actions_taken }
public fun last_raiser_seat(round: &BettingRound): Option<u64> { round.last_raiser_seat }

// ========== 计算需要跟注的金额 ==========
public fun chips_to_call(round: &BettingRound, seat_bet: u64): u64 {
    if (round.current_bet > seat_bet) { round.current_bet - seat_bet } else { 0 }
}

// ========== 验证动作 ==========
public fun can_check(round: &BettingRound, seat_bet: u64): bool {
    chips_to_call(round, seat_bet) == 0
}

public fun can_call(round: &BettingRound, seat_bet: u64, _stack: u64): bool {
    chips_to_call(round, seat_bet) > 0
}

public fun can_raise(round: &BettingRound, seat_bet: u64, stack: u64): bool {
    let to_call = chips_to_call(round, seat_bet);
    stack > to_call && (stack - to_call) >= round.min_raise
}

// 获取可用动作（位掩码）
public fun available_actions(round: &BettingRound, seat_bet: u64, stack: u64): u8 {
    let mut actions = ACTION_FOLD;
    if (can_check(round, seat_bet)) { actions = actions | ACTION_CHECK };
    if (can_call(round, seat_bet, stack)) { actions = actions | ACTION_CALL };
    if (can_raise(round, seat_bet, stack)) { actions = actions | ACTION_RAISE };
    actions
}

// ========== 处理动作 ==========
public fun process_call(round: &mut BettingRound, seat_bet: u64, stack: u64): u64 {
    let to_call = chips_to_call(round, seat_bet);
    assert!(to_call > 0, ECannotCall);
    let actual = if (to_call > stack) { stack } else { to_call };
    round.actions_taken = round.actions_taken + 1;
    actual
}

public fun process_raise(
    round: &mut BettingRound,
    total_bet: u64,
    seat_id: u64,
    seat_bet: u64,
    stack: u64,
): u64 {
    let raise_amount = total_bet - round.current_bet;
    assert!(raise_amount >= round.min_raise, EInvalidRaiseAmount);
    let needed = total_bet - seat_bet;
    assert!(needed <= stack, ECannotRaise);

    round.current_bet = total_bet;
    round.min_raise = raise_amount;
    round.last_raiser_seat = option::some(seat_id);
    round.actions_taken = round.actions_taken + 1;
    needed
}

public fun process_check(round: &mut BettingRound, seat_bet: u64) {
    assert!(chips_to_call(round, seat_bet) == 0, ECannotCheck);
    round.actions_taken = round.actions_taken + 1;
}

public fun process_fold(round: &mut BettingRound) {
    round.actions_taken = round.actions_taken + 1;
}

// ========== 动作常量访问 ==========
public fun action_fold(): u8 { ACTION_FOLD }
public fun action_check(): u8 { ACTION_CHECK }
public fun action_call(): u8 { ACTION_CALL }
public fun action_raise(): u8 { ACTION_RAISE }
