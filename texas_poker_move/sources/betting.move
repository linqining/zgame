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
// M-P11: actions_taken 统计所有动作（含 fold）。
// 设计意图：用于判断 betting round 是否完成（所有活跃玩家都已行动）。
// fold 虽然使玩家退出，但仍计入 actions_taken 以反映"该座位已处理"。
// 如需单独统计非 fold 动作，应新增 active_actions_taken 字段。
public struct BettingRound has store, drop {
    current_bet: u64,
    min_raise: u64,
    big_blind: u64,
    last_raiser_seat: Option<u64>,
    actions_taken: u64,
}

// ========== 构造函数 ==========
public fun new_preflop(big_blind: u64): BettingRound {
    assert!(big_blind > 0, EInvalidRaiseAmount);
    BettingRound {
        current_bet: big_blind,
        min_raise: big_blind,
        big_blind,
        last_raiser_seat: option::none(),
        actions_taken: 0,
    }
}

public fun new_postflop(big_blind: u64): BettingRound {
    assert!(big_blind > 0, EInvalidRaiseAmount);
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

// M-P12: stack 参数用于校验玩家有筹码跟注（stack > 0）。
// 原实现忽略 stack，现增加 stack > 0 检查以反映语义。
public fun can_call(round: &BettingRound, seat_bet: u64, stack: u64): bool {
    chips_to_call(round, seat_bet) > 0 && stack > 0
}

public fun can_raise(round: &BettingRound, seat_bet: u64, stack: u64): bool {
    let to_call = chips_to_call(round, seat_bet);
    // M-D7 修复：玩家有筹码超出跟注部分即可加注（包括 all-in 小于 min_raise 的情况）
    stack > to_call
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
    // M-D8 修复：在减法前添加 assert 校验，防止 u64 减法下溢
    assert!(total_bet > round.current_bet, EInvalidRaiseAmount);
    assert!(total_bet > seat_bet, EInvalidRaiseAmount);
    let raise_amount = total_bet - round.current_bet;
    let needed = total_bet - seat_bet;
    assert!(needed <= stack, ECannotRaise);

    // M-D7 修复：允许 all-in 小于 min_raise，但不更新 min_raise 和 last_raiser_seat
    // （不重新打开行动权），仅当非 all-in 时才强制 min_raise 检查并更新状态
    // M1 修复：满足 min_raise 的 all-in 也应更新 min_raise 和 last_raiser_seat（重新打开行动权）
    if (needed == stack) {
        // all-in 情况：仅当满足 min_raise 时才更新状态（重新打开行动权）
        if (raise_amount >= round.min_raise) {
            round.min_raise = raise_amount;
            round.last_raiser_seat = option::some(seat_id);
        };
        // 短 all-in（raise_amount < min_raise）：不更新，不重新打开行动权
    } else {
        // 非 all-in：强制 min_raise 检查并更新状态
        assert!(raise_amount >= round.min_raise, EInvalidRaiseAmount);
        round.min_raise = raise_amount;
        round.last_raiser_seat = option::some(seat_id);
    };

    round.current_bet = total_bet;
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
