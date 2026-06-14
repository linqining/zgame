#[test_only]
module texas_poker::table_test_helpers;

/// 测试辅助模块
/// 提供绕过 ZK 验证的 test_only 函数，用于测试状态机逻辑
///
/// 使用方法:
/// 1. create_table_with_players: 创建牌桌并加入 N 个玩家
/// 2. start_hand_for_test: 开始手牌
/// 3. complete_shuffle_for_test: 绕过 ZK 完成洗牌
/// 4. complete_preflop_reveal_for_test: 绕过 ZK 完成 preflop 揭示
/// 5. 模拟下注: fold/check/call/raise
/// 6. complete_community_reveal_for_test: 绕过 ZK 完成公共牌揭示
/// 7. settle_hand: 结算

use sui::tx_context::TxContext;
use std::string;
use texas_poker::table;
use texas_poker::table_constants;

// ========== 常量 ==========
const ADMIN: address = @0xA;
const PLAYER1: address = @0xB;
const PLAYER2: address = @0xC;
const PLAYER3: address = @0xD;
const PLAYER4: address = @0xE;
const PLAYER5: address = @0xF;
const PLAYER6: address = @0x10;
const PLAYER7: address = @0x11;
const PLAYER8: address = @0x12;
const PLAYER9: address = @0x13;

// ========== 地址访问器 ==========
public fun admin(): address { ADMIN }
public fun player1(): address { PLAYER1 }
public fun player2(): address { PLAYER2 }
public fun player3(): address { PLAYER3 }
public fun player4(): address { PLAYER4 }
public fun player5(): address { PLAYER5 }
public fun player6(): address { PLAYER6 }
public fun player7(): address { PLAYER7 }
public fun player8(): address { PLAYER8 }
public fun player9(): address { PLAYER9 }

/// 获取前 N 个玩家地址
public fun get_players(n: u64): vector<address> {
    let mut players = vector[];
    let mut i = 0;
    while (i < n) {
        players.push_back(get_player(i));
        i = i + 1;
    };
    players
}

public fun get_player(index: u64): address {
    if (index == 0) PLAYER1
    else if (index == 1) PLAYER2
    else if (index == 2) PLAYER3
    else if (index == 3) PLAYER4
    else if (index == 4) PLAYER5
    else if (index == 5) PLAYER6
    else if (index == 6) PLAYER7
    else if (index == 7) PLAYER8
    else PLAYER9
}

// ========== 牌桌创建与设置 ==========

/// 创建牌桌并加入指定数量的玩家
public fun create_table_with_players(
    num_players: u64,
    buy_in: u64,
    ctx: &mut TxContext,
): table::Table {
    let mut t = table::create_table_for_test(
        string::utf8(b"TestTable"),
        10,  // small_blind
        20,  // big_blind
        9,   // max_players
        ctx,
    );
    let mut i = 0;
    while (i < num_players) {
        table::join_table_for_test(&mut t, i, get_player(i), buy_in);
        i = i + 1;
    };
    t
}

/// 开始手牌
public fun start_hand_for_test(table: &mut table::Table, ctx: &mut TxContext) {
    table::start_hand(table, ctx);
}

// ========== 绕过 ZK 的状态推进函数 ==========

/// 绕过 ZK 验证，直接完成洗牌阶段
/// 设置加密牌组并推进到 preflop reveal
public fun complete_shuffle_for_test(table: &mut table::Table, ctx: &mut TxContext) {
    // 直接调用内部的 test_only 推进函数
    table::advance_shuffle_for_test(table, ctx);
}

/// 绕过 ZK 验证，直接完成 preflop 揭示
public fun complete_preflop_reveal_for_test(table: &mut table::Table) {
    table::complete_reveal_phase_for_test(table);
}

/// 绕过 ZK 验证，直接完成公共牌揭示
public fun complete_community_reveal_for_test(table: &mut table::Table) {
    table::complete_reveal_phase_for_test(table);
}

/// 绕过 ZK 验证，直接完成 showdown 揭示
public fun complete_showdown_reveal_for_test(table: &mut table::Table) {
    table::complete_reveal_phase_for_test(table);
}

// ========== 下注辅助 ==========

/// 玩家弃牌
public fun do_fold(table: &mut table::Table, seat_index: u64, ctx: &mut TxContext) {
    table::fold(table, seat_index, ctx);
}

/// 玩家过牌
public fun do_check(table: &mut table::Table, seat_index: u64, ctx: &mut TxContext) {
    table::check(table, seat_index, ctx);
}

/// 玩家跟注
public fun do_call(table: &mut table::Table, seat_index: u64, ctx: &mut TxContext) {
    table::call(table, seat_index, ctx);
}

/// 玩家加注
public fun do_raise(table: &mut table::Table, seat_index: u64, total_bet: u64, ctx: &mut TxContext) {
    table::raise(table, seat_index, total_bet, ctx);
}

// ========== 验证辅助 ==========

/// 验证玩家筹码
public fun assert_stack(table: &table::Table, seat_index: u64, expected: u64) {
    assert!(table::seat_stack(table, seat_index) == expected, EAssertFailed);
}

/// 验证底池
public fun assert_pot(table: &table::Table, expected: u64) {
    assert!(table::pot(table) == expected, EAssertFailed);
}

/// 验证轮次状态
public fun assert_round_state(table: &table::Table, expected: u8) {
    assert!(table::round_state(table) == expected, EAssertFailed);
}

/// 验证玩家是否弃牌
public fun assert_folded(table: &table::Table, seat_index: u64, expected: bool) {
    assert!(table::seat_folded(table, seat_index) == expected, EAssertFailed);
}

/// 验证玩家总下注
public fun assert_total_bet(table: &table::Table, seat_index: u64, expected: u64) {
    assert!(table::seat_total_bet(table, seat_index) == expected, EAssertFailed);
}

// ========== 错误码 ==========
#[error]
const EAssertFailed: vector<u8> = b"Test assertion failed";
