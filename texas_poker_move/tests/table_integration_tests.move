#[test_only]
module texas_poker::table_integration_tests;

/// 集成测试: 完整游戏流程
/// 从创建牌桌 → 发牌 → 下注 → 摊牌 → 结算 → 下一局
///
/// 测试场景:
/// 1. full_hand_all_check: 3人完整流程，全部过牌到摊牌
/// 2. full_hand_with_fold: 3人流程，中途弃牌
/// 3. full_hand_with_raise: 3人流程，含加注
/// 4. heads_up_flow: 2人单挑流程
/// 5. all_in_scenario: 全押场景
/// 6. kick_player_flow: 踢人后继续游戏
/// 7. multi_hand_flow: 连续多手牌

use sui::test_scenario;
use texas_poker::table;
use texas_poker::table_constants;
use texas_poker::table_test_helpers;
use std::string;

// ========== 测试 1: 完整流程 - 全部过牌到摊牌 ==========

#[test]
fun full_hand_all_check() {
    let mut scenario = test_scenario::begin(table_test_helpers::admin());
    let ctx = scenario.ctx();

    // 1. 创建牌桌，3 人加入
    let mut t = table_test_helpers::create_table_with_players(3, 1000, ctx);
    assert!(table::active_count(&t) == 3);

    // 2. 开始手牌
    scenario.next_tx(table_test_helpers::admin());
    table::start_hand(&mut t, scenario.ctx());
    // start_hand 后进入洗牌阶段，round_state 仍为 WAITING
    assert!(table::round_state(&t) == table_constants::round_waiting());

    // 3. 绕过 ZK 完成洗牌
    table::advance_shuffle_for_test(&mut t, scenario.ctx());
    // 洗牌完成后进入 preflop reveal
    assert!(table::reveal_phase(&t) == table_constants::reveal_phase_preflop());

    // 4. 绕过 ZK 完成 preflop reveal
    table::complete_reveal_phase_for_test(&mut t);
    // 进入 preflop 下注，盲注已发
    assert!(table::round_state(&t) == table_constants::round_preflop());
    assert!(table::betting_round_exists(&t));

    // 验证盲注: button=1, SB=2(10), BB=0(20)
    assert!(table::seat_bet(&t, 0) == 20); // BB
    assert!(table::seat_bet(&t, 2) == 10); // SB
    assert!(table::current_turn(&t).is_some() && *table::current_turn(&t).borrow() == 1);

    // 5. Preflop 下注: 全部跟注
    // Seat 1 (PLAYER2) calls 20
    scenario.next_tx(table_test_helpers::player2());
    table::call(&mut t, 1, scenario.ctx());
    assert!(table::seat_bet(&t, 1) == 20);

    // Seat 2 (PLAYER3) calls 20 (已有 10, 补 10)
    scenario.next_tx(table_test_helpers::player3());
    table::call(&mut t, 2, scenario.ctx());
    assert!(table::seat_bet(&t, 2) == 20);

    // Seat 0 (PLAYER1) checks (BB 已投 20)
    scenario.next_tx(table_test_helpers::player1());
    table::check(&mut t, 0, scenario.ctx());

    // Preflop 下注完成，进入 flop reveal
    assert!(table::reveal_phase(&t) == table_constants::reveal_phase_flop());
    assert!(table::pot(&t) == 60); // 20*3 = 60

    // 6. 完成 flop reveal
    table::complete_reveal_phase_for_test(&mut t);
    assert!(table::round_state(&t) == table_constants::round_flop());
    assert!(table::community_cards_count(&t) == 3);

    // 7. Flop 下注: 全部过牌
    // Postflop first to act = seat after button = seat 2
    assert!(table::current_turn(&t).is_some() && *table::current_turn(&t).borrow() == 2);
    scenario.next_tx(table_test_helpers::player3());
    table::check(&mut t, 2, scenario.ctx());

    scenario.next_tx(table_test_helpers::player1());
    table::check(&mut t, 0, scenario.ctx());

    scenario.next_tx(table_test_helpers::player2());
    table::check(&mut t, 1, scenario.ctx());

    // Flop 下注完成，进入 turn reveal
    assert!(table::reveal_phase(&t) == table_constants::reveal_phase_turn());

    // 8. 完成 turn reveal
    table::complete_reveal_phase_for_test(&mut t);
    assert!(table::round_state(&t) == table_constants::round_turn());
    assert!(table::community_cards_count(&t) == 4);

    // 9. Turn 下注: 全部过牌
    scenario.next_tx(table_test_helpers::player3());
    table::check(&mut t, 2, scenario.ctx());
    scenario.next_tx(table_test_helpers::player1());
    table::check(&mut t, 0, scenario.ctx());
    scenario.next_tx(table_test_helpers::player2());
    table::check(&mut t, 1, scenario.ctx());

    // 进入 river reveal
    assert!(table::reveal_phase(&t) == table_constants::reveal_phase_river());

    // 10. 完成 river reveal
    table::complete_reveal_phase_for_test(&mut t);
    assert!(table::round_state(&t) == table_constants::round_river());
    assert!(table::community_cards_count(&t) == 5);

    // 11. River 下注: 全部过牌
    scenario.next_tx(table_test_helpers::player3());
    table::check(&mut t, 2, scenario.ctx());
    scenario.next_tx(table_test_helpers::player1());
    table::check(&mut t, 0, scenario.ctx());
    scenario.next_tx(table_test_helpers::player2());
    table::check(&mut t, 1, scenario.ctx());

    // River 下注完成，进入 showdown reveal
    assert!(table::reveal_phase(&t) == table_constants::reveal_phase_showdown());

    // 12. 完成 showdown reveal → 自动结算
    table::complete_reveal_phase_for_test(&mut t);

    // 验证结算: pot 应该为 0（已分配）
    // 注意: settle_hand 后 round_state 可能被 reset
    // 验证总筹码守恒: 3 * 1000 = 3000
    let total_chips = table::seat_stack(&t, 0) + table::seat_stack(&t, 1) + table::seat_stack(&t, 2);
    assert!(total_chips == 3000);

    table::destroy_table(t);
    scenario.end();
}

// ========== 测试 2: 中途弃牌 ==========

#[test]
fun full_hand_with_fold() {
    let mut scenario = test_scenario::begin(table_test_helpers::admin());
    let ctx = scenario.ctx();

    let mut t = table_test_helpers::create_table_with_players(3, 1000, ctx);

    // 开始手牌
    scenario.next_tx(table_test_helpers::admin());
    table::start_hand(&mut t, scenario.ctx());
    table::advance_shuffle_for_test(&mut t, scenario.ctx());
    table::complete_reveal_phase_for_test(&mut t);

    // Preflop: Seat 1 calls, Seat 2 folds, Seat 0 checks
    scenario.next_tx(table_test_helpers::player2());
    table::call(&mut t, 1, scenario.ctx());

    // Seat 2 folds
    scenario.next_tx(table_test_helpers::player3());
    table::fold(&mut t, 2, scenario.ctx());
    assert!(table::seat_folded(&t, 2));

    // 只剩 2 人，继续下注
    // Seat 0 (BB) checks
    scenario.next_tx(table_test_helpers::player1());
    table::check(&mut t, 0, scenario.ctx());

    // 进入 flop reveal
    assert!(table::reveal_phase(&t) == table_constants::reveal_phase_flop());

    // 完成 flop
    table::complete_reveal_phase_for_test(&mut t);

    // Flop: Seat 2 已 fold, 只有 Seat 0 和 Seat 1
    // Postflop first to act = seat after button = seat 2 (folded) → skip → seat 0
    scenario.next_tx(table_test_helpers::player1());
    table::check(&mut t, 0, scenario.ctx());

    scenario.next_tx(table_test_helpers::player2());
    table::check(&mut t, 1, scenario.ctx());

    // 进入 turn
    assert!(table::reveal_phase(&t) == table_constants::reveal_phase_turn());
    table::complete_reveal_phase_for_test(&mut t);

    // Turn: check check
    scenario.next_tx(table_test_helpers::player1());
    table::check(&mut t, 0, scenario.ctx());
    scenario.next_tx(table_test_helpers::player2());
    table::check(&mut t, 1, scenario.ctx());

    // River
    assert!(table::reveal_phase(&t) == table_constants::reveal_phase_river());
    table::complete_reveal_phase_for_test(&mut t);

    // River: check check
    scenario.next_tx(table_test_helpers::player1());
    table::check(&mut t, 0, scenario.ctx());
    scenario.next_tx(table_test_helpers::player2());
    table::check(&mut t, 1, scenario.ctx());

    // Showdown
    assert!(table::reveal_phase(&t) == table_constants::reveal_phase_showdown());
    table::complete_reveal_phase_for_test(&mut t);

    // 验证筹码守恒
    let total = table::seat_stack(&t, 0) + table::seat_stack(&t, 1) + table::seat_stack(&t, 2);
    assert!(total == 3000);

    table::destroy_table(t);
    scenario.end();
}

// ========== 测试 3: 加注场景 ==========

#[test]
fun full_hand_with_raise() {
    let mut scenario = test_scenario::begin(table_test_helpers::admin());
    let ctx = scenario.ctx();

    let mut t = table_test_helpers::create_table_with_players(3, 1000, ctx);

    // 开始
    scenario.next_tx(table_test_helpers::admin());
    table::start_hand(&mut t, scenario.ctx());
    table::advance_shuffle_for_test(&mut t, scenario.ctx());
    table::complete_reveal_phase_for_test(&mut t);

    // Preflop: Seat 1 raises to 60
    scenario.next_tx(table_test_helpers::player2());
    table::raise(&mut t, 1, 60, scenario.ctx());
    assert!(table::seat_bet(&t, 1) == 60);
    assert!(table::seat_stack(&t, 1) == 940);

    // Seat 2 calls 60 (已有 10, 补 50)
    scenario.next_tx(table_test_helpers::player3());
    table::call(&mut t, 2, scenario.ctx());
    assert!(table::seat_bet(&t, 2) == 60);

    // Seat 0 calls 60 (已有 20, 补 40)
    scenario.next_tx(table_test_helpers::player1());
    table::call(&mut t, 0, scenario.ctx());
    // 下注轮完成后 bets 被收入 pot，seat.bet 清零
    assert!(table::seat_total_bet(&t, 0) == 60);

    // Preflop 完成, pot = 180
    assert!(table::reveal_phase(&t) == table_constants::reveal_phase_flop());
    assert!(table::pot(&t) == 180);

    // 完成 flop
    table::complete_reveal_phase_for_test(&mut t);

    // Flop: Seat 2 checks, Seat 0 checks, Seat 1 raises to 100
    scenario.next_tx(table_test_helpers::player3());
    table::check(&mut t, 2, scenario.ctx());

    scenario.next_tx(table_test_helpers::player1());
    table::check(&mut t, 0, scenario.ctx());

    scenario.next_tx(table_test_helpers::player2());
    table::raise(&mut t, 1, 100, scenario.ctx());
    assert!(table::seat_bet(&t, 1) == 100);

    // Seat 2 folds
    scenario.next_tx(table_test_helpers::player3());
    table::fold(&mut t, 2, scenario.ctx());

    // Seat 0 calls 100
    scenario.next_tx(table_test_helpers::player1());
    table::call(&mut t, 0, scenario.ctx());
    // 下注轮完成后 bets 被收入 pot，seat.bet 清零
    // total_bet 累计: preflop(60) + flop(100) = 160
    assert!(table::seat_total_bet(&t, 0) == 160);

    // Flop 完成, pot = 180 + 200 = 380
    assert!(table::reveal_phase(&t) == table_constants::reveal_phase_turn());
    assert!(table::pot(&t) == 380);

    // 快速完成剩余轮次
    table::complete_reveal_phase_for_test(&mut t);
    // Turn: check check
    scenario.next_tx(table_test_helpers::player1());
    table::check(&mut t, 0, scenario.ctx());
    scenario.next_tx(table_test_helpers::player2());
    table::check(&mut t, 1, scenario.ctx());

    table::complete_reveal_phase_for_test(&mut t);
    // River: check check
    scenario.next_tx(table_test_helpers::player1());
    table::check(&mut t, 0, scenario.ctx());
    scenario.next_tx(table_test_helpers::player2());
    table::check(&mut t, 1, scenario.ctx());

    // Showdown
    table::complete_reveal_phase_for_test(&mut t);

    // 验证筹码守恒
    let total = table::seat_stack(&t, 0) + table::seat_stack(&t, 1) + table::seat_stack(&t, 2);
    assert!(total == 3000);

    table::destroy_table(t);
    scenario.end();
}

// ========== 测试 4: 单人剩出（无摊牌） ==========

#[test]
fun hand_won_by_fold() {
    let mut scenario = test_scenario::begin(table_test_helpers::admin());
    let ctx = scenario.ctx();

    let mut t = table_test_helpers::create_table_with_players(3, 1000, ctx);

    // 开始
    scenario.next_tx(table_test_helpers::admin());
    table::start_hand(&mut t, scenario.ctx());
    table::advance_shuffle_for_test(&mut t, scenario.ctx());
    table::complete_reveal_phase_for_test(&mut t);

    // Preflop: Seat 1 calls, Seat 2 folds, Seat 0 folds → Seat 1 wins
    scenario.next_tx(table_test_helpers::player2());
    table::call(&mut t, 1, scenario.ctx());

    scenario.next_tx(table_test_helpers::player3());
    table::fold(&mut t, 2, scenario.ctx());

    scenario.next_tx(table_test_helpers::player1());
    table::fold(&mut t, 0, scenario.ctx());

    // 只剩 Seat 1, end_without_showdown
    // Seat 1 应该赢得 pot = 20(BB) + 20(call) + 10(SB) = 50
    // 验证 Seat 1 的筹码增加
    assert!(table::seat_stack(&t, 1) == 1000 - 20 + 50); // 1030

    // 验证筹码守恒
    let total = table::seat_stack(&t, 0) + table::seat_stack(&t, 1) + table::seat_stack(&t, 2);
    assert!(total == 3000);

    table::destroy_table(t);
    scenario.end();
}

// ========== 测试 5: 全押场景 ==========

#[test]
fun all_in_scenario() {
    let mut scenario = test_scenario::begin(table_test_helpers::admin());
    let ctx = scenario.ctx();

    // 创建牌桌，Player3 只有 30 筹码（不够大盲）
    let mut t = table::create_table_for_test(
        string::utf8(b"TestTable"), 10, 20, 9, ctx,
    );
    table::join_table_for_test(&mut t, 0, table_test_helpers::player1(), 1000);
    table::join_table_for_test(&mut t, 1, table_test_helpers::player2(), 1000);
    table::join_table_for_test(&mut t, 2, table_test_helpers::player3(), 30);

    // 开始
    scenario.next_tx(table_test_helpers::admin());
    table::start_hand(&mut t, scenario.ctx());
    table::advance_shuffle_for_test(&mut t, scenario.ctx());
    table::complete_reveal_phase_for_test(&mut t);

    // SB=2(10), BB=0(20), first=1
    // Seat 2 只有 30, SB=10, 还剩 20
    assert!(table::seat_stack(&t, 2) == 20);
    assert!(table::seat_bet(&t, 2) == 10);

    // Seat 1 raises to 100
    scenario.next_tx(table_test_helpers::player2());
    table::raise(&mut t, 1, 100, scenario.ctx());

    // Seat 2 all-in (只有 20, 需要补 20 到 30)
    scenario.next_tx(table_test_helpers::player3());
    table::call(&mut t, 2, scenario.ctx());
    assert!(table::seat_all_in(&t, 2));
    assert!(table::seat_stack(&t, 2) == 0);

    // Seat 0 calls 100
    scenario.next_tx(table_test_helpers::player1());
    table::call(&mut t, 0, scenario.ctx());

    // 进入 flop
    assert!(table::reveal_phase(&t) == table_constants::reveal_phase_flop());

    // 完成 flop
    table::complete_reveal_phase_for_test(&mut t);

    // Seat 2 all-in, 不参与下注
    // Flop: Seat 2 skip (all_in), Seat 0 checks, Seat 1 checks
    scenario.next_tx(table_test_helpers::player1());
    table::check(&mut t, 0, scenario.ctx());
    scenario.next_tx(table_test_helpers::player2());
    table::check(&mut t, 1, scenario.ctx());

    // Turn
    table::complete_reveal_phase_for_test(&mut t);
    scenario.next_tx(table_test_helpers::player1());
    table::check(&mut t, 0, scenario.ctx());
    scenario.next_tx(table_test_helpers::player2());
    table::check(&mut t, 1, scenario.ctx());

    // River
    table::complete_reveal_phase_for_test(&mut t);
    scenario.next_tx(table_test_helpers::player1());
    table::check(&mut t, 0, scenario.ctx());
    scenario.next_tx(table_test_helpers::player2());
    table::check(&mut t, 1, scenario.ctx());

    // Showdown
    table::complete_reveal_phase_for_test(&mut t);

    // 验证筹码守恒
    let total = table::seat_stack(&t, 0) + table::seat_stack(&t, 1) + table::seat_stack(&t, 2);
    assert!(total == 2030); // 1000 + 1000 + 30

    table::destroy_table(t);
    scenario.end();
}

// ========== 测试 6: 连续多手牌 ==========

#[test]
fun multi_hand_flow() {
    let mut scenario = test_scenario::begin(table_test_helpers::admin());
    let ctx = scenario.ctx();

    let mut t = table_test_helpers::create_table_with_players(3, 1000, ctx);

    // 第一手
    scenario.next_tx(table_test_helpers::admin());
    table::start_hand(&mut t, scenario.ctx());
    table::advance_shuffle_for_test(&mut t, scenario.ctx());
    table::complete_reveal_phase_for_test(&mut t);

    // 全部 fold 到 Seat 1
    scenario.next_tx(table_test_helpers::player2());
    table::call(&mut t, 1, scenario.ctx());
    scenario.next_tx(table_test_helpers::player3());
    table::fold(&mut t, 2, scenario.ctx());
    scenario.next_tx(table_test_helpers::player1());
    table::fold(&mut t, 0, scenario.ctx());

    // 第一手结束, Seat 1 赢
    assert!(table::round_state(&t) == table_constants::round_waiting());

    // 第二手
    scenario.next_tx(table_test_helpers::admin());
    table::start_hand(&mut t, scenario.ctx());
    table::advance_shuffle_for_test(&mut t, scenario.ctx());
    table::complete_reveal_phase_for_test(&mut t);

    // 这次 button 移动了
    // 验证 button 从 1 移动到 2
    assert!(table::button(&t) == 2);

    // 全部 call 到摊牌
    // button=2, SB=0, BB=1, first to act preflop = after BB = 2
    scenario.next_tx(table_test_helpers::player3());
    table::call(&mut t, 2, scenario.ctx());
    scenario.next_tx(table_test_helpers::player1());
    table::call(&mut t, 0, scenario.ctx());
    scenario.next_tx(table_test_helpers::player2());
    table::check(&mut t, 1, scenario.ctx());

    // 完成 flop, turn, river, showdown
    table::complete_reveal_phase_for_test(&mut t);
    scenario.next_tx(table_test_helpers::player1());
    table::check(&mut t, 0, scenario.ctx());
    scenario.next_tx(table_test_helpers::player2());
    table::check(&mut t, 1, scenario.ctx());
    scenario.next_tx(table_test_helpers::player3());
    table::check(&mut t, 2, scenario.ctx());

    table::complete_reveal_phase_for_test(&mut t);
    scenario.next_tx(table_test_helpers::player1());
    table::check(&mut t, 0, scenario.ctx());
    scenario.next_tx(table_test_helpers::player2());
    table::check(&mut t, 1, scenario.ctx());
    scenario.next_tx(table_test_helpers::player3());
    table::check(&mut t, 2, scenario.ctx());

    table::complete_reveal_phase_for_test(&mut t);
    scenario.next_tx(table_test_helpers::player1());
    table::check(&mut t, 0, scenario.ctx());
    scenario.next_tx(table_test_helpers::player2());
    table::check(&mut t, 1, scenario.ctx());
    scenario.next_tx(table_test_helpers::player3());
    table::check(&mut t, 2, scenario.ctx());

    table::complete_reveal_phase_for_test(&mut t);

    // 验证筹码守恒
    let total = table::seat_stack(&t, 0) + table::seat_stack(&t, 1) + table::seat_stack(&t, 2);
    assert!(total == 3000);

    table::destroy_table(t);
    scenario.end();
}

// ========== 测试 7: 2人单挑 ==========

#[test]
fun heads_up_flow() {
    let mut scenario = test_scenario::begin(table_test_helpers::admin());
    let ctx = scenario.ctx();

    let mut t = table_test_helpers::create_table_with_players(2, 1000, ctx);

    // 开始
    scenario.next_tx(table_test_helpers::admin());
    table::start_hand(&mut t, scenario.ctx());
    table::advance_shuffle_for_test(&mut t, scenario.ctx());
    table::complete_reveal_phase_for_test(&mut t);

    // Heads-up: button=1, SB=button=1, BB=0, first_to_act=SB=1
    assert!(table::seat_bet(&t, 1) == 10); // SB
    assert!(table::seat_bet(&t, 0) == 20); // BB
    assert!(table::current_turn(&t).borrow() == &1); // SB acts first

    // Preflop: SB calls, BB checks
    scenario.next_tx(table_test_helpers::player2());
    table::call(&mut t, 1, scenario.ctx());
    scenario.next_tx(table_test_helpers::player1());
    table::check(&mut t, 0, scenario.ctx());

    // Flop
    assert!(table::reveal_phase(&t) == table_constants::reveal_phase_flop());
    table::complete_reveal_phase_for_test(&mut t);

    // Postflop: first to act = after button = seat 0 (BB)
    scenario.next_tx(table_test_helpers::player1());
    table::check(&mut t, 0, scenario.ctx());
    scenario.next_tx(table_test_helpers::player2());
    table::check(&mut t, 1, scenario.ctx());

    // Turn
    table::complete_reveal_phase_for_test(&mut t);
    scenario.next_tx(table_test_helpers::player1());
    table::check(&mut t, 0, scenario.ctx());
    scenario.next_tx(table_test_helpers::player2());
    table::check(&mut t, 1, scenario.ctx());

    // River
    table::complete_reveal_phase_for_test(&mut t);
    scenario.next_tx(table_test_helpers::player1());
    table::check(&mut t, 0, scenario.ctx());
    scenario.next_tx(table_test_helpers::player2());
    table::check(&mut t, 1, scenario.ctx());

    // Showdown
    table::complete_reveal_phase_for_test(&mut t);

    // 验证筹码守恒
    let total = table::seat_stack(&t, 0) + table::seat_stack(&t, 1);
    assert!(total == 2000);

    table::destroy_table(t);
    scenario.end();
}
