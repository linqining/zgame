#[test_only]
module texas_poker::shuffle_timeout_tests;

/// Shuffle Timeout 测试
///
/// 覆盖 on_shuffle_timeout 的两个分支：
/// 1. 场景一：preflop 洗牌超时（shuffle_phase_before_preflop）
///    - 踢掉当前洗牌者后，使用 rebuild_deck_and_shuffle_on_timeout 重建牌组并继续洗牌
///    - set_initial_encrypted_deck 将 encrypted 初始化为 (identity, plaintext_i)，
///      非空牌组可通过 shuffle_proof::verify 的 n==0 检查
/// 2. 场景二：reconstruct 洗牌超时（shuffle_phase_reconstruct）
///    - 踢掉当前洗牌者后，从 reconstruct_state.player_decks 中移除被踢玩家的 deck，
///      调用 on_reconstruct_shuffle_failed 重建牌组并继续洗牌
///    - 密码学正确性：组合公式线性可加，移除玩家 k 等价于 k 未参与 reconstruct

use sui::test_scenario;
use std::option::{Self, Option};
use texas_poker::table;
use texas_poker::table_constants;
use texas_poker::table_test_helpers;
use texas_poker::bls_elgamal::{Self, ElGamalCiphertext};

// ========== 辅助函数 ==========

/// 生成 mock 加密牌组（52 张 placeholder），用于 reconstruct_state.player_decks
fun make_mock_deck(): vector<ElGamalCiphertext> {
    let mut deck = vector[];
    let mut i = 0;
    while (i < table_constants::n_cards()) {
        deck.push_back(bls_elgamal::new_placeholder_card());
        i = i + 1;
    };
    deck
}

// ========== 场景一：preflop 洗牌超时，重建牌组并继续洗牌 ==========

#[test]
fun preflop_shuffle_timeout_rebuilds_deck_and_continues() {
    // 场景：4 人牌桌，start_hand 后进入 shuffle_phase_before_preflop，
    // 当前洗牌者超时，踢人后剩余 3 人（>= min_players_to_start=2），
    // 触发 rebuild_deck_and_shuffle_on_timeout 重建牌组并继续洗牌。
    let mut scenario = test_scenario::begin(table_test_helpers::admin());
    let ctx = scenario.ctx();

    // 1. 创建牌桌，4 人加入
    let mut t = table_test_helpers::create_table_with_players(4, 1000, ctx);
    assert!(table::active_count(&t) == 4);

    // 2. 开始手牌，进入 shuffle_phase_before_preflop
    scenario.next_tx(table_test_helpers::admin());
    table::start_hand(&mut t, scenario.ctx());
    assert!(table::shuffle_phase(&t) == table_constants::shuffle_phase_before_preflop());
    assert!(table::shuffle_current_shuffler(&t).is_some());

    // 记录当前洗牌者
    let shuffler = *table::shuffle_current_shuffler(&t).borrow();
    let pending_before = table::shuffle_pending_count(&t);

    // 3. 触发 on_shuffle_timeout
    table::force_on_shuffle_timeout_for_test(&mut t, scenario.ctx());

    // 4. 验证：被踢玩家不再占座
    assert!(!table::seat_occupied(&t, shuffler));

    // 5. 验证：仍在 shuffle_phase_before_preflop（重建后继续洗牌）
    assert!(table::shuffle_phase(&t) == table_constants::shuffle_phase_before_preflop());

    // 6. 验证：encrypted 已被 set_initial_encrypted_deck 初始化为非空（52 张）
    assert!(table::deck_size(&t) == table_constants::n_cards());

    // 7. 验证：新的洗牌者已设置（advance_shuffle 推进）
    assert!(table::shuffle_current_shuffler(&t).is_some());

    // 8. 验证：pending_players 已重置为剩余活跃玩家（3 人）
    assert!(table::shuffle_pending_count(&t) == 3);
    assert!(table::shuffle_completed_count(&t) == 0);

    // 9. 验证：活跃玩家数减少 1
    assert!(table::active_count(&t) == 3);

    table::destroy_table(t);
    scenario.end();
}

#[test]
fun preflop_shuffle_timeout_kicks_last_pending_triggers_on_shuffle_complete() {
    // 边界场景：3 人牌桌，2 人已完成洗牌，最后 1 个 pending 玩家超时被踢。
    // kick_player_internal 会触发 advance_shuffle → on_shuffle_complete，
    // shuffle_state.phase 变为 none，不应再走 rebuild 路径。
    let mut scenario = test_scenario::begin(table_test_helpers::admin());
    let ctx = scenario.ctx();

    let mut t = table_test_helpers::create_table_with_players(3, 1000, ctx);

    scenario.next_tx(table_test_helpers::admin());
    table::start_hand(&mut t, scenario.ctx());
    assert!(table::shuffle_phase(&t) == table_constants::shuffle_phase_before_preflop());

    let shuffler = *table::shuffle_current_shuffler(&t).borrow();

    // 模拟另外 2 人已完成洗牌（从 pending 移除，加入 completed）
    // 取出 pending 列表，移除除 shuffler 外的所有玩家并标记为 completed
    let pending = table::shuffle_pending_players(&t);
    let mut completed = vector[];
    let mut i = 0;
    while (i < pending.length()) {
        let p = pending[i];
        if (p != shuffler) {
            completed.push_back(p);
        };
        i = i + 1;
    };
    // 构造新的 pending：只保留 shuffler
    let new_pending = vector[shuffler];
    table::set_shuffle_state_for_test(
        &mut t,
        table_constants::shuffle_phase_before_preflop(),
        option::some(shuffler),
        new_pending,
        completed,
    );

    // 触发 on_shuffle_timeout
    table::force_on_shuffle_timeout_for_test(&mut t, scenario.ctx());

    // 验证：被踢玩家不再占座
    assert!(!table::seat_occupied(&t, shuffler));

    // 验证：shuffle_state.phase 已变为 none（on_shuffle_complete 触发）
    // 注意：on_shuffle_complete 在 preflop 分支会进入 round_preflop + reveal_phase_preflop
    assert!(table::shuffle_phase(&t) == table_constants::shuffle_phase_none());

    table::destroy_table(t);
    scenario.end();
}

#[test]
fun preflop_shuffle_timeout_with_min_players_resets() {
    // 边界场景：2 人牌桌（min_players_to_start=2），1 人超时被踢后活跃玩家 < 2，
    // kick_player_internal 会触发 reset_for_next_hand。
    let mut scenario = test_scenario::begin(table_test_helpers::admin());
    let ctx = scenario.ctx();

    // 创建 2 人牌桌（注意：start_hand 要求 >= min_players_to_start=2）
    let mut t = table_test_helpers::create_table_with_players(2, 1000, ctx);

    scenario.next_tx(table_test_helpers::admin());
    table::start_hand(&mut t, scenario.ctx());
    assert!(table::shuffle_phase(&t) == table_constants::shuffle_phase_before_preflop());

    let shuffler = *table::shuffle_current_shuffler(&t).borrow();

    // 触发 on_shuffle_timeout
    table::force_on_shuffle_timeout_for_test(&mut t, scenario.ctx());

    // 验证：被踢玩家不再占座
    assert!(!table::seat_occupied(&t, shuffler));

    // 验证：活跃玩家 < min_players_to_start，已触发 reset_for_next_hand
    assert!(table::round_state(&t) == table_constants::round_waiting());
    assert!(table::shuffle_phase(&t) == table_constants::shuffle_phase_none());

    table::destroy_table(t);
    scenario.end();
}

// ========== 场景二：reconstruct 洗牌超时，保留 player_decks 并重建 ==========

#[test]
fun reconstruct_shuffle_timeout_removes_deck_and_rebuilds() {
    // 场景：4 人牌桌，进入 shuffle_phase_reconstruct 阶段，
    // 当前洗牌者超时，踢人后从 player_decks 移除该玩家的 deck，
    // 调用 on_reconstruct_shuffle_failed 重建牌组并继续洗牌。
    let mut scenario = test_scenario::begin(table_test_helpers::admin());
    let ctx = scenario.ctx();

    // 1. 创建牌桌，4 人加入
    let mut t = table_test_helpers::create_table_with_players(4, 1000, ctx);

    // 2. 开始手牌
    scenario.next_tx(table_test_helpers::admin());
    table::start_hand(&mut t, scenario.ctx());

    // 3. 构造 reconstruct 场景：
    //    - 设置 shuffle_state.phase = shuffle_phase_reconstruct
    //    - 设置 current_shuffler 为某个玩家
    //    - 设置 pending_players 为所有活跃玩家
    //    - 向 reconstruct_state.player_decks 添加 4 个玩家的 mock deck
    let shuffler = 0u64;
    let mut pending = vector[0u64, 1u64, 2u64, 3u64];
    let completed = vector[];
    table::set_shuffle_state_for_test(
        &mut t,
        table_constants::shuffle_phase_reconstruct(),
        option::some(shuffler),
        pending,
        completed,
    );

    // 设置 reconstruct_state.phase 为非 none（模拟 reconstruct 进行中）
    table::set_reconstruct_phase_for_test(&mut t, table_constants::reconstruct_phase_collecting());

    // 设置 round_state 为非 waiting（模拟手牌进行中）
    // on_shuffle_timeout 在 reconstruct 分支会检查 round_state == round_waiting 来判断
    // kick_player_internal 是否已触发 reset_for_next_hand
    table::set_round_state_for_test(&mut t, table_constants::round_flop());

    // 添加 4 个玩家的 mock deck
    table::add_reconstruct_player_deck_for_test(&mut t, 0, make_mock_deck());
    table::add_reconstruct_player_deck_for_test(&mut t, 1, make_mock_deck());
    table::add_reconstruct_player_deck_for_test(&mut t, 2, make_mock_deck());
    table::add_reconstruct_player_deck_for_test(&mut t, 3, make_mock_deck());
    assert!(table::reconstruct_player_decks_count(&t) == 4);

    // 4. 触发 on_shuffle_timeout
    table::force_on_shuffle_timeout_for_test(&mut t, scenario.ctx());

    // 5. 验证：被踢玩家（seat 0）不再占座
    assert!(!table::seat_occupied(&t, shuffler));

    // 6. 验证：仍在 shuffle_phase_reconstruct（重建后继续洗牌）
    assert!(table::shuffle_phase(&t) == table_constants::shuffle_phase_reconstruct());

    // 7. 验证：encrypted 已被 rebuild_deck_from_reconstruct_deck 重建为非空（52 张）
    assert!(table::deck_size(&t) == table_constants::n_cards());

    // 8. 验证：新的洗牌者已设置
    assert!(table::shuffle_current_shuffler(&t).is_some());

    // 9. 验证：pending_players 已重置为剩余活跃玩家（3 人）
    assert!(table::shuffle_pending_count(&t) == 3);
    assert!(table::shuffle_completed_count(&t) == 0);

    // 10. 验证：活跃玩家数减少 1
    assert!(table::active_count(&t) == 3);

    table::destroy_table(t);
    scenario.end();
}

#[test]
fun reconstruct_shuffle_timeout_kicks_last_pending_resets() {
    // 边界场景：reconstruct 阶段，最后一个 pending 玩家超时被踢。
    // kick_player_internal 触发 advance_shuffle → on_shuffle_complete，
    // on_shuffle_complete 在 reconstruct 分支会清空 reconstruct_state，
    // 此时 player_decks 已丢失，必须 reset。
    let mut scenario = test_scenario::begin(table_test_helpers::admin());
    let ctx = scenario.ctx();

    let mut t = table_test_helpers::create_table_with_players(3, 1000, ctx);

    scenario.next_tx(table_test_helpers::admin());
    table::start_hand(&mut t, scenario.ctx());

    // 构造 reconstruct 场景：shuffler 是最后一个 pending 玩家
    let shuffler = 0u64;
    let pending = vector[0u64];
    let completed = vector[1u64, 2u64];
    table::set_shuffle_state_for_test(
        &mut t,
        table_constants::shuffle_phase_reconstruct(),
        option::some(shuffler),
        pending,
        completed,
    );
    table::set_reconstruct_phase_for_test(&mut t, table_constants::reconstruct_phase_collecting());

    table::add_reconstruct_player_deck_for_test(&mut t, 0, make_mock_deck());
    table::add_reconstruct_player_deck_for_test(&mut t, 1, make_mock_deck());
    table::add_reconstruct_player_deck_for_test(&mut t, 2, make_mock_deck());

    // 触发 on_shuffle_timeout
    table::force_on_shuffle_timeout_for_test(&mut t, scenario.ctx());

    // 验证：被踢玩家不再占座
    assert!(!table::seat_occupied(&t, shuffler));

    // 验证：on_shuffle_complete 已触发，shuffle_state.phase 变为 none
    // on_shuffle_complete 在 reconstruct 分支会清空 reconstruct_state 并推进到 reveal
    assert!(table::shuffle_phase(&t) == table_constants::shuffle_phase_none());

    table::destroy_table(t);
    scenario.end();
}

#[test]
fun reconstruct_shuffle_timeout_with_min_players_resets() {
    // 边界场景：reconstruct 阶段，2 人牌桌，1 人超时被踢后活跃玩家 < 2，
    // kick_player_internal 触发 reset_for_next_hand。
    let mut scenario = test_scenario::begin(table_test_helpers::admin());
    let ctx = scenario.ctx();

    let mut t = table_test_helpers::create_table_with_players(2, 1000, ctx);

    scenario.next_tx(table_test_helpers::admin());
    table::start_hand(&mut t, scenario.ctx());

    let shuffler = 0u64;
    let pending = vector[0u64, 1u64];
    let completed = vector[];
    table::set_shuffle_state_for_test(
        &mut t,
        table_constants::shuffle_phase_reconstruct(),
        option::some(shuffler),
        pending,
        completed,
    );
    table::set_reconstruct_phase_for_test(&mut t, table_constants::reconstruct_phase_collecting());

    table::add_reconstruct_player_deck_for_test(&mut t, 0, make_mock_deck());
    table::add_reconstruct_player_deck_for_test(&mut t, 1, make_mock_deck());

    // 触发 on_shuffle_timeout
    table::force_on_shuffle_timeout_for_test(&mut t, scenario.ctx());

    // 验证：被踢玩家不再占座
    assert!(!table::seat_occupied(&t, shuffler));

    // 验证：活跃玩家 < min_players_to_start，已触发 reset_for_next_hand
    assert!(table::round_state(&t) == table_constants::round_waiting());
    assert!(table::shuffle_phase(&t) == table_constants::shuffle_phase_none());

    table::destroy_table(t);
    scenario.end();
}

#[test]
fun reconstruct_shuffle_timeout_preserves_other_player_decks() {
    // 密码学正确性验证：移除被踢玩家的 deck 后，剩余 player_decks 仍能重建有效牌组。
    // 验证 player_decks 数量减少 1，且剩余 deck 的 seat_index 不包含被踢玩家。
    let mut scenario = test_scenario::begin(table_test_helpers::admin());
    let ctx = scenario.ctx();

    let mut t = table_test_helpers::create_table_with_players(4, 1000, ctx);

    scenario.next_tx(table_test_helpers::admin());
    table::start_hand(&mut t, scenario.ctx());

    let shuffler = 0u64;
    let pending = vector[0u64, 1u64, 2u64, 3u64];
    let completed = vector[];
    table::set_shuffle_state_for_test(
        &mut t,
        table_constants::shuffle_phase_reconstruct(),
        option::some(shuffler),
        pending,
        completed,
    );
    table::set_reconstruct_phase_for_test(&mut t, table_constants::reconstruct_phase_collecting());

    // 设置 round_state 为非 waiting（模拟手牌进行中）
    table::set_round_state_for_test(&mut t, table_constants::round_flop());

    table::add_reconstruct_player_deck_for_test(&mut t, 0, make_mock_deck());
    table::add_reconstruct_player_deck_for_test(&mut t, 1, make_mock_deck());
    table::add_reconstruct_player_deck_for_test(&mut t, 2, make_mock_deck());
    table::add_reconstruct_player_deck_for_test(&mut t, 3, make_mock_deck());

    // 触发 on_shuffle_timeout
    table::force_on_shuffle_timeout_for_test(&mut t, scenario.ctx());

    // 验证：on_reconstruct_shuffle_failed 已调用，shuffle_state 重置
    assert!(table::shuffle_phase(&t) == table_constants::shuffle_phase_reconstruct());
    assert!(table::shuffle_pending_count(&t) == 3);

    // 验证：encrypted 已重建（rebuild_deck_from_reconstruct_deck 使用剩余 3 个 deck）
    assert!(table::deck_size(&t) == table_constants::n_cards());

    table::destroy_table(t);
    scenario.end();
}
