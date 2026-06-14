#[test_only]
module texas_poker::side_pot_tests;

use texas_poker::side_pot;
use std::unit_test::assert_eq;

#[test]
fun no_all_in_returns_main_pot() {
    let bets = vector[100, 100, 100];
    let folded = vector[false, false, false];
    let all_in = vector[false, false, false];
    let (main, side_pots) = side_pot::calculate_side_pots(&bets, &folded, &all_in);
    assert_eq!(main, 300);
    assert_eq!(side_pots.length(), 0);
}

#[test]
fun one_all_in_creates_side_pot() {
    let bets = vector[50, 100, 100];
    let folded = vector[false, false, false];
    let all_in = vector[true, false, false];
    let (main, side_pots) = side_pot::calculate_side_pots(&bets, &folded, &all_in);
    assert_eq!(main, 150);
    assert_eq!(side_pots.length(), 1);
    assert_eq!(side_pot::amount(&side_pots[0]), 100);
}

#[test]
fun two_all_in_levels() {
    let bets = vector[30, 60, 100];
    let folded = vector[false, false, false];
    let all_in = vector[true, true, false];
    let (main, side_pots) = side_pot::calculate_side_pots(&bets, &folded, &all_in);
    assert_eq!(main, 90);
    assert_eq!(side_pots.length(), 2);
}

#[test]
fun folded_player_excluded_from_eligible() {
    let bets = vector[50, 50, 100];
    let folded = vector[false, true, false];
    let all_in = vector[true, false, false];
    let (_main, side_pots) = side_pot::calculate_side_pots(&bets, &folded, &all_in);
    let eligible = side_pot::eligible_seats(&side_pots[0]);
    assert_eq!(eligible.length(), 1);
    assert_eq!(eligible[0], 2);
}

#[test]
fun zero_bets_no_side_pots() {
    let bets = vector[0, 0, 0];
    let folded = vector[false, false, false];
    let all_in = vector[false, false, false];
    let (main, side_pots) = side_pot::calculate_side_pots(&bets, &folded, &all_in);
    assert_eq!(main, 0);
    assert_eq!(side_pots.length(), 0);
}

// ========== 补充: 复杂场景测试 ==========

#[test]
fun all_players_all_in() {
    // 3 players all-in with different amounts
    let bets = vector[30, 60, 100];
    let folded = vector[false, false, false];
    let all_in = vector[true, true, true];
    let (main, side_pots) = side_pot::calculate_side_pots(&bets, &folded, &all_in);
    // main pot: 30*3 = 90
    assert_eq!(main, 90);
    assert_eq!(side_pots.length(), 2);
}

#[test]
fun folded_player_contributes_but_excluded() {
    // Player 1 folded but contributed 50, players 2 and 3 all-in at different amounts
    let bets = vector[50, 80, 100];
    let folded = vector[true, false, false];
    let all_in = vector[false, true, true];
    let (main, side_pots) = side_pot::calculate_side_pots(&bets, &folded, &all_in);
    // Total pot = 230
    let total = main + side_pot_total(&side_pots);
    assert_eq!(total, 230);
    // Folded player not eligible for any side pot
    if (side_pots.length() > 0) {
        let eligible = side_pot::eligible_seats(&side_pots[0]);
        let mut has_folded = false;
        let mut i = 0;
        while (i < eligible.length()) {
            if (eligible[i] == 0) { has_folded = true };
            i = i + 1;
        };
        assert!(!has_folded);
    };
}

#[test]
fun two_players_same_all_in_amount() {
    // Two players all-in for same amount, one player with more chips
    let bets = vector[100, 100, 200];
    let folded = vector[false, false, false];
    let all_in = vector[true, true, false];
    let (main, side_pots) = side_pot::calculate_side_pots(&bets, &folded, &all_in);
    // main pot: 100*3 = 300
    assert_eq!(main, 300);
    // side pot: 100 from player 3
    assert_eq!(side_pots.length(), 1);
    assert_eq!(side_pot::amount(&side_pots[0]), 100);
}

#[test]
fun single_player_no_side_pot() {
    let bets = vector[100, 0, 0];
    let folded = vector[false, true, true];
    let all_in = vector[false, false, false];
    let (main, side_pots) = side_pot::calculate_side_pots(&bets, &folded, &all_in);
    assert_eq!(main, 100);
    assert_eq!(side_pots.length(), 0);
}

// 辅助函数: 计算 side_pots 总额
fun side_pot_total(side_pots: &vector<side_pot::SidePot>): u64 {
    let mut total = 0;
    let mut i = 0;
    while (i < side_pots.length()) {
        total = total + side_pot::amount(&side_pots[i]);
        i = i + 1;
    };
    total
}
