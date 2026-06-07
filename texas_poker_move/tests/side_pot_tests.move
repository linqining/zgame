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
