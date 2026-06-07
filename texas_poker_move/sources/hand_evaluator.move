module texas_poker::hand_evaluator;

use std::string::{Self, String};
use texas_poker::card::{Self, Card};

// ========== 手牌等级类别 ==========
const HIGH_CARD: u8 = 0;
const ONE_PAIR: u8 = 1;
const TWO_PAIR: u8 = 2;
const THREE_OF_A_KIND: u8 = 3;
const STRAIGHT: u8 = 4;
const FLUSH: u8 = 5;
const FULL_HOUSE: u8 = 6;
const FOUR_OF_A_KIND: u8 = 7;
const STRAIGHT_FLUSH: u8 = 8;
const ROYAL_FLUSH: u8 = 9;

#[error]
const EInvalidCardCount: vector<u8> = b"Invalid card count for hand evaluation";

// ========== 手牌等级 ==========
public struct HandRank has store, copy, drop {
    category: u8,
    kickers: vector<u8>,
}

// ========== 构造/访问 ==========
public fun new_hand_rank(category: u8, kickers: vector<u8>): HandRank {
    HandRank { category, kickers }
}

public fun category(hr: &HandRank): u8 { hr.category }
public fun kickers(hr: &HandRank): &vector<u8> { &hr.kickers }

// ========== 比较 ==========
// 返回: 0 = a < b, 1 = 相等, 2 = a > b
public fun compare(a: &HandRank, b: &HandRank): u8 {
    if (a.category < b.category) { return 0 };
    if (a.category > b.category) { return 2 };
    compare_kickers(&a.kickers, &b.kickers)
}

fun compare_kickers(a: &vector<u8>, b: &vector<u8>): u8 {
    let len = if (a.length() < b.length()) { a.length() } else { b.length() };
    let mut i = 0;
    while (i < len) {
        let va = a[i];
        let vb = b[i];
        if (va < vb) { return 0 };
        if (va > vb) { return 2 };
        i = i + 1;
    };
    1
}

// ========== 从7张牌中选最优5张 ==========
public fun best_hand(cards: &vector<Card>): HandRank {
    assert!(cards.length() == 7, EInvalidCardCount);

    let mut best = eval5i(cards, 0, 1, 2, 3, 4);
    best = update_best(cards, &best, 0, 1, 2, 3, 5);
    best = update_best(cards, &best, 0, 1, 2, 3, 6);
    best = update_best(cards, &best, 0, 1, 2, 4, 5);
    best = update_best(cards, &best, 0, 1, 2, 4, 6);
    best = update_best(cards, &best, 0, 1, 2, 5, 6);
    best = update_best(cards, &best, 0, 1, 3, 4, 5);
    best = update_best(cards, &best, 0, 1, 3, 4, 6);
    best = update_best(cards, &best, 0, 1, 3, 5, 6);
    best = update_best(cards, &best, 0, 1, 4, 5, 6);
    best = update_best(cards, &best, 0, 2, 3, 4, 5);
    best = update_best(cards, &best, 0, 2, 3, 4, 6);
    best = update_best(cards, &best, 0, 2, 3, 5, 6);
    best = update_best(cards, &best, 0, 2, 4, 5, 6);
    best = update_best(cards, &best, 0, 3, 4, 5, 6);
    best = update_best(cards, &best, 1, 2, 3, 4, 5);
    best = update_best(cards, &best, 1, 2, 3, 4, 6);
    best = update_best(cards, &best, 1, 2, 3, 5, 6);
    best = update_best(cards, &best, 1, 2, 4, 5, 6);
    best = update_best(cards, &best, 1, 3, 4, 5, 6);
    best = update_best(cards, &best, 2, 3, 4, 5, 6);
    best
}

fun update_best(
    cards: &vector<Card>,
    best: &HandRank,
    i0: u64, i1: u64, i2: u64, i3: u64, i4: u64
): HandRank {
    let current = eval5i(cards, i0, i1, i2, i3, i4);
    if (compare(&current, best) == 2) { current } else { *best }
}

fun eval5i(
    cards: &vector<Card>,
    i0: u64, i1: u64, i2: u64, i3: u64, i4: u64
): HandRank {
    let five = vector[cards[i0], cards[i1], cards[i2], cards[i3], cards[i4]];
    evaluate_five(&five)
}

// ========== 评估5张牌 ==========
public fun evaluate_five(cards: &vector<Card>): HandRank {
    assert!(cards.length() == 5, EInvalidCardCount);

    let is_flush = check_flush(cards);
    let (is_straight_val, straight_high) = check_straight(cards);

    // 统计各点数出现次数
    let c2 = count_rank(cards, 2);
    let c3 = count_rank(cards, 3);
    let c4 = count_rank(cards, 4);
    let c5 = count_rank(cards, 5);
    let c6 = count_rank(cards, 6);
    let c7 = count_rank(cards, 7);
    let c8 = count_rank(cards, 8);
    let c9 = count_rank(cards, 9);
    let c10 = count_rank(cards, 10);
    let c11 = count_rank(cards, 11);
    let c12 = count_rank(cards, 12);
    let c13 = count_rank(cards, 13);
    let c14 = count_rank(cards, 14);

    // 同花顺 / 皇家同花顺
    if (is_flush && is_straight_val) {
        if (straight_high == card::ace()) {
            return new_hand_rank(ROYAL_FLUSH, vector[straight_high])
        } else {
            return new_hand_rank(STRAIGHT_FLUSH, vector[straight_high])
        }
    };

    // 四条
    let four_r = find_four(c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14);
    if (four_r > 0) {
        let kicker = find_highest_excluding(c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, four_r);
        return new_hand_rank(FOUR_OF_A_KIND, vector[four_r, kicker])
    };

    // 葫芦
    let three_r = find_three(c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14);
    let pair_r = find_pair(c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, 0);
    if (three_r > 0 && pair_r > 0) {
        return new_hand_rank(FULL_HOUSE, vector[three_r, pair_r])
    };

    // 同花
    if (is_flush) {
        return new_hand_rank(FLUSH, sorted_ranks_desc(cards))
    };

    // 顺子
    if (is_straight_val) {
        return new_hand_rank(STRAIGHT, vector[straight_high])
    };

    // 三条
    if (three_r > 0) {
        let k1 = find_highest_excluding(c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, three_r);
        let k2 = find_highest_excluding2(c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, three_r, k1);
        return new_hand_rank(THREE_OF_A_KIND, vector[three_r, k1, k2])
    };

    // 两对
    let p1 = find_pair(c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, 0);
    let p2 = find_pair(c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, p1);
    if (p1 > 0 && p2 > 0) {
        let kicker = find_highest_excluding2(c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, p1, p2);
        return new_hand_rank(TWO_PAIR, vector[p1, p2, kicker])
    };

    // 一对
    if (p1 > 0) {
        let k1 = find_highest_excluding(c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, p1);
        let k2 = find_highest_excluding2(c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, p1, k1);
        let k3 = find_highest_excluding3(c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, p1, k1, k2);
        return new_hand_rank(ONE_PAIR, vector[p1, k1, k2, k3])
    };

    // 高牌
    new_hand_rank(HIGH_CARD, sorted_ranks_desc(cards))
}

// ========== 统计某个点数出现次数 ==========
fun count_rank(cards: &vector<Card>, target: u8): u8 {
    let mut count = 0;
    let mut i = 0;
    while (i < 5) {
        if (cards[i].rank() == target) { count = count + 1 };
        i = i + 1;
    };
    count
}

// ========== 查找四条 ==========
fun find_four(c2: u8, c3: u8, c4: u8, c5: u8, c6: u8, c7: u8, c8: u8, c9: u8, c10: u8, c11: u8, c12: u8, c13: u8, c14: u8): u8 {
    if (c14 == 4) { 14 }
    else if (c13 == 4) { 13 }
    else if (c12 == 4) { 12 }
    else if (c11 == 4) { 11 }
    else if (c10 == 4) { 10 }
    else if (c9 == 4) { 9 }
    else if (c8 == 4) { 8 }
    else if (c7 == 4) { 7 }
    else if (c6 == 4) { 6 }
    else if (c5 == 4) { 5 }
    else if (c4 == 4) { 4 }
    else if (c3 == 4) { 3 }
    else if (c2 == 4) { 2 }
    else { 0 }
}

fun find_three(c2: u8, c3: u8, c4: u8, c5: u8, c6: u8, c7: u8, c8: u8, c9: u8, c10: u8, c11: u8, c12: u8, c13: u8, c14: u8): u8 {
    if (c14 == 3) { 14 }
    else if (c13 == 3) { 13 }
    else if (c12 == 3) { 12 }
    else if (c11 == 3) { 11 }
    else if (c10 == 3) { 10 }
    else if (c9 == 3) { 9 }
    else if (c8 == 3) { 8 }
    else if (c7 == 3) { 7 }
    else if (c6 == 3) { 6 }
    else if (c5 == 3) { 5 }
    else if (c4 == 3) { 4 }
    else if (c3 == 3) { 3 }
    else if (c2 == 3) { 2 }
    else { 0 }
}

fun find_pair(c2: u8, c3: u8, c4: u8, c5: u8, c6: u8, c7: u8, c8: u8, c9: u8, c10: u8, c11: u8, c12: u8, c13: u8, c14: u8, exclude: u8): u8 {
    if (c14 == 2 && 14 != exclude) { 14 }
    else if (c13 == 2 && 13 != exclude) { 13 }
    else if (c12 == 2 && 12 != exclude) { 12 }
    else if (c11 == 2 && 11 != exclude) { 11 }
    else if (c10 == 2 && 10 != exclude) { 10 }
    else if (c9 == 2 && 9 != exclude) { 9 }
    else if (c8 == 2 && 8 != exclude) { 8 }
    else if (c7 == 2 && 7 != exclude) { 7 }
    else if (c6 == 2 && 6 != exclude) { 6 }
    else if (c5 == 2 && 5 != exclude) { 5 }
    else if (c4 == 2 && 4 != exclude) { 4 }
    else if (c3 == 2 && 3 != exclude) { 3 }
    else if (c2 == 2 && 2 != exclude) { 2 }
    else { 0 }
}

fun find_highest_excluding(c2: u8, c3: u8, c4: u8, c5: u8, c6: u8, c7: u8, c8: u8, c9: u8, c10: u8, c11: u8, c12: u8, c13: u8, c14: u8, e1: u8): u8 {
    if (c14 > 0 && 14 != e1) { 14 }
    else if (c13 > 0 && 13 != e1) { 13 }
    else if (c12 > 0 && 12 != e1) { 12 }
    else if (c11 > 0 && 11 != e1) { 11 }
    else if (c10 > 0 && 10 != e1) { 10 }
    else if (c9 > 0 && 9 != e1) { 9 }
    else if (c8 > 0 && 8 != e1) { 8 }
    else if (c7 > 0 && 7 != e1) { 7 }
    else if (c6 > 0 && 6 != e1) { 6 }
    else if (c5 > 0 && 5 != e1) { 5 }
    else if (c4 > 0 && 4 != e1) { 4 }
    else if (c3 > 0 && 3 != e1) { 3 }
    else if (c2 > 0 && 2 != e1) { 2 }
    else { 0 }
}

fun find_highest_excluding2(c2: u8, c3: u8, c4: u8, c5: u8, c6: u8, c7: u8, c8: u8, c9: u8, c10: u8, c11: u8, c12: u8, c13: u8, c14: u8, e1: u8, e2: u8): u8 {
    if (c14 > 0 && 14 != e1 && 14 != e2) { 14 }
    else if (c13 > 0 && 13 != e1 && 13 != e2) { 13 }
    else if (c12 > 0 && 12 != e1 && 12 != e2) { 12 }
    else if (c11 > 0 && 11 != e1 && 11 != e2) { 11 }
    else if (c10 > 0 && 10 != e1 && 10 != e2) { 10 }
    else if (c9 > 0 && 9 != e1 && 9 != e2) { 9 }
    else if (c8 > 0 && 8 != e1 && 8 != e2) { 8 }
    else if (c7 > 0 && 7 != e1 && 7 != e2) { 7 }
    else if (c6 > 0 && 6 != e1 && 6 != e2) { 6 }
    else if (c5 > 0 && 5 != e1 && 5 != e2) { 5 }
    else if (c4 > 0 && 4 != e1 && 4 != e2) { 4 }
    else if (c3 > 0 && 3 != e1 && 3 != e2) { 3 }
    else if (c2 > 0 && 2 != e1 && 2 != e2) { 2 }
    else { 0 }
}

fun find_highest_excluding3(c2: u8, c3: u8, c4: u8, c5: u8, c6: u8, c7: u8, c8: u8, c9: u8, c10: u8, c11: u8, c12: u8, c13: u8, c14: u8, e1: u8, e2: u8, e3: u8): u8 {
    if (c14 > 0 && 14 != e1 && 14 != e2 && 14 != e3) { 14 }
    else if (c13 > 0 && 13 != e1 && 13 != e2 && 13 != e3) { 13 }
    else if (c12 > 0 && 12 != e1 && 12 != e2 && 12 != e3) { 12 }
    else if (c11 > 0 && 11 != e1 && 11 != e2 && 11 != e3) { 11 }
    else if (c10 > 0 && 10 != e1 && 10 != e2 && 10 != e3) { 10 }
    else if (c9 > 0 && 9 != e1 && 9 != e2 && 9 != e3) { 9 }
    else if (c8 > 0 && 8 != e1 && 8 != e2 && 8 != e3) { 8 }
    else if (c7 > 0 && 7 != e1 && 7 != e2 && 7 != e3) { 7 }
    else if (c6 > 0 && 6 != e1 && 6 != e2 && 6 != e3) { 6 }
    else if (c5 > 0 && 5 != e1 && 5 != e2 && 5 != e3) { 5 }
    else if (c4 > 0 && 4 != e1 && 4 != e2 && 4 != e3) { 4 }
    else if (c3 > 0 && 3 != e1 && 3 != e2 && 3 != e3) { 3 }
    else if (c2 > 0 && 2 != e1 && 2 != e2 && 2 != e3) { 2 }
    else { 0 }
}

// ========== 同花检测 ==========
fun check_flush(cards: &vector<Card>): bool {
    let s = cards[0].suit();
    let mut i = 1;
    while (i < 5) {
        if (cards[i].suit() != s) { return false };
        i = i + 1;
    };
    true
}

// ========== 顺子检测 ==========
fun check_straight(cards: &vector<Card>): (bool, u8) {
    let ranks = sorted_ranks_desc(cards);
    let mut i = 0;
    while (i < 4) {
        let curr = ranks[i];
        let next = ranks[i + 1];
        if (curr != next + 1) {
            // A-2-3-4-5 (Wheel): 排序后 14,5,4,3,2
            if (i == 0 && curr == card::ace() && next == 5) {
                let mut j = 1;
                while (j < 4) {
                    if (ranks[j] != ranks[j + 1] + 1) { return (false, 0) };
                    j = j + 1;
                };
                return (true, 5)
            };
            return (false, 0)
        };
        i = i + 1;
    };
    (true, ranks[0])
}

// ========== 排序点数降序 ==========
fun sorted_ranks_desc(cards: &vector<Card>): vector<u8> {
    let mut ranks = vector[cards[0].rank(), cards[1].rank(), cards[2].rank(), cards[3].rank(), cards[4].rank()];
    // 冒泡排序降序
    let mut j = 0;
    while (j < 4) {
        let mut k = 0;
        while (k < 4 - j) {
            if (ranks[k] < ranks[k + 1]) {
                let tmp = ranks[k];
                let next_val = ranks[k + 1];
                *(vector::borrow_mut(&mut ranks, k)) = next_val;
                *(vector::borrow_mut(&mut ranks, k + 1)) = tmp;
            };
            k = k + 1;
        };
        j = j + 1;
    };
    ranks
}

// ========== 类别名称 ==========
public fun category_name(cat: u8): String {
    if (cat == HIGH_CARD) { string::utf8(b"High Card") }
    else if (cat == ONE_PAIR) { string::utf8(b"One Pair") }
    else if (cat == TWO_PAIR) { string::utf8(b"Two Pair") }
    else if (cat == THREE_OF_A_KIND) { string::utf8(b"Three of a Kind") }
    else if (cat == STRAIGHT) { string::utf8(b"Straight") }
    else if (cat == FLUSH) { string::utf8(b"Flush") }
    else if (cat == FULL_HOUSE) { string::utf8(b"Full House") }
    else if (cat == FOUR_OF_A_KIND) { string::utf8(b"Four of a Kind") }
    else if (cat == STRAIGHT_FLUSH) { string::utf8(b"Straight Flush") }
    else if (cat == ROYAL_FLUSH) { string::utf8(b"Royal Flush") }
    else { string::utf8(b"Unknown") }
}
