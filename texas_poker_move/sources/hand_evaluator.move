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

/// 将 HandRank 序列化为 u64，便于事件传递。
/// 编码: category 占 bits 0-7，kickers[i] 占 bits 8*(i+1) ~ 8*(i+1)+7
/// 最多 5 个 kickers，总共使用 48 bits，可完整还原。
public fun to_u64(hr: &HandRank): u64 {
    let mut result = (hr.category as u64);
    let mut i = 0;
    while (i < hr.kickers.length()) {
        let shift = (8 * (i + 1)) as u8;
        result = result | ((hr.kickers[i] as u64) << shift);
        i = i + 1;
    };
    result
}

// ========== 比较 ==========
// 返回: 0 = a < b, 1 = 相等, 2 = a > b
public fun compare(a: &HandRank, b: &HandRank): u8 {
    if (a.category < b.category) { return 0 };
    if (a.category > b.category) { return 2 };
    compare_kickers(&a.kickers, &b.kickers)
}

fun compare_kickers(a: &vector<u8>, b: &vector<u8>): u8 {
    // M-P6: 校验长度一致——同一 category 的 HandRank 应有相同 kickers 长度。
    // 不一致则视为非法输入，abort 防止错误的比较结果。
    assert!(a.length() == b.length(), EInvalidCardCount);
    let len = a.length();
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

// M-P8: 校验牌组中无重复牌（防御性编程）
fun cards_are_unique(cards: &vector<Card>): bool {
    let n = cards.length();
    let mut i = 0;
    while (i < n) {
        let mut j = i + 1;
        while (j < n) {
            if (card::equals(&cards[i], &cards[j])) {
                return false
            };
            j = j + 1;
        };
        i = i + 1;
    };
    true
}

public fun best_hand(cards: &vector<Card>): HandRank {
    assert!(cards.length() == 7, EInvalidCardCount);
    // M-P8: 防御性校验——确保 7 张牌唯一（无重复）。
    // 调用方应保证牌组来自合法 deck，此处为深度防御。
    assert!(cards_are_unique(cards), EInvalidCardCount);

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

// 优化: 直接按索引评估，避免分配中间 vector
fun eval5i(
    cards: &vector<Card>,
    i0: u64, i1: u64, i2: u64, i3: u64, i4: u64
): HandRank {
    evaluate_five_by_indices(cards, i0, i1, i2, i3, i4)
}

// ========== 评估5张牌 (公共 API，保持兼容) ==========
public fun evaluate_five(cards: &vector<Card>): HandRank {
    assert!(cards.length() == 5, EInvalidCardCount);
    // M-P8: 防御性校验——确保 5 张牌唯一（无重复）
    assert!(cards_are_unique(cards), EInvalidCardCount);
    // 复用优化后的按索引评估逻辑
    evaluate_five_impl(
        cards[0], cards[1], cards[2], cards[3], cards[4]
    )
}

// 按索引评估，避免 vector 分配
fun evaluate_five_by_indices(
    cards: &vector<Card>,
    i0: u64, i1: u64, i2: u64, i3: u64, i4: u64
): HandRank {
    evaluate_five_impl(cards[i0], cards[i1], cards[i2], cards[i3], cards[i4])
}

// 核心评估逻辑：单次遍历计数 + 复用排序结果
fun evaluate_five_impl(c0: Card, c1: Card, c2: Card, c3: Card, c4: Card): HandRank {
    // 单次遍历：构建点数计数数组 (索引 0=点数2, 12=点数14)
    let mut counts = vector[0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
    // M-P7: Move 2024 edition 中 u8 无 .into() 方法，保留 as u64 转换。
    // as 在 Move 2024 中仍为合法的数值转换语法，此处为安全的拓宽转换（u8 → u64）。
    *(vector::borrow_mut(&mut counts, (c0.rank() - 2) as u64)) = counts[(c0.rank() - 2) as u64] + 1;
    *(vector::borrow_mut(&mut counts, (c1.rank() - 2) as u64)) = counts[(c1.rank() - 2) as u64] + 1;
    *(vector::borrow_mut(&mut counts, (c2.rank() - 2) as u64)) = counts[(c2.rank() - 2) as u64] + 1;
    *(vector::borrow_mut(&mut counts, (c3.rank() - 2) as u64)) = counts[(c3.rank() - 2) as u64] + 1;
    *(vector::borrow_mut(&mut counts, (c4.rank() - 2) as u64)) = counts[(c4.rank() - 2) as u64] + 1;

    // 同花检测
    let is_flush = c0.suit() == c1.suit()
        && c1.suit() == c2.suit()
        && c2.suit() == c3.suit()
        && c3.suit() == c4.suit();

    // 排序点数降序 (复用)
    let sorted = sorted_ranks_from_cards(c0, c1, c2, c3, c4);
    let (is_straight_val, straight_high) = check_straight_from_sorted(&sorted);

    // 同花顺 / 皇家同花顺
    if (is_flush && is_straight_val) {
        if (straight_high == card::ace()) {
            return new_hand_rank(ROYAL_FLUSH, vector[straight_high])
        } else {
            return new_hand_rank(STRAIGHT_FLUSH, vector[straight_high])
        }
    };

    // 四条
    let four_r = find_in_counts(&counts, 4);
    if (four_r > 0) {
        let kicker = find_highest_excluding_in_counts(&counts, four_r);
        return new_hand_rank(FOUR_OF_A_KIND, vector[four_r, kicker])
    };

    // 葫芦
    let three_r = find_in_counts(&counts, 3);
    let pair_r = find_pair_in_counts(&counts, 0);
    if (three_r > 0 && pair_r > 0) {
        return new_hand_rank(FULL_HOUSE, vector[three_r, pair_r])
    };

    // 同花
    if (is_flush) {
        return new_hand_rank(FLUSH, sorted)
    };

    // 顺子
    if (is_straight_val) {
        return new_hand_rank(STRAIGHT, vector[straight_high])
    };

    // 三条
    if (three_r > 0) {
        let k1 = find_highest_excluding_in_counts(&counts, three_r);
        let k2 = find_highest_excluding2_in_counts(&counts, three_r, k1);
        return new_hand_rank(THREE_OF_A_KIND, vector[three_r, k1, k2])
    };

    // 两对 (复用 pair_r 作为 p1)
    let p1 = pair_r;
    let p2 = find_pair_in_counts(&counts, p1);
    if (p1 > 0 && p2 > 0) {
        let kicker = find_highest_excluding2_in_counts(&counts, p1, p2);
        return new_hand_rank(TWO_PAIR, vector[p1, p2, kicker])
    };

    // 一对
    if (p1 > 0) {
        let k1 = find_highest_excluding_in_counts(&counts, p1);
        let k2 = find_highest_excluding2_in_counts(&counts, p1, k1);
        let k3 = find_highest_excluding3_in_counts(&counts, p1, k1, k2);
        return new_hand_rank(ONE_PAIR, vector[p1, k1, k2, k3])
    };

    // 高牌
    new_hand_rank(HIGH_CARD, sorted)
}

// ========== 基于计数数组的查找函数 ==========
// counts 索引: 0=点数2, 1=点数3, ..., 12=点数14

fun find_in_counts(counts: &vector<u8>, target_count: u8): u8 {
    // 从高到低查找
    let mut i = 12;
    while (i < 13) {  // i 从 12 递减到 0
        if (counts[i] == target_count) {
            return (i + 2) as u8
        };
        if (i == 0) { break };
        i = i - 1;
    };
    0
}

fun find_pair_in_counts(counts: &vector<u8>, exclude: u8): u8 {
    let mut i = 12;
    while (i < 13) {
        let rank = (i + 2) as u8;
        if (counts[i] == 2 && rank != exclude) {
            return rank
        };
        if (i == 0) { break };
        i = i - 1;
    };
    0
}

fun find_highest_excluding_in_counts(counts: &vector<u8>, e1: u8): u8 {
    let mut i = 12;
    while (i < 13) {
        let rank = (i + 2) as u8;
        if (counts[i] > 0 && rank != e1) {
            return rank
        };
        if (i == 0) { break };
        i = i - 1;
    };
    0
}

fun find_highest_excluding2_in_counts(counts: &vector<u8>, e1: u8, e2: u8): u8 {
    let mut i = 12;
    while (i < 13) {
        let rank = (i + 2) as u8;
        if (counts[i] > 0 && rank != e1 && rank != e2) {
            return rank
        };
        if (i == 0) { break };
        i = i - 1;
    };
    0
}

fun find_highest_excluding3_in_counts(counts: &vector<u8>, e1: u8, e2: u8, e3: u8): u8 {
    let mut i = 12;
    while (i < 13) {
        let rank = (i + 2) as u8;
        if (counts[i] > 0 && rank != e1 && rank != e2 && rank != e3) {
            return rank
        };
        if (i == 0) { break };
        i = i - 1;
    };
    0
}

// ========== 排序和顺子检测 (基于 Card 参数，避免 vector 分配) ==========

fun sorted_ranks_from_cards(c0: Card, c1: Card, c2: Card, c3: Card, c4: Card): vector<u8> {
    let mut ranks = vector[c0.rank(), c1.rank(), c2.rank(), c3.rank(), c4.rank()];
    // 冒泡排序降序 (5个元素，最多10次比较)
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

fun check_straight_from_sorted(ranks: &vector<u8>): (bool, u8) {
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
