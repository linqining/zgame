//! 手牌评估（移植自 `texas_poker::hand_evaluator`）。
//!
//! 从 7 张牌中选最优 5 张，返回 `HandRank`。`HandRank` 可序列化为 `u64`
//! 便于事件传递与比较。评估算法与 Move 原实现一致：单次遍历计数 + 排序。

use serde::{Deserialize, Serialize};

use crate::card::{Card, ACE};

// ========== 手牌等级类别 ==========

/// 高牌
pub const HIGH_CARD: u8 = 0;
/// 一对
pub const ONE_PAIR: u8 = 1;
/// 两对
pub const TWO_PAIR: u8 = 2;
/// 三条
pub const THREE_OF_A_KIND: u8 = 3;
/// 顺子
pub const STRAIGHT: u8 = 4;
/// 同花
pub const FLUSH: u8 = 5;
/// 葫芦
pub const FULL_HOUSE: u8 = 6;
/// 四条
pub const FOUR_OF_A_KIND: u8 = 7;
/// 同花顺
pub const STRAIGHT_FLUSH: u8 = 8;
/// 皇家同花顺
pub const ROYAL_FLUSH: u8 = 9;

/// 手牌评估错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HandEvalError {
    /// 牌数不正确。
    #[error("invalid card count for hand evaluation")]
    InvalidCardCount,
    /// 牌组中存在重复牌。
    #[error("duplicate cards detected")]
    DuplicateCards,
}

/// 手牌等级。
///
/// `category` 决定牌型大小；同 category 时按 `kickers` 字典序比较（降序）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandRank {
    /// 牌型类别（0=高牌 .. 9=皇家同花顺）。
    pub category: u8,
    /// 决胜牌点数（降序排列，最多 5 个）。
    pub kickers: Vec<u8>,
}

impl HandRank {
    /// 构造新手牌等级。
    #[must_use]
    pub fn new(category: u8, kickers: Vec<u8>) -> Self {
        Self { category, kickers }
    }

    /// 类别。
    #[must_use]
    pub const fn category(&self) -> u8 {
        self.category
    }

    /// kicker 切片。
    #[must_use]
    pub fn kickers(&self) -> &[u8] {
        &self.kickers
    }

    /// 序列化为 u64，便于事件传递。
    ///
    /// 编码：category 占 bits 0-7，kickers[i] 占 bits `8*(i+1)` ~ `8*(i+1)+7`，
    /// 最多 5 个 kickers，共 48 bits，可完整还原。
    #[must_use]
    pub fn to_u64(&self) -> u64 {
        let mut result = u64::from(self.category);
        for (i, &k) in self.kickers.iter().enumerate() {
            let shift = 8 * (i + 1);
            result |= u64::from(k) << shift;
        }
        result
    }

    /// 比较：返回 `Less` / `Equal` / `Greater`。
    #[must_use]
    pub fn cmp_to(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        match self.category.cmp(&other.category) {
            Ordering::Equal => self.compare_kickers(&other.kickers),
            non_eq => non_eq,
        }
    }

    /// 比较 kicker（同 category 须等长）。
    fn compare_kickers(&self, other_kickers: &[u8]) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        // 同 category 的 HandRank 应有相同 kickers 长度；不一致视为非法，按长度比较兜底
        if self.kickers.len() != other_kickers.len() {
            return self.kickers.len().cmp(&other_kickers.len());
        }
        for (a, b) in self.kickers.iter().zip(other_kickers.iter()) {
            match a.cmp(b) {
                Ordering::Equal => continue,
                non_eq => return non_eq,
            }
        }
        Ordering::Equal
    }
}

// ========== 7 选 5 最优手牌 ==========

/// 校验牌组中无重复牌。
fn cards_are_unique(cards: &[Card]) -> bool {
    let n = cards.len();
    for i in 0..n {
        for j in i + 1..n {
            if cards[i] == cards[j] {
                return false;
            }
        }
    }
    true
}

/// 从 7 张牌中选最优 5 张（C(7,5)=21 种组合）。
///
/// # 错误
/// - [`HandEvalError::InvalidCardCount`]：牌数非 7
/// - [`HandEvalError::DuplicateCards`]：存在重复牌
pub fn best_hand(cards: &[Card]) -> Result<HandRank, HandEvalError> {
    if cards.len() != 7 {
        return Err(HandEvalError::InvalidCardCount);
    }
    if !cards_are_unique(cards) {
        return Err(HandEvalError::DuplicateCards);
    }

    // 枚举 C(7,5)=21 种组合
    const COMBOS: [(usize, usize, usize, usize, usize); 21] = [
        (0, 1, 2, 3, 4),
        (0, 1, 2, 3, 5),
        (0, 1, 2, 3, 6),
        (0, 1, 2, 4, 5),
        (0, 1, 2, 4, 6),
        (0, 1, 2, 5, 6),
        (0, 1, 3, 4, 5),
        (0, 1, 3, 4, 6),
        (0, 1, 3, 5, 6),
        (0, 1, 4, 5, 6),
        (0, 2, 3, 4, 5),
        (0, 2, 3, 4, 6),
        (0, 2, 3, 5, 6),
        (0, 2, 4, 5, 6),
        (0, 3, 4, 5, 6),
        (1, 2, 3, 4, 5),
        (1, 2, 3, 4, 6),
        (1, 2, 3, 5, 6),
        (1, 2, 4, 5, 6),
        (1, 3, 4, 5, 6),
        (2, 3, 4, 5, 6),
    ];

    let mut best = evaluate_five_impl(cards[0], cards[1], cards[2], cards[3], cards[4]);
    for &(i0, i1, i2, i3, i4) in COMBOS.iter().skip(1) {
        let current = evaluate_five_impl(cards[i0], cards[i1], cards[i2], cards[i3], cards[i4]);
        if current.cmp_to(&best) == std::cmp::Ordering::Greater {
            best = current;
        }
    }
    Ok(best)
}

/// 评估 5 张牌（公共 API）。
pub fn evaluate_five(cards: &[Card]) -> Result<HandRank, HandEvalError> {
    if cards.len() != 5 {
        return Err(HandEvalError::InvalidCardCount);
    }
    if !cards_are_unique(cards) {
        return Err(HandEvalError::DuplicateCards);
    }
    Ok(evaluate_five_impl(
        cards[0], cards[1], cards[2], cards[3], cards[4],
    ))
}

/// 核心评估逻辑：单次遍历计数 + 复用排序结果。
fn evaluate_five_impl(c0: Card, c1: Card, c2: Card, c3: Card, c4: Card) -> HandRank {
    // 点数计数数组（索引 0=点数2, 12=点数14）
    let mut counts = [0u8; 13];
    for c in [c0, c1, c2, c3, c4] {
        let idx = (c.rank - 2) as usize;
        counts[idx] += 1;
    }

    // 同花检测
    let is_flush = c0.suit == c1.suit
        && c1.suit == c2.suit
        && c2.suit == c3.suit
        && c3.suit == c4.suit;

    // 排序点数降序
    let sorted = sorted_ranks_from_cards(c0, c1, c2, c3, c4);
    let (is_straight_val, straight_high) = check_straight_from_sorted(&sorted);

    // 同花顺 / 皇家同花顺
    if is_flush && is_straight_val {
        if straight_high == ACE {
            return HandRank::new(ROYAL_FLUSH, vec![straight_high]);
        }
        return HandRank::new(STRAIGHT_FLUSH, vec![straight_high]);
    }

    // 四条
    let four_r = find_in_counts(&counts, 4);
    if four_r > 0 {
        let kicker = find_highest_excluding_in_counts(&counts, four_r);
        return HandRank::new(FOUR_OF_A_KIND, vec![four_r, kicker]);
    }

    // 葫芦
    let three_r = find_in_counts(&counts, 3);
    let pair_r = find_pair_in_counts(&counts, 0);
    if three_r > 0 && pair_r > 0 {
        return HandRank::new(FULL_HOUSE, vec![three_r, pair_r]);
    }

    // 同花
    if is_flush {
        return HandRank::new(FLUSH, sorted);
    }

    // 顺子
    if is_straight_val {
        return HandRank::new(STRAIGHT, vec![straight_high]);
    }

    // 三条
    if three_r > 0 {
        let k1 = find_highest_excluding_in_counts(&counts, three_r);
        let k2 = find_highest_excluding2_in_counts(&counts, three_r, k1);
        return HandRank::new(THREE_OF_A_KIND, vec![three_r, k1, k2]);
    }

    // 两对
    let p1 = pair_r;
    let p2 = find_pair_in_counts(&counts, p1);
    if p1 > 0 && p2 > 0 {
        let kicker = find_highest_excluding2_in_counts(&counts, p1, p2);
        return HandRank::new(TWO_PAIR, vec![p1, p2, kicker]);
    }

    // 一对
    if p1 > 0 {
        let k1 = find_highest_excluding_in_counts(&counts, p1);
        let k2 = find_highest_excluding2_in_counts(&counts, p1, k1);
        let k3 = find_highest_excluding3_in_counts(&counts, p1, k1, k2);
        return HandRank::new(ONE_PAIR, vec![p1, k1, k2, k3]);
    }

    // 高牌
    HandRank::new(HIGH_CARD, sorted)
}

// ========== 基于计数数组的查找函数 ==========

/// 从高到低查找第一个达到 target_count 的点数，未找到返回 0。
fn find_in_counts(counts: &[u8; 13], target_count: u8) -> u8 {
    for i in (0..13).rev() {
        if counts[i] == target_count {
            return (i as u8) + 2;
        }
    }
    0
}

/// 从高到低查找第一个 count==2 且 rank != exclude 的点数。
fn find_pair_in_counts(counts: &[u8; 13], exclude: u8) -> u8 {
    for i in (0..13).rev() {
        let rank = (i as u8) + 2;
        if counts[i] == 2 && rank != exclude {
            return rank;
        }
    }
    0
}

/// 查找最高点数（count>0），排除 e1。
fn find_highest_excluding_in_counts(counts: &[u8; 13], e1: u8) -> u8 {
    for i in (0..13).rev() {
        let rank = (i as u8) + 2;
        if counts[i] > 0 && rank != e1 {
            return rank;
        }
    }
    0
}

/// 查找最高点数，排除 e1, e2。
fn find_highest_excluding2_in_counts(counts: &[u8; 13], e1: u8, e2: u8) -> u8 {
    for i in (0..13).rev() {
        let rank = (i as u8) + 2;
        if counts[i] > 0 && rank != e1 && rank != e2 {
            return rank;
        }
    }
    0
}

/// 查找最高点数，排除 e1, e2, e3。
fn find_highest_excluding3_in_counts(counts: &[u8; 13], e1: u8, e2: u8, e3: u8) -> u8 {
    for i in (0..13).rev() {
        let rank = (i as u8) + 2;
        if counts[i] > 0 && rank != e1 && rank != e2 && rank != e3 {
            return rank;
        }
    }
    0
}

// ========== 排序与顺子检测 ==========

/// 5 张牌点数降序排列（冒泡排序）。
fn sorted_ranks_from_cards(c0: Card, c1: Card, c2: Card, c3: Card, c4: Card) -> Vec<u8> {
    let mut ranks = [c0.rank, c1.rank, c2.rank, c3.rank, c4.rank];
    // 冒泡排序降序（5 元素，最多 10 次比较）
    for j in 0..4 {
        for k in 0..(4 - j) {
            if ranks[k] < ranks[k + 1] {
                ranks.swap(k, k + 1);
            }
        }
    }
    ranks.to_vec()
}

/// 从降序排列的点数检测顺子。
///
/// 返回 `(is_straight, high_card)`。处理 A-2-3-4-5（Wheel）特殊情况。
fn check_straight_from_sorted(ranks: &[u8]) -> (bool, u8) {
    for i in 0..4 {
        let curr = ranks[i];
        let next = ranks[i + 1];
        if curr != next + 1 {
            // A-2-3-4-5 (Wheel)：排序后 14,5,4,3,2
            if i == 0 && curr == ACE && next == 5 {
                for j in 1..4 {
                    if ranks[j] != ranks[j + 1] + 1 {
                        return (false, 0);
                    }
                }
                return (true, 5);
            }
            return (false, 0);
        }
    }
    (true, ranks[0])
}

/// 牌型类别名称。
#[must_use]
pub fn category_name(cat: u8) -> &'static str {
    match cat {
        HIGH_CARD => "High Card",
        ONE_PAIR => "One Pair",
        TWO_PAIR => "Two Pair",
        THREE_OF_A_KIND => "Three of a Kind",
        STRAIGHT => "Straight",
        FLUSH => "Flush",
        FULL_HOUSE => "Full House",
        FOUR_OF_A_KIND => "Four of a Kind",
        STRAIGHT_FLUSH => "Straight Flush",
        ROYAL_FLUSH => "Royal Flush",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::card::{CLUBS, DIAMONDS, HEARTS, SPADES, ACE, KING, QUEEN, JACK, TEN};

    fn c(suit: u8, rank: u8) -> Card {
        Card::new_unchecked(suit, rank)
    }

    #[test]
    fn test_royal_flush() {
        // A♠ K♠ Q♠ J♠ 10♠ + 2 张杂牌
        let cards = vec![
            c(SPADES, ACE),
            c(SPADES, KING),
            c(SPADES, QUEEN),
            c(SPADES, JACK),
            c(SPADES, TEN),
            c(HEARTS, 2),
            c(HEARTS, 3),
        ];
        let hr = best_hand(&cards).unwrap();
        assert_eq!(hr.category, ROYAL_FLUSH);
        assert_eq!(hr.kickers, vec![ACE]);
    }

    #[test]
    fn test_straight_flush() {
        // 9♠ 8♠ 7♠ 6♠ 5♠
        let cards = vec![
            c(SPADES, 9),
            c(SPADES, 8),
            c(SPADES, 7),
            c(SPADES, 6),
            c(SPADES, 5),
            c(HEARTS, 2),
            c(HEARTS, 3),
        ];
        let hr = best_hand(&cards).unwrap();
        assert_eq!(hr.category, STRAIGHT_FLUSH);
        assert_eq!(hr.kickers, vec![9]);
    }

    #[test]
    fn test_wheel_straight() {
        // A-2-3-4-5（Wheel，5 为高牌）
        let cards = vec![
            c(SPADES, ACE),
            c(HEARTS, 2),
            c(DIAMONDS, 3),
            c(CLUBS, 4),
            c(SPADES, 5),
            c(HEARTS, 9),
            c(HEARTS, 10),
        ];
        let hr = best_hand(&cards).unwrap();
        assert_eq!(hr.category, STRAIGHT);
        assert_eq!(hr.kickers, vec![5]);
    }

    #[test]
    fn test_four_of_a_kind() {
        let cards = vec![
            c(SPADES, 7),
            c(HEARTS, 7),
            c(DIAMONDS, 7),
            c(CLUBS, 7),
            c(SPADES, ACE),
            c(HEARTS, 2),
            c(HEARTS, 3),
        ];
        let hr = best_hand(&cards).unwrap();
        assert_eq!(hr.category, FOUR_OF_A_KIND);
        assert_eq!(hr.kickers, vec![7, ACE]);
    }

    #[test]
    fn test_full_house() {
        let cards = vec![
            c(SPADES, 9),
            c(HEARTS, 9),
            c(DIAMONDS, 9),
            c(CLUBS, 4),
            c(SPADES, 4),
            c(HEARTS, 2),
            c(HEARTS, 3),
        ];
        let hr = best_hand(&cards).unwrap();
        assert_eq!(hr.category, FULL_HOUSE);
        assert_eq!(hr.kickers, vec![9, 4]);
    }

    #[test]
    fn test_flush() {
        let cards = vec![
            c(SPADES, ACE),
            c(SPADES, 10),
            c(SPADES, 7),
            c(SPADES, 4),
            c(SPADES, 2),
            c(HEARTS, 5),
            c(HEARTS, 6),
        ];
        let hr = best_hand(&cards).unwrap();
        assert_eq!(hr.category, FLUSH);
    }

    #[test]
    fn test_straight() {
        let cards = vec![
            c(SPADES, 10),
            c(HEARTS, 9),
            c(DIAMONDS, 8),
            c(CLUBS, 7),
            c(SPADES, 6),
            c(HEARTS, 2),
            c(HEARTS, 3),
        ];
        let hr = best_hand(&cards).unwrap();
        assert_eq!(hr.category, STRAIGHT);
        assert_eq!(hr.kickers, vec![10]);
    }

    #[test]
    fn test_three_of_a_kind() {
        let cards = vec![
            c(SPADES, 5),
            c(HEARTS, 5),
            c(DIAMONDS, 5),
            c(CLUBS, 9),
            c(SPADES, KING),
            c(HEARTS, 2),
            c(HEARTS, 3),
        ];
        let hr = best_hand(&cards).unwrap();
        assert_eq!(hr.category, THREE_OF_A_KIND);
        assert_eq!(hr.kickers, vec![5, KING, 9]);
    }

    #[test]
    fn test_two_pair() {
        let cards = vec![
            c(SPADES, 5),
            c(HEARTS, 5),
            c(DIAMONDS, 9),
            c(CLUBS, 9),
            c(SPADES, KING),
            c(HEARTS, 2),
            c(HEARTS, 3),
        ];
        let hr = best_hand(&cards).unwrap();
        assert_eq!(hr.category, TWO_PAIR);
        assert_eq!(hr.kickers, vec![9, 5, KING]);
    }

    #[test]
    fn test_one_pair() {
        let cards = vec![
            c(SPADES, 5),
            c(HEARTS, 5),
            c(DIAMONDS, 9),
            c(CLUBS, KING),
            c(SPADES, ACE),
            c(HEARTS, 2),
            c(HEARTS, 3),
        ];
        let hr = best_hand(&cards).unwrap();
        assert_eq!(hr.category, ONE_PAIR);
        assert_eq!(hr.kickers, vec![5, ACE, KING, 9]);
    }

    #[test]
    fn test_high_card() {
        let cards = vec![
            c(SPADES, 2),
            c(HEARTS, 5),
            c(DIAMONDS, 9),
            c(CLUBS, KING),
            c(SPADES, ACE),
            c(HEARTS, 7),
            c(HEARTS, 3),
        ];
        let hr = best_hand(&cards).unwrap();
        assert_eq!(hr.category, HIGH_CARD);
    }

    #[test]
    fn test_compare_different_category() {
        let pair = HandRank::new(ONE_PAIR, vec![5, 4, 3, 2]);
        let trips = HandRank::new(THREE_OF_A_KIND, vec![5, 4, 3]);
        assert_eq!(pair.cmp_to(&trips), std::cmp::Ordering::Less);
        assert_eq!(trips.cmp_to(&pair), std::cmp::Ordering::Greater);
    }

    #[test]
    fn test_compare_same_category_kickers() {
        let a = HandRank::new(ONE_PAIR, vec![ACE, KING, 5, 4]);
        let b = HandRank::new(ONE_PAIR, vec![KING, QUEEN, 5, 4]);
        assert_eq!(a.cmp_to(&b), std::cmp::Ordering::Greater);
    }

    #[test]
    fn test_to_u64_roundtrip() {
        let hr = HandRank::new(TWO_PAIR, vec![9, 5, KING]);
        let packed = hr.to_u64();
        // category 在低 8 位
        assert_eq!((packed & 0xFF) as u8, TWO_PAIR);
        // kicker[0]=9 在 bits 8-15
        assert_eq!(((packed >> 8) & 0xFF) as u8, 9);
        assert_eq!(((packed >> 16) & 0xFF) as u8, 5);
        assert_eq!(((packed >> 24) & 0xFF) as u8, KING);
    }

    #[test]
    fn test_duplicate_cards_rejected() {
        let cards = vec![
            c(SPADES, 5),
            c(SPADES, 5), // 重复
            c(DIAMONDS, 9),
            c(CLUBS, KING),
            c(SPADES, ACE),
            c(HEARTS, 2),
            c(HEARTS, 3),
        ];
        assert_eq!(best_hand(&cards).unwrap_err(), HandEvalError::DuplicateCards);
    }

    #[test]
    fn test_wrong_card_count() {
        let cards = vec![c(SPADES, 5), c(HEARTS, 6), c(DIAMONDS, 7)];
        assert_eq!(best_hand(&cards).unwrap_err(), HandEvalError::InvalidCardCount);
    }

    #[test]
    fn test_category_name() {
        assert_eq!(category_name(ROYAL_FLUSH), "Royal Flush");
        assert_eq!(category_name(HIGH_CARD), "High Card");
        assert_eq!(category_name(255), "Unknown");
    }
}
