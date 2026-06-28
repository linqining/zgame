//! 扑克牌表示（移植自 `texas_poker::card`）。
//!
//! 定义花色、点数与 `Card` 结构。Card 满足 `Copy`/`Clone`/`Eq`/`Ord`，
//! 可直接用于手牌评估与序列化。

use serde::{Deserialize, Serialize};

// ========== 花色常量 ==========

/// 黑桃 ♠
pub const SPADES: u8 = 0;
/// 红心 ♥
pub const HEARTS: u8 = 1;
/// 方块 ♦
pub const DIAMONDS: u8 = 2;
/// 梅花 ♣
pub const CLUBS: u8 = 3;

// ========== 点数常量 ==========

/// 点数 2
pub const TWO: u8 = 2;
/// 点数 10
pub const TEN: u8 = 10;
/// Jack
pub const JACK: u8 = 11;
/// Queen
pub const QUEEN: u8 = 12;
/// King
pub const KING: u8 = 13;
/// Ace
pub const ACE: u8 = 14;

/// Card 错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CardError {
    /// 非法花色。
    #[error("invalid suit value")]
    InvalidSuit,
    /// 非法点数。
    #[error("invalid rank value")]
    InvalidRank,
}

/// 一张扑克牌。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct Card {
    /// 花色（0=♠, 1=♥, 2=♦, 3=♣）。
    pub suit: u8,
    /// 点数（2..=14，14=Ace）。
    pub rank: u8,
}

impl Card {
    /// 创建新牌（校验花色与点数合法性）。
    pub fn new(suit: u8, rank: u8) -> Result<Self, CardError> {
        if !is_valid_suit(suit) {
            return Err(CardError::InvalidSuit);
        }
        if !is_valid_rank(rank) {
            return Err(CardError::InvalidRank);
        }
        Ok(Self { suit, rank })
    }

    /// 不校验地创建牌（调用方须保证合法性，用于内部已知合法的快路径）。
    ///
    /// # Safety（逻辑层面）
    /// 调用方须保证 `suit ∈ {0,1,2,3}` 且 `rank ∈ [2,14]`。
    #[must_use]
    pub const fn new_unchecked(suit: u8, rank: u8) -> Self {
        Self { suit, rank }
    }

    /// 花色。
    #[must_use]
    pub const fn suit(&self) -> u8 {
        self.suit
    }

    /// 点数。
    #[must_use]
    pub const fn rank(&self) -> u8 {
        self.rank
    }

    /// 是否为合法牌。
    #[must_use]
    pub fn is_valid(&self) -> bool {
        is_valid_suit(self.suit) && is_valid_rank(self.rank)
    }

    /// 牌的紧凑编码：`(suit << 4) | rank`，单字节可还原。
    #[must_use]
    pub const fn to_byte(&self) -> u8 {
        (self.suit << 4) | self.rank
    }

    /// 从紧凑编码解码。
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        Self {
            suit: b >> 4,
            rank: b & 0x0F,
        }
    }
}

/// 校验花色合法性。
#[must_use]
pub const fn is_valid_suit(s: u8) -> bool {
    s <= CLUBS
}

/// 校验点数合法性。
#[must_use]
pub const fn is_valid_rank(r: u8) -> bool {
    r >= TWO && r <= ACE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_valid() {
        let c = Card::new(SPADES, ACE).unwrap();
        assert_eq!(c.suit, SPADES);
        assert_eq!(c.rank, ACE);
        assert!(c.is_valid());
    }

    #[test]
    fn test_new_invalid_suit() {
        assert_eq!(Card::new(4, ACE).unwrap_err(), CardError::InvalidSuit);
    }

    #[test]
    fn test_new_invalid_rank() {
        assert_eq!(Card::new(SPADES, 1).unwrap_err(), CardError::InvalidRank);
        assert_eq!(Card::new(SPADES, 15).unwrap_err(), CardError::InvalidRank);
    }

    #[test]
    fn test_byte_roundtrip() {
        for suit in 0..=3 {
            for rank in 2..=14 {
                let c = Card::new(suit, rank).unwrap();
                let b = c.to_byte();
                let c2 = Card::from_byte(b);
                assert_eq!(c, c2, "roundtrip failed for suit={suit} rank={rank}");
            }
        }
    }

    #[test]
    fn test_ord() {
        let ace = Card::new(SPADES, ACE).unwrap();
        let king = Card::new(SPADES, KING).unwrap();
        assert!(ace > king);
    }

    #[test]
    fn test_is_valid_suit_rank() {
        assert!(is_valid_suit(0));
        assert!(is_valid_suit(3));
        assert!(!is_valid_suit(4));
        assert!(is_valid_rank(2));
        assert!(is_valid_rank(14));
        assert!(!is_valid_rank(1));
    }
}
