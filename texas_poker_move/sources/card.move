module texas_poker::card;

// ========== 花色常量 ==========
const SPADES: u8 = 0;   // 黑桃 ♠
const HEARTS: u8 = 1;   // 红心 ♥
const DIAMONDS: u8 = 2; // 方块 ♦
const CLUBS: u8 = 3;    // 梅花 ♣

// ========== 点数常量 ==========
const TWO: u8 = 2;
const TEN: u8 = 10;
const JACK: u8 = 11;
const QUEEN: u8 = 12;
const KING: u8 = 13;
const ACE: u8 = 14;

// ========== 错误码 ==========
#[error]
const EInvalidSuit: vector<u8> = b"Invalid suit value";
#[error]
const EInvalidRank: vector<u8> = b"Invalid rank value";

// ========== 结构体 ==========
public struct Card has store, copy, drop {
    suit: u8,
    rank: u8,
}

// ========== 构造函数 ==========
public fun new(suit: u8, rank: u8): Card {
    assert!(is_valid_suit(suit), EInvalidSuit);
    assert!(is_valid_rank(rank), EInvalidRank);
    Card { suit, rank }
}

// ========== 访问器 ==========
public fun suit(card: &Card): u8 { card.suit }
public fun rank(card: &Card): u8 { card.rank }

// ========== 验证函数 ==========
public fun is_valid_suit(s: u8): bool {
    s == SPADES || s == HEARTS || s == DIAMONDS || s == CLUBS
}

public fun is_valid_rank(r: u8): bool {
    r >= TWO && r <= ACE
}

public fun is_valid_card(card: &Card): bool {
    is_valid_suit(card.suit) && is_valid_rank(card.rank)
}

// ========== 比较 ==========
public fun equals(a: &Card, b: &Card): bool {
    a.suit == b.suit && a.rank == b.rank
}

// ========== 花色常量访问 ==========
public fun spades(): u8 { SPADES }
public fun hearts(): u8 { HEARTS }
public fun diamonds(): u8 { DIAMONDS }
public fun clubs(): u8 { CLUBS }
public fun ace(): u8 { ACE }
public fun king(): u8 { KING }
public fun queen(): u8 { QUEEN }
public fun jack(): u8 { JACK }
public fun ten(): u8 { TEN }
public fun two(): u8 { TWO }
