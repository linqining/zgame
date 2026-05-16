use super::card::{PlayingCard, Rank, Suit};
use std::cmp::Ordering;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HandRank {
    HighCard = 1,
    OnePair = 2,
    TwoPair = 3,
    ThreeOfAKind = 4,
    Straight = 5,
    Flush = 6,
    FullHouse = 7,
    FourOfAKind = 8,
    StraightFlush = 9,
    RoyalFlush = 10,
}

impl fmt::Display for HandRank {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HighCard => write!(f, "High Card"),
            Self::OnePair => write!(f, "One Pair"),
            Self::TwoPair => write!(f, "Two Pair"),
            Self::ThreeOfAKind => write!(f, "Three of a Kind"),
            Self::Straight => write!(f, "Straight"),
            Self::Flush => write!(f, "Flush"),
            Self::FullHouse => write!(f, "Full House"),
            Self::FourOfAKind => write!(f, "Four of a Kind"),
            Self::StraightFlush => write!(f, "Straight Flush"),
            Self::RoyalFlush => write!(f, "Royal Flush"),
        }
    }
}

use std::fmt;

#[derive(Debug, Clone)]
pub struct PokerHand {
    pub cards: Vec<PlayingCard>,
    pub rank: HandRank,
    pub kickers: Vec<Rank>,
}

impl PokerHand {
    pub fn new(cards: Vec<PlayingCard>) -> Option<Self> {
        if !(5..=7).contains(&cards.len()) {
            return None;
        }
        let mut sorted_cards = cards.clone();
        sorted_cards.sort_by(|a, b| b.rank.cmp(&a.rank));
        let evaluator = HandEvaluator::evaluate(&sorted_cards)?;
        Some(Self {
            cards: sorted_cards,
            rank: evaluator.0,
            kickers: evaluator.1,
        })
    }

    pub fn cmp_hands(&self, other: &Self) -> Ordering {
        match self.rank.cmp(&other.rank) {
            Ordering::Equal => {
                for (a, b) in self.kickers.iter().zip(other.kickers.iter()) {
                    match a.cmp(b) {
                        Ordering::Equal => continue,
                        ord => return ord,
                    }
                }
                Ordering::Equal
            }
            ord => ord,
        }
    }

    pub fn beats(&self, other: &Self) -> bool {
        matches!(self.cmp_hands(other), Ordering::Greater)
    }
}

impl fmt::Display for PokerHand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cards_str: Vec<String> = self.cards.iter().map(|c| format!("{}", c)).collect();
        write!(f, "[{}] {} ({})", cards_str.join(" "), self.rank, {
            let kicker_str: Vec<String> =
                self.kickers.iter().map(|r| format!("{}", r)).collect();
            kicker_str.join(",")
        })
    }
}

pub struct HandEvaluator;

impl HandEvaluator {
    pub fn evaluate(cards: &[PlayingCard]) -> Option<(HandRank, Vec<Rank>)> {
        if cards.len() < 5 {
            return None;
        }
        let ranks: Vec<Rank> = cards.iter().map(|c| c.rank).collect();
        let suits: Vec<Suit> = cards.iter().map(|c| c.suit).collect();

        let is_flush = Self::is_flush(&suits);
        let is_straight = Self::is_straight(&ranks);

        if is_flush && is_straight {
            let high = ranks[0];
            if high == Rank::Ace {
                return Some((HandRank::RoyalFlush, vec![high]));
            }
            return Some((HandRank::StraightFlush, vec![high]));
        }

        if is_flush {
            return Some((HandRank::Flush, ranks[..5].to_vec()));
        }

        if is_straight {
            return Some((HandRank::Straight, vec![ranks[0]]));
        }

        let counts = Self::count_ranks(&ranks);
        let mut count_vec: Vec<(usize, Rank)> = counts
            .into_iter()
            .map(|(rank, count)| (count, rank))
            .collect();
        count_vec.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));

        match count_vec[0].0 {
            4 => Some((
                HandRank::FourOfAKind,
                vec![count_vec[0].1, count_vec[1].1],
            )),
            3 => {
                if count_vec.len() > 1 && count_vec[1].0 >= 2 {
                    Some((
                        HandRank::FullHouse,
                        vec![count_vec[0].1, count_vec[1].1],
                    ))
                } else {
                    Some((
                        HandRank::ThreeOfAKind,
                        vec![
                            count_vec[0].1,
                            count_vec.get(1).map(|c| c.1).unwrap_or(Rank::Two),
                            count_vec.get(2).map(|c| c.1).unwrap_or(Rank::Two),
                        ],
                    ))
                }
            }
            2 => {
                if count_vec.len() > 1 && count_vec[1].0 == 2 {
                    Some((HandRank::TwoPair, vec![count_vec[0].1, count_vec[1].1]))
                } else {
                    Some((
                        HandRank::OnePair,
                        vec![
                            count_vec[0].1,
                            count_vec.get(1).map(|c| c.1).unwrap_or(Rank::Two),
                            count_vec.get(2).map(|c| c.1).unwrap_or(Rank::Two),
                            count_vec.get(3).map(|c| c.1).unwrap_or(Rank::Two),
                        ],
                    ))
                }
            }
            _ => Some((
                HandRank::HighCard,
                ranks[..5.min(ranks.len())].to_vec(),
            )),
        }
    }

    fn is_flush(suits: &[Suit]) -> bool {
        if suits.len() < 5 {
            return false;
        }
        let first = suits[0];
        suits[..5].iter().all(|&s| s == first)
    }

    fn is_straight(ranks: &[Rank]) -> bool {
        if ranks.len() < 5 {
            return false;
        }
        let unique: Vec<Rank> = {
            let mut seen = Vec::new();
            for &r in &ranks[..5] {
                if !seen.contains(&r) {
                    seen.push(r);
                }
            }
            seen
        };
        if unique.len() != 5 {
            return false;
        }
        let high = unique[0].numeric_value();
        let low = unique[4].numeric_value();
        if high - low == 4 {
            return true;
        }
        if unique[0] == Rank::Ace && unique[1] == Rank::Five {
            return true;
        }
        false
    }

    fn count_ranks(ranks: &[Rank]) -> std::collections::HashMap<Rank, usize> {
        let mut map = std::collections::HashMap::new();
        for &r in ranks {
            *map.entry(r).or_insert(0) += 1;
        }
        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::z_poker::card::standard_deck;

    #[test]
    fn test_high_card() {
        let cards = vec![
            PlayingCard::new(Rank::Two, Suit::Club),
            PlayingCard::new(Rank::Five, Suit::Diamond),
            PlayingCard::new(Rank::Seven, Suit::Heart),
            PlayingCard::new(Rank::Nine, Suit::Spade),
            PlayingCard::new(Rank::King, Suit::Club),
        ];
        let hand = PokerHand::new(cards);
        assert!(hand.is_some());
        let h = hand.unwrap();
        assert_eq!(h.rank, HandRank::HighCard);
    }

    #[test]
    fn test_royal_flush() {
        let cards = vec![
            PlayingCard::new(Rank::Ace, Suit::Spade),
            PlayingCard::new(Rank::King, Suit::Spade),
            PlayingCard::new(Rank::Queen, Suit::Spade),
            PlayingCard::new(Rank::Jack, Suit::Spade),
            PlayingCard::new(Rank::Ten, Suit::Spade),
        ];
        let hand = PokerHand::new(cards);
        assert!(hand.is_some());
        let h = hand.unwrap();
        assert_eq!(h.rank, HandRank::RoyalFlush);
    }

    #[test]
    fn test_four_of_a_kind() {
        let cards = vec![
            PlayingCard::new(Rank::Ace, Suit::Club),
            PlayingCard::new(Rank::Ace, Suit::Diamond),
            PlayingCard::new(Rank::Ace, Suit::Heart),
            PlayingCard::new(Rank::Ace, Suit::Spade),
            PlayingCard::new(Rank::King, Suit::Club),
        ];
        let hand = PokerHand::new(cards);
        assert!(hand.is_some());
        let h = hand.unwrap();
        assert_eq!(h.rank, HandRank::FourOfAKind);
    }

    #[test]
    fn test_hand_comparison() {
        let royal = vec![
            PlayingCard::new(Rank::Ace, Suit::Spade),
            PlayingCard::new(Rank::King, Suit::Spade),
            PlayingCard::new(Rank::Queen, Suit::Spade),
            PlayingCard::new(Rank::Jack, Suit::Spade),
            PlayingCard::new(Rank::Ten, Suit::Spade),
        ];
        let pair = vec![
            PlayingCard::new(Rank::Two, Suit::Club),
            PlayingCard::new(Rank::Two, Suit::Diamond),
            PlayingCard::new(Rank::Three, Suit::Heart),
            PlayingCard::new(Rank::Four, Suit::Spade),
            PlayingCard::new(Rank::Five, Suit::Club),
        ];

        let h1 = PokerHand::new(royal).unwrap();
        let h2 = PokerHand::new(pair).unwrap();
        assert!(h1.beats(&h2));
    }

    #[test]
    fn test_less_than_5_cards_returns_none() {
        let cards = vec![
            PlayingCard::new(Rank::Ace, Suit::Spade),
            PlayingCard::new(Rank::King, Suit::Spade),
            PlayingCard::new(Rank::Queen, Suit::Spade),
            PlayingCard::new(Rank::Jack, Suit::Spade),
        ];
        assert!(PokerHand::new(cards).is_none());
    }
}
