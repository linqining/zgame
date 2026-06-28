//! 摊牌结算（showdown）——整合手牌评估 + 边池分配。
//!
//! 当一局到达摊牌阶段时，对每个边池层级在合格玩家中按手牌大小分配奖金。
//! 单人未弃牌（无人 call 到摊牌）时直接把底池给该玩家，无需手牌评估。
//!
//! 台费（rake）按 zchain `poker_l1::vm::contracts::settle` 公式计算：
//! `rake = min(rake_rate_bps * pot / 10_000, rake_cap)`，且 `rake <= pot`。

use serde::{Deserialize, Serialize};

use crate::card::Card;
use crate::hand_evaluator::{best_hand, HandRank};
use crate::side_pot::{calculate_side_pots, SidePot};
use crate::Address;

/// 台费配置。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RakeConfig {
    /// 台费比例（basis points，100 = 1%，max 1000 = 10%）。
    pub rake_rate_bps: u32,
    /// 单手牌台费封顶金额。
    pub rake_cap: u64,
    /// 台费收款方地址。
    pub rake_recipient: Address,
}

impl RakeConfig {
    /// 台费比例上限（10%）。
    pub const MAX_RAKE_RATE_BPS: u32 = 1000;

    /// 校验台费配置合法性。
    pub fn validate(&self) -> Result<(), ShowdownError> {
        if self.rake_rate_bps > Self::MAX_RAKE_RATE_BPS {
            return Err(ShowdownError::InvalidRakeConfig(format!(
                "rake_rate_bps {} > MAX_RAKE_RATE_BPS {}",
                self.rake_rate_bps,
                Self::MAX_RAKE_RATE_BPS
            )));
        }
        Ok(())
    }
}

/// 摊牌错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ShowdownError {
    /// 所有玩家已 fold，无胜者。
    #[error("no winner (all players folded)")]
    NoWinner,
    /// 台费配置非法。
    #[error("invalid rake config: {0}")]
    InvalidRakeConfig(String),
    /// 玩家/底池/手牌数据长度不匹配。
    #[error("data length mismatch: {0}")]
    LengthMismatch(String),
    /// 手牌评估失败。
    #[error("hand evaluation failed")]
    HandEvalFailed,
    /// 边池计算失败。
    #[error("side pot calculation failed")]
    SidePotFailed,
}

/// 单个边池的分配结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PotPayout {
    /// 该层级池底金额（已扣台费）。
    pub pot_amount: u64,
    /// 该层级台费。
    pub rake: u64,
    /// 胜者地址列表（平局时多人瓜分）。
    pub winners: Vec<Address>,
    /// 每位胜者分得金额。
    pub per_winner: u64,
}

/// 摊牌结算结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShowdownResult {
    /// 主池分配。
    pub main_pot: PotPayout,
    /// 边池分配列表。
    pub side_pots: Vec<PotPayout>,
    /// 台费总额。
    pub total_rake: u64,
    /// 台费收款方。
    pub rake_recipient: Address,
}

/// 计算台费：`rake = min(pot * rate / 10_000, rake_cap)`，且 `rake <= pot`。
#[must_use]
pub fn compute_rake(pot: u64, config: &RakeConfig) -> u64 {
    if pot == 0 {
        return 0;
    }
    let rake_by_rate = pot.saturating_mul(u64::from(config.rake_rate_bps)) / 10_000;
    let rake = rake_by_rate.min(config.rake_cap);
    rake.min(pot)
}

/// 摊牌结算输入。
#[derive(Debug, Clone)]
pub struct ShowdownInput<'a> {
    /// 各座位玩家地址。
    pub addresses: &'a [Address],
    /// 各座位本手牌累计下注。
    pub bets: &'a [u64],
    /// 各座位是否已 fold。
    pub folded: &'a [bool],
    /// 各座位是否 all-in。
    pub all_in: &'a [bool],
    /// 各座位手牌（2 张底牌）+ 5 张公共牌 = 7 张（folded 玩家可为空）。
    /// `hole_cards[i]` 为座位 i 的底牌（长度 2，未摊牌则为空）。
    pub hole_cards: &'a [Vec<Card>],
    /// 5 张公共牌。
    pub community_cards: &'a [Card],
    /// 台费配置。
    pub rake_config: &'a RakeConfig,
}

/// 执行摊牌结算。
///
/// # 流程
///
/// 1. 校验输入长度一致性与台费配置
/// 2. 计算主池/边池层级
/// 3. 每层级在合格未 fold 玩家中按 `best_hand` 分配奖金
/// 4. 扣除台费
pub fn settle_showdown(input: &ShowdownInput<'_>) -> Result<ShowdownResult, ShowdownError> {
    input.rake_config.validate()?;

    let n = input.addresses.len();
    if input.bets.len() != n
        || input.folded.len() != n
        || input.all_in.len() != n
        || input.hole_cards.len() != n
    {
        return Err(ShowdownError::LengthMismatch(format!(
            "addresses/bets/folded/all_in/hole_cards must have same length, got {}/{}/{}/{}/{}",
            input.addresses.len(),
            input.bets.len(),
            input.folded.len(),
            input.all_in.len(),
            input.hole_cards.len()
        )));
    }
    if input.community_cards.len() != 5 {
        return Err(ShowdownError::LengthMismatch(format!(
            "community_cards must be 5, got {}",
            input.community_cards.len()
        )));
    }

    // 无 all-in 时仍需判断是否有人未 fold
    let unfolded_count = input.folded.iter().filter(|&&f| !f).count();
    if unfolded_count == 0 {
        return Err(ShowdownError::NoWinner);
    }

    // 计算主池与边池
    let (main_amount, side_pots) =
        calculate_side_pots(input.bets, input.folded, input.all_in).map_err(|_| ShowdownError::SidePotFailed)?;

    // 为每个未 fold 且有手牌的玩家计算 best_hand
    let mut hand_ranks: Vec<Option<HandRank>> = Vec::with_capacity(n);
    for i in 0..n {
        if input.folded[i] || input.hole_cards[i].len() < 2 {
            hand_ranks.push(None);
            continue;
        }
        let mut seven: Vec<Card> = Vec::with_capacity(7);
        seven.extend_from_slice(&input.hole_cards[i][..2]);
        seven.extend_from_slice(input.community_cards);
        if seven.len() != 7 {
            hand_ranks.push(None);
            continue;
        }
        match best_hand(&seven) {
            Ok(hr) => hand_ranks.push(Some(hr)),
            Err(_) => return Err(ShowdownError::HandEvalFailed),
        }
    }

    let mut total_rake: u64 = 0;
    let mut all_pots: Vec<SidePot> = side_pots;
    // 主池作为第一个层级
    all_pots.insert(0, SidePot::new(main_amount, eligible_main_seats(input)));

    let mut payouts: Vec<PotPayout> = Vec::with_capacity(all_pots.len());

    for pot in &all_pots {
        if pot.amount == 0 {
            payouts.push(PotPayout {
                pot_amount: 0,
                rake: 0,
                winners: Vec::new(),
                per_winner: 0,
            });
            continue;
        }

        // 在合格座位中找最大手牌
        let mut best_hr: Option<HandRank> = None;
        for &seat in &pot.eligible_seats {
            let idx = seat as usize;
            if let Some(hr) = &hand_ranks[idx] {
                match &best_hr {
                    None => best_hr = Some(hr.clone()),
                    Some(cur) => {
                        if hr.cmp_to(cur) == std::cmp::Ordering::Greater {
                            best_hr = Some(hr.clone());
                        }
                    }
                }
            }
        }

        // 确定胜者（平局瓜分）
        let winners: Vec<Address> = match &best_hr {
            None => {
                // 无手牌（例如单人未 fold 直接获胜），取第一个合格座位
                pot.eligible_seats
                    .first()
                    .map(|&s| input.addresses[s as usize])
                    .into_iter()
                    .collect()
            }
            Some(target_hr) => pot
                .eligible_seats
                .iter()
                .filter(|&&s| hand_ranks[s as usize].as_ref() == Some(target_hr))
                .map(|&s| input.addresses[s as usize])
                .collect(),
        };

        let rake = compute_rake(pot.amount, input.rake_config);
        total_rake = total_rake
            .checked_add(rake)
            .ok_or(ShowdownError::InvalidRakeConfig("rake overflow".into()))?;
        let payout_pool = pot
            .amount
            .checked_sub(rake)
            .ok_or(ShowdownError::InvalidRakeConfig("pot underflow".into()))?;
        let per_winner = if winners.is_empty() {
            0
        } else {
            payout_pool / winners.len() as u64
        };

        payouts.push(PotPayout {
            pot_amount: payout_pool,
            rake,
            winners,
            per_winner,
        });
    }

    let main_pot = payouts.remove(0);
    Ok(ShowdownResult {
        main_pot,
        side_pots: payouts,
        total_rake,
        rake_recipient: input.rake_config.rake_recipient,
    })
}

/// 主池合格座位（所有未 fold 玩家）。
fn eligible_main_seats(input: &ShowdownInput<'_>) -> Vec<u64> {
    (0..input.folded.len())
        .filter(|&i| !input.folded[i])
        .map(|i| i as u64)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::card::{CLUBS, DIAMONDS, HEARTS, SPADES, ACE, KING, QUEEN, JACK, TEN};

    fn addr(b: u8) -> Address {
        [b; 20]
    }

    fn rake_config(rate_bps: u32, cap: u64) -> RakeConfig {
        RakeConfig {
            rake_rate_bps: rate_bps,
            rake_cap: cap,
            rake_recipient: addr(0xff),
        }
    }

    fn card(suit: u8, rank: u8) -> Card {
        Card::new_unchecked(suit, rank)
    }

    #[test]
    fn test_compute_rake() {
        let cfg = rake_config(500, 1000); // 5%
        assert_eq!(compute_rake(1000, &cfg), 50);
        assert_eq!(compute_rake(0, &cfg), 0);
        let cfg_capped = rake_config(500, 30);
        assert_eq!(compute_rake(1000, &cfg_capped), 30);
    }

    #[test]
    fn test_single_winner_no_showdown() {
        // 仅一人未 fold，直接获胜，无需手牌
        let addresses = [addr(1), addr(2), addr(3)];
        let bets = vec![100, 100, 100];
        let folded = vec![true, false, true];
        let all_in = vec![false, false, false];
        let hole_cards: Vec<Vec<Card>> = vec![vec![], vec![], vec![]];
        let community = vec![card(SPADES, 2), card(HEARTS, 3), card(DIAMONDS, 4), card(CLUBS, 5), card(SPADES, 6)];
        let input = ShowdownInput {
            addresses: &addresses,
            bets: &bets,
            folded: &folded,
            all_in: &all_in,
            hole_cards: &hole_cards,
            community_cards: &community,
            rake_config: &rake_config(500, 1000),
        };
        let result = settle_showdown(&input).unwrap();
        assert_eq!(result.main_pot.winners, vec![addr(2)]);
        assert_eq!(result.main_pot.pot_amount, 285); // 300 - 5% rake(15)
        assert_eq!(result.main_pot.rake, 15);
        assert_eq!(result.total_rake, 15);
        assert!(result.side_pots.is_empty());
    }

    #[test]
    fn test_showdown_winner_by_hand() {
        // 玩家 0: 一对 A，玩家 1: 高牌
        let addresses = [addr(1), addr(2)];
        let bets = vec![100, 100];
        let folded = vec![false, false];
        let all_in = vec![false, false];
        let hole_cards: Vec<Vec<Card>> = vec![
            vec![card(SPADES, ACE), card(HEARTS, ACE)], // AA
            vec![card(DIAMONDS, 2), card(CLUBS, 7)],   // 27o
        ];
        let community = vec![
            card(SPADES, 3),
            card(HEARTS, 5),
            card(DIAMONDS, 9),
            card(CLUBS, KING),
            card(SPADES, QUEEN),
        ];
        let input = ShowdownInput {
            addresses: &addresses,
            bets: &bets,
            folded: &folded,
            all_in: &all_in,
            hole_cards: &hole_cards,
            community_cards: &community,
            rake_config: &rake_config(0, 1000), // 0% rake 简化
        };
        let result = settle_showdown(&input).unwrap();
        assert_eq!(result.main_pot.winners, vec![addr(1)]);
        assert_eq!(result.main_pot.pot_amount, 200);
        assert_eq!(result.main_pot.per_winner, 200);
    }

    #[test]
    fn test_showdown_split_pot() {
        // 两位玩家都是 AA，平分
        let addresses = [addr(1), addr(2)];
        let bets = vec![100, 100];
        let folded = vec![false, false];
        let all_in = vec![false, false];
        let hole_cards: Vec<Vec<Card>> = vec![
            vec![card(SPADES, ACE), card(HEARTS, ACE)],
            vec![card(DIAMONDS, ACE), card(CLUBS, ACE)],
        ];
        let community = vec![
            card(SPADES, 3),
            card(HEARTS, 5),
            card(DIAMONDS, 9),
            card(CLUBS, KING),
            card(SPADES, QUEEN),
        ];
        let input = ShowdownInput {
            addresses: &addresses,
            bets: &bets,
            folded: &folded,
            all_in: &all_in,
            hole_cards: &hole_cards,
            community_cards: &community,
            rake_config: &rake_config(0, 1000),
        };
        let result = settle_showdown(&input).unwrap();
        assert_eq!(result.main_pot.winners.len(), 2);
        assert_eq!(result.main_pot.per_winner, 100); // 200 / 2
    }

    #[test]
    fn test_showdown_side_pot() {
        // 玩家 0 all-in 50，玩家 1 下注 100，玩家 2 下注 100
        // 主池=150（三人资格），边池=100（玩家1,2资格）
        // 玩家 0 手牌最强 → 赢主池；玩家 1 手牌强于玩家 2 → 赢边池
        let addresses = [addr(1), addr(2), addr(3)];
        let bets = vec![50, 100, 100];
        let folded = vec![false, false, false];
        let all_in = vec![true, false, false];
        let hole_cards: Vec<Vec<Card>> = vec![
            vec![card(SPADES, ACE), card(HEARTS, ACE)], // 玩家0: AA（最强）
            vec![card(DIAMONDS, KING), card(CLUBS, KING)], // 玩家1: KK
            vec![card(SPADES, 2), card(HEARTS, 7)],     // 玩家2: 27o（最弱）
        ];
        let community = vec![
            card(SPADES, 3),
            card(HEARTS, 5),
            card(DIAMONDS, 9),
            card(CLUBS, QUEEN),
            card(SPADES, JACK),
        ];
        let input = ShowdownInput {
            addresses: &addresses,
            bets: &bets,
            folded: &folded,
            all_in: &all_in,
            hole_cards: &hole_cards,
            community_cards: &community,
            rake_config: &rake_config(0, 1000),
        };
        let result = settle_showdown(&input).unwrap();
        // 主池赢家 = 玩家0
        assert_eq!(result.main_pot.winners, vec![addr(1)]);
        assert_eq!(result.main_pot.pot_amount, 150);
        // 边池赢家 = 玩家1
        assert_eq!(result.side_pots.len(), 1);
        assert_eq!(result.side_pots[0].winners, vec![addr(2)]);
        assert_eq!(result.side_pots[0].pot_amount, 100);
    }

    #[test]
    fn test_all_folded_error() {
        let addresses = [addr(1), addr(2)];
        let bets = vec![100, 100];
        let folded = vec![true, true];
        let all_in = vec![false, false];
        let hole_cards: Vec<Vec<Card>> = vec![vec![], vec![]];
        let community = vec![
            card(SPADES, 3),
            card(HEARTS, 5),
            card(DIAMONDS, 9),
            card(CLUBS, KING),
            card(SPADES, QUEEN),
        ];
        let input = ShowdownInput {
            addresses: &addresses,
            bets: &bets,
            folded: &folded,
            all_in: &all_in,
            hole_cards: &hole_cards,
            community_cards: &community,
            rake_config: &rake_config(500, 1000),
        };
        assert_eq!(settle_showdown(&input).unwrap_err(), ShowdownError::NoWinner);
    }

    #[test]
    fn test_length_mismatch_error() {
        let addresses = [addr(1), addr(2)];
        let bets = vec![100]; // 长度不一致
        let folded = vec![false, false];
        let all_in = vec![false, false];
        let hole_cards: Vec<Vec<Card>> = vec![vec![], vec![]];
        let community = vec![
            card(SPADES, 3),
            card(HEARTS, 5),
            card(DIAMONDS, 9),
            card(CLUBS, KING),
            card(SPADES, QUEEN),
        ];
        let input = ShowdownInput {
            addresses: &addresses,
            bets: &bets,
            folded: &folded,
            all_in: &all_in,
            hole_cards: &hole_cards,
            community_cards: &community,
            rake_config: &rake_config(500, 1000),
        };
        assert!(matches!(
            settle_showdown(&input).unwrap_err(),
            ShowdownError::LengthMismatch(_)
        ));
    }

    #[test]
    fn test_invalid_rake_config() {
        let cfg = RakeConfig {
            rake_rate_bps: 2000, // 超过 10%
            rake_cap: 1000,
            rake_recipient: addr(0xff),
        };
        let addresses = [addr(1)];
        let bets = vec![100];
        let folded = vec![false];
        let all_in = vec![false];
        let hole_cards: Vec<Vec<Card>> = vec![vec![]];
        let community = vec![
            card(SPADES, 3),
            card(HEARTS, 5),
            card(DIAMONDS, 9),
            card(CLUBS, KING),
            card(SPADES, QUEEN),
        ];
        let input = ShowdownInput {
            addresses: &addresses,
            bets: &bets,
            folded: &folded,
            all_in: &all_in,
            hole_cards: &hole_cards,
            community_cards: &community,
            rake_config: &cfg,
        };
        assert!(matches!(
            settle_showdown(&input).unwrap_err(),
            ShowdownError::InvalidRakeConfig(_)
        ));
    }

    #[test]
    fn test_royal_flush_beats_straight_flush() {
        // 玩家 0: 皇家同花顺，玩家 1: 同花顺
        let addresses = [addr(1), addr(2)];
        let bets = vec![100, 100];
        let folded = vec![false, false];
        let all_in = vec![false, false];
        let hole_cards: Vec<Vec<Card>> = vec![
            vec![card(SPADES, ACE), card(SPADES, KING)],
            vec![card(HEARTS, 9), card(HEARTS, 8)],
        ];
        // 公共牌：♠Q♠J♠10 + ♥7♥6
        let community = vec![
            card(SPADES, QUEEN),
            card(SPADES, JACK),
            card(SPADES, TEN),
            card(HEARTS, 7),
            card(HEARTS, 6),
        ];
        let input = ShowdownInput {
            addresses: &addresses,
            bets: &bets,
            folded: &folded,
            all_in: &all_in,
            hole_cards: &hole_cards,
            community_cards: &community,
            rake_config: &rake_config(0, 1000),
        };
        let result = settle_showdown(&input).unwrap();
        assert_eq!(result.main_pot.winners, vec![addr(1)]); // 皇家同花顺胜
    }

    #[test]
    fn test_total_payout_conservation() {
        // 总分配 + 台费 = 总下注
        let addresses = [addr(1), addr(2), addr(3)];
        let bets = vec![50, 100, 100];
        let folded = vec![false, false, false];
        let all_in = vec![true, false, false];
        let hole_cards: Vec<Vec<Card>> = vec![
            vec![card(SPADES, ACE), card(HEARTS, ACE)],
            vec![card(DIAMONDS, KING), card(CLUBS, KING)],
            vec![card(SPADES, 2), card(HEARTS, 7)],
        ];
        let community = vec![
            card(SPADES, 3),
            card(HEARTS, 5),
            card(DIAMONDS, 9),
            card(CLUBS, QUEEN),
            card(SPADES, JACK),
        ];
        let input = ShowdownInput {
            addresses: &addresses,
            bets: &bets,
            folded: &folded,
            all_in: &all_in,
            hole_cards: &hole_cards,
            community_cards: &community,
            rake_config: &rake_config(500, 1000), // 5%
        };
        let result = settle_showdown(&input).unwrap();
        let total_bet: u64 = bets.iter().sum();
        let total_payout: u64 = result
            .main_pot
            .per_winner
            .saturating_mul(result.main_pot.winners.len() as u64)
            + result
                .side_pots
                .iter()
                .map(|p| p.per_winner.saturating_mul(p.winners.len() as u64))
                .sum::<u64>();
        assert_eq!(
            total_payout + result.total_rake,
            total_bet,
            "总分配 + 台费必须等于总下注"
        );
    }
}
