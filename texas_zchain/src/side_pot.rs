//! 边池计算（移植自 `texas_poker::side_pot`）。
//!
//! 根据各座位的下注额、弃牌状态与 all-in 状态，计算主池与边池层级。
//! 算法与 Move 原实现一致：收集 all-in 金额并升序排列，按层级切分池底。

use serde::{Deserialize, Serialize};

use crate::Seat;

/// 单局总下注上限（10^18，远超实际筹码量，防溢出）。
pub const MAX_TOTAL_BET: u64 = 1_000_000_000_000_000_000;

/// 边池错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SidePotError {
    /// 总下注溢出。
    #[error("total bets exceed MAX_TOTAL_BET, possible overflow")]
    BetOverflow,
    /// 向量长度不一致。
    #[error("bets/folded/all_in vectors must have same length")]
    LengthMismatch,
}

/// 单个边池层级。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SidePot {
    /// 该层级池底金额。
    pub amount: u64,
    /// 有资格争夺该层级的座位索引列表。
    pub eligible_seats: Vec<Seat>,
}

impl SidePot {
    /// 构造新边池。
    #[must_use]
    pub fn new(amount: u64, eligible_seats: Vec<Seat>) -> Self {
        Self {
            amount,
            eligible_seats,
        }
    }

    /// 池底金额。
    #[must_use]
    pub const fn amount(&self) -> u64 {
        self.amount
    }

    /// 资格座位切片。
    #[must_use]
    pub fn eligible_seats(&self) -> &[Seat] {
        &self.eligible_seats
    }
}

/// 计算主池与边池。
///
/// 返回 `(main_pot_amount, side_pots)`。当无 all-in 时，`side_pots` 为空，
/// `main_pot_amount` 即总池底。
///
/// # 参数
///
/// - `bets`：各座位本手牌累计下注
/// - `folded`：各座位是否已弃牌
/// - `all_in`：各座位是否已 all-in
///
/// # 错误
/// - [`SidePotError::LengthMismatch`]：三向量长度不一致
/// - [`SidePotError::BetOverflow`]：总下注超过 `MAX_TOTAL_BET`
pub fn calculate_side_pots(
    bets: &[u64],
    folded: &[bool],
    all_in: &[bool],
) -> Result<(u64, Vec<SidePot>), SidePotError> {
    let n = bets.len();
    if folded.len() != n || all_in.len() != n {
        return Err(SidePotError::LengthMismatch);
    }
    let total_pot = sum_bets(bets)?;

    // 收集去重后的 all-in 金额
    let mut all_in_bets = collect_all_in_bets(bets, all_in);
    if all_in_bets.is_empty() {
        return Ok((total_pot, Vec::new()));
    }

    // 升序排列
    all_in_bets.sort_unstable();

    let mut side_pots: Vec<SidePot> = Vec::new();
    let mut prev_level: u64 = 0;

    for &level in &all_in_bets {
        if level <= prev_level {
            continue;
        }

        let mut pot_amount: u64 = 0;
        let mut eligible: Vec<Seat> = Vec::new();
        for (j, &bet) in bets.iter().enumerate() {
            if bet > prev_level {
                let contribution = if bet < level {
                    bet - prev_level
                } else {
                    level - prev_level
                };
                pot_amount = pot_amount
                    .checked_add(contribution)
                    .ok_or(SidePotError::BetOverflow)?;
                if !folded[j] {
                    eligible.push(j as Seat);
                }
            }
        }

        if pot_amount > 0 {
            side_pots.push(SidePot::new(pot_amount, eligible));
        }

        prev_level = level;
    }

    // 最外层（超出最大 all-in 的部分）
    let mut outer_amount: u64 = 0;
    let mut outer_eligible: Vec<Seat> = Vec::new();
    for (k, &bet) in bets.iter().enumerate() {
        if bet > prev_level {
            outer_amount = outer_amount
                .checked_add(bet - prev_level)
                .ok_or(SidePotError::BetOverflow)?;
            if !folded[k] {
                outer_eligible.push(k as Seat);
            }
        }
    }
    if outer_amount > 0 {
        side_pots.push(SidePot::new(outer_amount, outer_eligible));
    }

    // 当最后一个 side_pot（outer pot）的 eligible 为空时
    // （所有超额贡献者都 folded），将其金额合并到上一个有 eligible 的层级，避免筹码丢失。
    if let Some(last) = side_pots.last()
        && last.eligible_seats.is_empty()
        && last.amount > 0
    {
        let merge_amount = last.amount;
        side_pots.pop();
        if !side_pots.is_empty() {
            // 从后往前找第一个有 eligible 的层级
            let mut merge_idx = 0;
            for k in (0..side_pots.len()).rev() {
                if !side_pots[k].eligible_seats.is_empty() {
                    merge_idx = k;
                    break;
                }
            }
            side_pots[merge_idx].amount = side_pots[merge_idx]
                .amount
                .checked_add(merge_amount)
                .ok_or(SidePotError::BetOverflow)?;
        } else {
            // pop 后 side_pots 为空，重新放回（由调用方处理）
            side_pots.push(SidePot::new(merge_amount, Vec::new()));
        }
    }

    // 主池 = 第一个边池
    if let Some(first) = side_pots.first() {
        let main = first.amount;
        let rest = side_pots[1..].to_vec();
        Ok((main, rest))
    } else {
        Ok((total_pot, Vec::new()))
    }
}

/// 求和并校验溢出。
fn sum_bets(bets: &[u64]) -> Result<u64, SidePotError> {
    let mut total: u64 = 0;
    for &b in bets {
        total = total
            .checked_add(b)
            .ok_or(SidePotError::BetOverflow)?;
        if total > MAX_TOTAL_BET {
            return Err(SidePotError::BetOverflow);
        }
    }
    Ok(total)
}

/// 收集去重后的 all-in 金额。
fn collect_all_in_bets(bets: &[u64], all_in: &[bool]) -> Vec<u64> {
    let mut result: Vec<u64> = Vec::new();
    for (&bet, &is_all_in) in bets.iter().zip(all_in.iter()) {
        if is_all_in && bet > 0 && !result.contains(&bet) {
            result.push(bet);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_all_in() {
        // 无 all-in：返回总池底，无边池
        let bets = vec![100, 100, 100];
        let folded = vec![false, false, false];
        let all_in = vec![false, false, false];
        let (main, sides) = calculate_side_pots(&bets, &folded, &all_in).unwrap();
        assert_eq!(main, 300);
        assert!(sides.is_empty());
    }

    #[test]
    fn test_single_all_in() {
        // 玩家 0 all-in 50，其他人各下注 100
        // 主池 = 50*3 = 150（三人有资格）
        // 边池 = (100-50)*2 = 100（玩家 1, 2 有资格）
        let bets = vec![50, 100, 100];
        let folded = vec![false, false, false];
        let all_in = vec![true, false, false];
        let (main, sides) = calculate_side_pots(&bets, &folded, &all_in).unwrap();
        assert_eq!(main, 150);
        assert_eq!(sides.len(), 1);
        assert_eq!(sides[0].amount, 100);
        assert_eq!(sides[0].eligible_seats, vec![1, 2]);
    }

    #[test]
    fn test_all_in_with_folded() {
        // 玩家 0 all-in 50 后 fold 的人贡献仍计入主池
        let bets = vec![50, 50, 100];
        let folded = vec![false, true, false];
        let all_in = vec![true, false, false];
        let (main, sides) = calculate_side_pots(&bets, &folded, &all_in).unwrap();
        // 主池 = 50+50+50 = 150，eligible = [0, 2]（座位1 folded）
        assert_eq!(main, 150);
        // 边池 = (100-50) = 50，eligible = [2]
        assert_eq!(sides.len(), 1);
        assert_eq!(sides[0].amount, 50);
        assert_eq!(sides[0].eligible_seats, vec![2]);
    }

    #[test]
    fn test_multiple_all_in_levels() {
        // 三个 all-in 级别：50, 80, 120
        let bets = vec![50, 80, 120, 200];
        let folded = vec![false, false, false, false];
        let all_in = vec![true, true, true, false];
        let (main, sides) = calculate_side_pots(&bets, &folded, &all_in).unwrap();
        // 层级 50：min(bet,50)-0 各贡献 50*4=200，eligible=[0,1,2,3]
        assert_eq!(main, 200);
        // 层级 80：(80-50)*3 + (80-50) = 30*3 + ... 实际上座位0=50<=80不贡献
        //   座位1: 80-50=30, 座位2: 80-50=30, 座位3: 80-50=30 → 90, eligible=[1,2,3]
        // 层级 120：座位1=80<=120不贡献，座位2: 120-80=40, 座位3: 120-80=40 → 80, eligible=[2,3]
        // outer: 座位3: 200-120=80, eligible=[3]
        assert_eq!(sides.len(), 3);
        assert_eq!(sides[0].amount, 90);
        assert_eq!(sides[0].eligible_seats, vec![1, 2, 3]);
        assert_eq!(sides[1].amount, 80);
        assert_eq!(sides[1].eligible_seats, vec![2, 3]);
        assert_eq!(sides[2].amount, 80);
        assert_eq!(sides[2].eligible_seats, vec![3]);
    }

    #[test]
    fn test_outer_pot_empty_eligible_merged() {
        // 所有超额贡献者都 folded → 合并到上一个有 eligible 的层级
        let bets = vec![100, 200];
        let folded = vec![false, true];
        let all_in = vec![true, false];
        let (main, sides) = calculate_side_pots(&bets, &folded, &all_in).unwrap();
        // 层级 100：座位0贡献100 + 座位1贡献100 = 200，eligible=[0]（座位1 folded 不计入）
        // outer: 座位1 bet=200>100，贡献100，但座位1 folded → eligible 为空
        //   → 合并到上一个有 eligible 的层级（main pot）
        // main = 200 + 100(合并) = 300
        assert_eq!(main, 300);
        assert!(sides.is_empty(), "outer 已合并到 main，sides 应为空");
        // 总金额守恒：main + sides = 300 = sum(bets)
        let total: u64 = main + sides.iter().map(|s| s.amount).sum::<u64>();
        assert_eq!(total, 300, "总金额守恒");
    }

    #[test]
    fn test_length_mismatch() {
        let bets = vec![100, 100];
        let folded = vec![false];
        let all_in = vec![false, false];
        assert_eq!(
            calculate_side_pots(&bets, &folded, &all_in).unwrap_err(),
            SidePotError::LengthMismatch
        );
    }

    #[test]
    fn test_overflow_detected() {
        let bets = vec![u64::MAX, 1];
        let folded = vec![false, false];
        let all_in = vec![false, false];
        assert_eq!(
            calculate_side_pots(&bets, &folded, &all_in).unwrap_err(),
            SidePotError::BetOverflow
        );
    }

    #[test]
    fn test_total_pot_conservation() {
        // 总金额守恒：main + side_pots 之和 = sum(bets)
        let bets = vec![30, 60, 120, 200];
        let folded = vec![false, true, false, false];
        let all_in = vec![true, false, true, false];
        let (main, sides) = calculate_side_pots(&bets, &folded, &all_in).unwrap();
        let total: u64 = main + sides.iter().map(|s| s.amount).sum::<u64>();
        let expected: u64 = bets.iter().sum();
        assert_eq!(total, expected, "总金额必须守恒");
    }

    #[test]
    fn test_empty_bets() {
        let bets: Vec<u64> = vec![];
        let folded: Vec<bool> = vec![];
        let all_in: Vec<bool> = vec![];
        let (main, sides) = calculate_side_pots(&bets, &folded, &all_in).unwrap();
        assert_eq!(main, 0);
        assert!(sides.is_empty());
    }
}
