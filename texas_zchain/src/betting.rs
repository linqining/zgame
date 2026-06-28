//! 下注轮状态机（移植自 `texas_poker::betting`）。
//!
//! 跟踪当前下注轮的 `current_bet` / `min_raise` / `last_raiser_seat`，
//! 校验 fold / check / call / raise 的合法性并返回实际投入筹码。

use serde::{Deserialize, Serialize};

use crate::Seat;

// ========== 动作常量（位掩码） ==========

/// 弃牌动作位。
pub const ACTION_FOLD: u8 = 1;
/// 过牌动作位。
pub const ACTION_CHECK: u8 = 2;
/// 跟注动作位。
pub const ACTION_CALL: u8 = 4;
/// 加注动作位。
pub const ACTION_RAISE: u8 = 8;

/// 下注轮错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BettingError {
    /// 存在需跟注的下注时不能 check。
    #[error("Cannot check when there is a bet to call")]
    CannotCheck,
    /// 无需跟注时不能 call。
    #[error("Cannot call when nothing to call")]
    CannotCall,
    /// 筹码不足，不能 raise。
    #[error("Cannot raise: insufficient stack")]
    CannotRaise,
    /// 加注金额低于最小加注额。
    #[error("Raise amount is less than minimum raise")]
    InvalidRaiseAmount,
    /// 大盲金额非法（须 > 0）。
    #[error("Big blind must be > 0")]
    InvalidBigBlind,
}

/// 单个下注轮的状态。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BettingRound {
    /// 当前下注轮的最高下注额。
    pub current_bet: u64,
    /// 最小加注增量。
    pub min_raise: u64,
    /// 大盲金额（preflop 初始 current_bet）。
    pub big_blind: u64,
    /// 最后一次合法加注者的座位（None 表示本轮尚无加注）。
    pub last_raiser_seat: Option<Seat>,
    /// 本轮已执行的动作数（含 fold）。
    pub actions_taken: u64,
}

impl BettingRound {
    /// 创建 preflop 下注轮（current_bet = big_blind）。
    pub fn new_preflop(big_blind: u64) -> Result<Self, BettingError> {
        if big_blind == 0 {
            return Err(BettingError::InvalidBigBlind);
        }
        Ok(Self {
            current_bet: big_blind,
            min_raise: big_blind,
            big_blind,
            last_raiser_seat: None,
            actions_taken: 0,
        })
    }

    /// 创建 postflop 下注轮（current_bet = 0）。
    pub fn new_postflop(big_blind: u64) -> Result<Self, BettingError> {
        if big_blind == 0 {
            return Err(BettingError::InvalidBigBlind);
        }
        Ok(Self {
            current_bet: 0,
            min_raise: big_blind,
            big_blind,
            last_raiser_seat: None,
            actions_taken: 0,
        })
    }

    /// 当前需跟注金额。
    #[must_use]
    pub fn chips_to_call(&self, seat_bet: u64) -> u64 {
        self.current_bet.saturating_sub(seat_bet)
    }

    /// 是否可以 check。
    #[must_use]
    pub fn can_check(&self, seat_bet: u64) -> bool {
        self.chips_to_call(seat_bet) == 0
    }

    /// 是否可以 call（需有跟注额且有筹码）。
    #[must_use]
    pub fn can_call(&self, seat_bet: u64, stack: u64) -> bool {
        self.chips_to_call(seat_bet) > 0 && stack > 0
    }

    /// 是否可以 raise（筹码需超过跟注额）。
    #[must_use]
    pub fn can_raise(&self, seat_bet: u64, stack: u64) -> bool {
        let to_call = self.chips_to_call(seat_bet);
        stack > to_call
    }

    /// 获取可用动作（位掩码，always 含 FOLD）。
    #[must_use]
    pub fn available_actions(&self, seat_bet: u64, stack: u64) -> u8 {
        let mut actions = ACTION_FOLD;
        if self.can_check(seat_bet) {
            actions |= ACTION_CHECK;
        }
        if self.can_call(seat_bet, stack) {
            actions |= ACTION_CALL;
        }
        if self.can_raise(seat_bet, stack) {
            actions |= ACTION_RAISE;
        }
        actions
    }

    /// 处理 call，返回实际投入筹码（受 stack 限制）。
    pub fn process_call(&mut self, seat_bet: u64, stack: u64) -> Result<u64, BettingError> {
        let to_call = self.chips_to_call(seat_bet);
        if to_call == 0 {
            return Err(BettingError::CannotCall);
        }
        let actual = to_call.min(stack);
        self.actions_taken += 1;
        Ok(actual)
    }

    /// 处理 raise，返回实际需追加的筹码。
    ///
    /// - `total_bet`：加注后的下注总额
    /// - `seat_id`：执行加注的座位
    /// - `seat_bet`：该座位本轮已投入
    /// - `stack`：该座位剩余筹码
    pub fn process_raise(
        &mut self,
        total_bet: u64,
        seat_id: Seat,
        seat_bet: u64,
        stack: u64,
    ) -> Result<u64, BettingError> {
        if total_bet <= self.current_bet {
            return Err(BettingError::InvalidRaiseAmount);
        }
        if total_bet <= seat_bet {
            return Err(BettingError::InvalidRaiseAmount);
        }
        let raise_amount = total_bet - self.current_bet;
        let needed = total_bet - seat_bet;
        if needed > stack {
            return Err(BettingError::CannotRaise);
        }

        let is_all_in = needed == stack;
        if is_all_in {
            // all-in 且满足 min_raise → 更新状态（重新打开行动权）
            if raise_amount >= self.min_raise {
                self.min_raise = raise_amount;
                self.last_raiser_seat = Some(seat_id);
            }
            // 短 all-in（raise_amount < min_raise）：不更新，不重新打开行动权
        } else {
            // 非 all-in：强制 min_raise 检查并更新状态
            if raise_amount < self.min_raise {
                return Err(BettingError::InvalidRaiseAmount);
            }
            self.min_raise = raise_amount;
            self.last_raiser_seat = Some(seat_id);
        }

        self.current_bet = total_bet;
        self.actions_taken += 1;
        Ok(needed)
    }

    /// 处理 check。
    pub fn process_check(&mut self, seat_bet: u64) -> Result<(), BettingError> {
        if self.chips_to_call(seat_bet) != 0 {
            return Err(BettingError::CannotCheck);
        }
        self.actions_taken += 1;
        Ok(())
    }

    /// 处理 fold。
    pub fn process_fold(&mut self) {
        self.actions_taken += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_preflop() {
        let r = BettingRound::new_preflop(20).unwrap();
        assert_eq!(r.current_bet, 20);
        assert_eq!(r.min_raise, 20);
        assert_eq!(r.big_blind, 20);
        assert_eq!(r.last_raiser_seat, None);
    }

    #[test]
    fn test_new_postflop() {
        let r = BettingRound::new_postflop(20).unwrap();
        assert_eq!(r.current_bet, 0);
        assert_eq!(r.min_raise, 20);
    }

    #[test]
    fn test_invalid_big_blind() {
        assert_eq!(
            BettingRound::new_preflop(0).unwrap_err(),
            BettingError::InvalidBigBlind
        );
    }

    #[test]
    fn test_chips_to_call() {
        let r = BettingRound::new_preflop(20).unwrap();
        assert_eq!(r.chips_to_call(0), 20);
        assert_eq!(r.chips_to_call(10), 10);
        assert_eq!(r.chips_to_call(20), 0);
        assert_eq!(r.chips_to_call(30), 0); // 超额不退
    }

    #[test]
    fn test_can_check_call_raise() {
        let r = BettingRound::new_preflop(20).unwrap();
        // seat_bet=0：需 call 20
        assert!(!r.can_check(0));
        assert!(r.can_call(0, 100));
        assert!(r.can_raise(0, 100)); // stack > to_call
        assert!(!r.can_raise(0, 20)); // stack == to_call，无超额筹码

        // seat_bet=20：无需 call
        assert!(r.can_check(20));
        assert!(!r.can_call(20, 100));
    }

    #[test]
    fn test_available_actions() {
        let r = BettingRound::new_preflop(20).unwrap();
        // seat_bet=0, stack=100：可 fold/call/raise，不可 check
        let a = r.available_actions(0, 100);
        assert_eq!(a & ACTION_FOLD, ACTION_FOLD);
        assert_eq!(a & ACTION_CHECK, 0);
        assert_eq!(a & ACTION_CALL, ACTION_CALL);
        assert_eq!(a & ACTION_RAISE, ACTION_RAISE);

        // seat_bet=20, stack=100：可 fold/check，不可 call/raise（postflop 场景）
        let r2 = BettingRound::new_postflop(20).unwrap();
        let a2 = r2.available_actions(0, 100);
        assert_eq!(a2 & ACTION_CHECK, ACTION_CHECK);
        assert_eq!(a2 & ACTION_CALL, 0);
        assert_eq!(a2 & ACTION_RAISE, ACTION_RAISE);
    }

    #[test]
    fn test_process_call() {
        let mut r = BettingRound::new_preflop(20).unwrap();
        // seat_bet=0, stack=100 → call 20
        let actual = r.process_call(0, 100).unwrap();
        assert_eq!(actual, 20);
        assert_eq!(r.actions_taken, 1);
    }

    #[test]
    fn test_process_call_all_in() {
        let mut r = BettingRound::new_preflop(20).unwrap();
        // stack 不足，actual = stack
        let actual = r.process_call(0, 5).unwrap();
        assert_eq!(actual, 5);
    }

    #[test]
    fn test_process_call_nothing_to_call() {
        let mut r = BettingRound::new_postflop(20).unwrap();
        assert_eq!(
            r.process_call(0, 100).unwrap_err(),
            BettingError::CannotCall
        );
    }

    #[test]
    fn test_process_raise() {
        let mut r = BettingRound::new_preflop(20).unwrap();
        // raise to 60，seat_bet=0, stack=100
        let needed = r.process_raise(60, 1, 0, 100).unwrap();
        assert_eq!(needed, 60);
        assert_eq!(r.current_bet, 60);
        assert_eq!(r.min_raise, 40); // 60-20
        assert_eq!(r.last_raiser_seat, Some(1));
    }

    #[test]
    fn test_process_raise_below_min() {
        let mut r = BettingRound::new_preflop(20).unwrap();
        // min_raise=20，raise to 30 → raise_amount=10 < 20
        assert_eq!(
            r.process_raise(30, 1, 0, 100).unwrap_err(),
            BettingError::InvalidRaiseAmount
        );
    }

    #[test]
    fn test_process_raise_all_in_short() {
        // 短 all-in（< min_raise）：不更新 min_raise/last_raiser
        let mut r = BettingRound::new_preflop(20).unwrap();
        // stack=30, seat_bet=0 → needed=30=all_in, raise_amount=10 < min_raise=20
        let needed = r.process_raise(30, 1, 0, 30).unwrap();
        assert_eq!(needed, 30);
        assert_eq!(r.current_bet, 30);
        assert_eq!(r.min_raise, 20); // 未更新
        assert_eq!(r.last_raiser_seat, None); // 未更新
    }

    #[test]
    fn test_process_raise_insufficient_stack() {
        let mut r = BettingRound::new_preflop(20).unwrap();
        // needed=60 > stack=50
        assert_eq!(
            r.process_raise(60, 1, 0, 50).unwrap_err(),
            BettingError::CannotRaise
        );
    }

    #[test]
    fn test_process_check() {
        let mut r = BettingRound::new_postflop(20).unwrap();
        r.process_check(0).unwrap();
        assert_eq!(r.actions_taken, 1);
    }

    #[test]
    fn test_process_check_with_bet() {
        let mut r = BettingRound::new_preflop(20).unwrap();
        assert_eq!(
            r.process_check(0).unwrap_err(),
            BettingError::CannotCheck
        );
    }

    #[test]
    fn test_process_fold() {
        let mut r = BettingRound::new_preflop(20).unwrap();
        r.process_fold();
        assert_eq!(r.actions_taken, 1);
        // fold 后 current_bet 不变
        assert_eq!(r.current_bet, 20);
    }
}
