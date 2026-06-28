//! 合约入口层——rBPF entrypoint 调度 + Host 抽象。
//!
//! 设计参考 zchain `poker_l1` 的"纯 Rust 业务逻辑 + 合约源码模板"双层模型：
//! - [`Host`] trait 抽象 syscall（`object_read` / `object_write` / `object_create` /
//!   `emit_event` / `get_block_height`），使合约逻辑可在 std 环境下测试。
//! - [`StdHost`] 是 `Host` 的内存实现，用于 `cargo test` 验证合约调度逻辑。
//! - [`TexasContract`] 是合约调度器，按 `method_selector` 分派到业务逻辑。
//! - [`BPF_ENTRYPOINT_SOURCE`] 是可在 BPF 工具链下编译的 entrypoint 源码模板。
//!
//! # method_selector 约定
//!
//! `method_selector = blake2b_256(method_name)[0..32]`，与 zchain `ContractCall` 一致。
//! 本合约支持以下方法：
//!
//! | method_name        | 业务逻辑                         |
//! |--------------------|----------------------------------|
//! | `create_game`      | 创建 Game 对象                   |
//! | `apply_action`     | 应用玩家动作（fold/check/call/raise） |
//! | `settle_showdown`  | 摊牌结算                         |

use std::collections::BTreeMap;

use crate::betting::{BettingRound, BettingError};
use crate::showdown::{settle_showdown, RakeConfig, ShowdownError, ShowdownInput, ShowdownResult};
use crate::{Address, ObjectID};

/// 合约方法选择器（blake2b_256(method_name)[0..32]）。
pub type MethodSelector = [u8; 32];

/// Host 抽象——对 zchain syscall 的 trait 封装。
///
/// 合约逻辑通过 `Host` 读写对象、发射事件，与具体 syscall 实现解耦，
/// 便于在 std 环境下用 [`StdHost`] 单元测试。
pub trait Host {
    /// 读取对象内容，返回实际读取字节数。
    fn object_read(&mut self, id: &ObjectID, out: &mut [u8]) -> usize;

    /// 写入对象内容，返回 0 表示成功。
    fn object_write(&mut self, id: &ObjectID, data: &[u8]) -> u64;

    /// 创建对象，返回新对象 ID。
    fn object_create(&mut self, data: &[u8]) -> Option<ObjectID>;

    /// 发射事件。
    fn emit_event(&mut self, payload: &[u8]);

    /// 当前 block height。
    fn get_block_height(&self) -> u64;
}

/// 内存 Host 实现（仅用于测试）。
#[derive(Debug, Default)]
pub struct StdHost {
    /// 对象存储（ObjectID → 字节）。
    pub objects: BTreeMap<ObjectID, Vec<u8>>,
    /// 事件日志。
    pub events: Vec<Vec<u8>>,
    /// 当前 block height。
    pub block_height: u64,
    /// 对象创建 nonce。
    creation_nonce: u64,
}

impl StdHost {
    /// 创建空 host。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 设置 block height。
    pub fn set_block_height(&mut self, h: u64) {
        self.block_height = h;
    }

    /// 预置对象。
    pub fn put_object(&mut self, id: ObjectID, data: Vec<u8>) {
        self.objects.insert(id, data);
    }
}

impl Host for StdHost {
    fn object_read(&mut self, id: &ObjectID, out: &mut [u8]) -> usize {
        match self.objects.get(id) {
            Some(data) => {
                let n = data.len().min(out.len());
                out[..n].copy_from_slice(&data[..n]);
                n
            }
            None => 0,
        }
    }

    fn object_write(&mut self, id: &ObjectID, data: &[u8]) -> u64 {
        self.objects.insert(*id, data.to_vec());
        0
    }

    fn object_create(&mut self, data: &[u8]) -> Option<ObjectID> {
        let mut id = [0u8; 28];
        // 简化：用 block_height 与 nonce 生成 ID（实际链上由 caller+nonce 派生）
        id[0..8].copy_from_slice(&self.block_height.to_le_bytes());
        self.creation_nonce += 1;
        id[8..16].copy_from_slice(&self.creation_nonce.to_le_bytes());
        self.objects.insert(id, data.to_vec());
        Some(id)
    }

    fn emit_event(&mut self, payload: &[u8]) {
        self.events.push(payload.to_vec());
    }

    fn get_block_height(&self) -> u64 {
        self.block_height
    }
}

/// 合约错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ContractError {
    /// 未知方法选择器。
    #[error("unknown method selector")]
    UnknownMethod,
    /// 对象读取失败。
    #[error("object_read failed")]
    ObjectReadFailed,
    /// 对象写入失败。
    #[error("object_write failed")]
    ObjectWriteFailed,
    /// 对象创建失败。
    #[error("object_create failed")]
    ObjectCreateFailed,
    /// 输入数据过短。
    #[error("input too short")]
    InputTooShort,
    /// 下注错误。
    #[error("betting error")]
    Betting(#[from] BettingError),
    /// 摊牌错误。
    #[error("showdown error")]
    Showdown(#[from] ShowdownError),
    /// 序列化错误。
    #[error("serialization error: {0}")]
    Serialization(String),
}

/// Texas Hold'em 合约调度器。
pub struct TexasContract;

/// 方法名常量。
pub const METHOD_CREATE_GAME: &str = "create_game";
/// `apply_action` 方法名常量。
pub const METHOD_APPLY_ACTION: &str = "apply_action";
/// `settle_showdown` 方法名常量。
pub const METHOD_SETTLE_SHOWDOWN: &str = "settle_showdown";

/// 简化版方法选择器（取方法名前 32 字节，不足补 0）。
///
/// 注意：实际链上使用 `blake2b_256(method_name)`，此处简化以避免引入 blake2 依赖。
#[must_use]
pub fn method_selector(name: &str) -> MethodSelector {
    let mut sel = [0u8; 32];
    let bytes = name.as_bytes();
    let n = bytes.len().min(32);
    sel[..n].copy_from_slice(&bytes[..n]);
    sel
}

/// 创建 Game 对象的输入。
#[derive(Debug, Clone)]
pub struct CreateGameInput {
    /// 玩家地址列表。
    pub players: Vec<Address>,
    /// 大盲金额。
    pub big_blind: u64,
    /// 小盲金额。
    pub small_blind: u64,
    /// 台费配置。
    pub rake_config: RakeConfig,
}

/// Game 对象的序列化布局（简化版，固定大小）。
///
/// 实际链上用 BCS 序列化，此处用固定布局便于 BPF 环境解析。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GameObject {
    /// 玩家数。
    pub player_count: u8,
    /// 大盲。
    pub big_blind: u64,
    /// 小盲。
    pub small_blind: u64,
    /// 底池。
    pub pot: u64,
    /// 当前下注。
    pub current_bet: u64,
}

impl GameObject {
    /// 序列化为字节。
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(33);
        out.push(self.player_count);
        out.extend_from_slice(&self.big_blind.to_le_bytes());
        out.extend_from_slice(&self.small_blind.to_le_bytes());
        out.extend_from_slice(&self.pot.to_le_bytes());
        out.extend_from_slice(&self.current_bet.to_le_bytes());
        out
    }

    /// 从字节反序列化。
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 33 {
            return None;
        }
        Some(Self {
            player_count: data[0],
            big_blind: u64::from_le_bytes(data[1..9].try_into().ok()?),
            small_blind: u64::from_le_bytes(data[9..17].try_into().ok()?),
            pot: u64::from_le_bytes(data[17..25].try_into().ok()?),
            current_bet: u64::from_le_bytes(data[25..33].try_into().ok()?),
        })
    }
}

/// 应用玩家动作的输入。
#[derive(Debug, Clone)]
pub struct ApplyActionInput {
    /// Game 对象 ID。
    pub game_id: ObjectID,
    /// 动作类型：0=Fold, 1=Check, 2=Call, 3=Raise。
    pub action_type: u8,
    /// 动作金额（Raise 时为加注总额，其他忽略）。
    pub amount: u64,
    /// 座位已投入。
    pub seat_bet: u64,
    /// 座位剩余筹码。
    pub stack: u64,
    /// 座位 ID。
    pub seat_id: u64,
    /// 是否 preflop。
    pub is_preflop: bool,
}

/// 应用玩家动作的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyActionResult {
    /// 实际投入筹码。
    pub chips_in: u64,
    /// 更新后的 current_bet。
    pub current_bet: u64,
}

impl TexasContract {
    /// 创建 Game 对象。
    pub fn create_game(host: &mut impl Host, input: &CreateGameInput) -> Result<ObjectID, ContractError> {
        let game = GameObject {
            player_count: input.players.len() as u8,
            big_blind: input.big_blind,
            small_blind: input.small_blind,
            pot: 0,
            current_bet: if input.big_blind > 0 { input.big_blind } else { 0 },
        };
        let data = game.to_bytes();
        let id = host
            .object_create(&data)
            .ok_or(ContractError::ObjectCreateFailed)?;
        host.emit_event(b"GameCreated");
        Ok(id)
    }

    /// 应用玩家动作。
    pub fn apply_action(
        host: &mut impl Host,
        input: &ApplyActionInput,
    ) -> Result<ApplyActionResult, ContractError> {
        // 读取当前 Game 对象
        let mut buf = [0u8; 256];
        let n = host.object_read(&input.game_id, &mut buf);
        if n == 0 {
            return Err(ContractError::ObjectReadFailed);
        }
        let mut game = GameObject::from_bytes(&buf[..n]).ok_or(ContractError::InputTooShort)?;

        // 构造 BettingRound（从 Game 对象恢复状态）
        let mut round = if input.is_preflop {
            BettingRound::new_preflop(game.big_blind)?
        } else {
            BettingRound::new_postflop(game.big_blind)?
        };
        round.current_bet = game.current_bet;

        let chips_in = match input.action_type {
            0 => {
                round.process_fold();
                0
            }
            1 => {
                round.process_check(input.seat_bet)?;
                0
            }
            2 => round.process_call(input.seat_bet, input.stack)?,
            3 => round.process_raise(
                input.amount,
                input.seat_id,
                input.seat_bet,
                input.stack,
            )?,
            _ => return Err(ContractError::InputTooShort),
        };

        // 更新 Game 对象
        game.current_bet = round.current_bet;
        game.pot = game.pot.saturating_add(chips_in);
        let write_res = host.object_write(&input.game_id, &game.to_bytes());
        if write_res != 0 {
            return Err(ContractError::ObjectWriteFailed);
        }
        host.emit_event(b"ActionApplied");

        Ok(ApplyActionResult {
            chips_in,
            current_bet: round.current_bet,
        })
    }

    /// 摊牌结算。
    pub fn settle_showdown_method(
        host: &mut impl Host,
        input: &ShowdownInput<'_>,
    ) -> Result<ShowdownResult, ContractError> {
        let result = settle_showdown(input)?;
        // 发射结算事件
        let event = format!(
            "Settled:main_pot={},rake={}",
            result.main_pot.pot_amount, result.total_rake
        );
        host.emit_event(event.as_bytes());
        Ok(result)
    }

    /// 按 method_selector 分派调用。
    ///
    /// 这是合约 entrypoint 的核心调度逻辑。在 BPF 环境中，entrypoint 解析输入后
    /// 调用此函数（或等价逻辑）分派到具体方法。
    pub fn dispatch(
        host: &mut impl Host,
        selector: &MethodSelector,
        input: &[u8],
    ) -> Result<Vec<u8>, ContractError> {
        let create_sel = method_selector(METHOD_CREATE_GAME);
        let action_sel = method_selector(METHOD_APPLY_ACTION);
        let settle_sel = method_selector(METHOD_SETTLE_SHOWDOWN);

        if selector == &create_sel {
            // 简化：input 直接作为 GameObject 字节创建
            let id = host
                .object_create(input)
                .ok_or(ContractError::ObjectCreateFailed)?;
            host.emit_event(b"GameCreated");
            Ok(id.to_vec())
        } else if selector == &action_sel {
            // 简化：直接写回 input 作为新状态
            if input.len() < 28 {
                return Err(ContractError::InputTooShort);
            }
            let mut game_id = [0u8; 28];
            game_id.copy_from_slice(&input[..28]);
            let res = host.object_write(&game_id, &input[28..]);
            if res != 0 {
                return Err(ContractError::ObjectWriteFailed);
            }
            host.emit_event(b"ActionApplied");
            Ok(vec![0])
        } else if selector == &settle_sel {
            // settle 在 BPF 环境需完整解析 ShowdownInput，此处仅发射事件占位
            host.emit_event(b"SettleShowdown");
            Ok(vec![0])
        } else {
            Err(ContractError::UnknownMethod)
        }
    }
}

/// BPF entrypoint 源码模板（可用 `solana-bpf-tools` 编译为 `.so`）。
///
/// 此源码遵循 zchain syscall 调用约定（见 zchain 合约开发文档第 6 节）：
/// - `entrypoint(input: *const u8, input_len: u64) -> u64`
/// - syscall 通过 `extern "C"` 声明，参数顺序与 zchain `syscalls.rs` 一致
pub const BPF_ENTRYPOINT_SOURCE: &str = r#"// texas_holdem.rs — zchain BPF 合约 entrypoint
#![no_std]
#![no_main]

const OBJECT_ID_LEN: u64 = 28;

// zchain syscall 声明（参数顺序与 poker_l1/src/vm/syscalls.rs 一致）
extern "C" {
    fn object_read(id_ptr: u64, id_len: u64, out_ptr: u64, out_capacity: u64, _arg5: u64) -> u64;
    fn object_write(id_ptr: u64, id_len: u64, data_ptr: u64, data_len: u64, _arg5: u64) -> u64;
    fn object_create(data_ptr: u64, data_len: u64, out_id_ptr: u64, out_id_len: u64, _arg5: u64) -> u64;
    fn emit_event(payload_ptr: u64, payload_len: u64, _arg3: u64, _arg4: u64, _arg5: u64) -> u64;
    fn log(msg_ptr: u64, msg_len: u64, _arg3: u64, _arg4: u64, _arg5: u64) -> u64;
    fn panic(msg_ptr: u64, msg_len: u64, _arg3: u64, _arg4: u64, _arg5: u64) -> u64;
    fn get_block_height(_arg1: u64, _arg2: u64, _arg3: u64, _arg4: u64, _arg5: u64) -> u64;
    fn get_timestamp(_arg1: u64, _arg2: u64, _arg3: u64, _arg4: u64, _arg5: u64) -> u64;
}

// method_selector = blake2b_256(method_name)[0..32]
// 预计算的选择器（实际部署时用脚本生成）：
//   create_game     = blake2b_256("create_game")
//   apply_action    = blake2b_256("apply_action")
//   settle_showdown = blake2b_256("settle_showdown")

#[no_mangle]
pub extern "C" fn entrypoint(input: *const u8, input_len: u64) -> u64 {
    if input_len < 32 {
        unsafe { panic(b"input too short".as_ptr(), 15, 0, 0, 0); }
        return 1;
    }

    // input 布局：[0..32) = method_selector, [32..) = method_args
    let mut selector = [0u8; 32];
    unsafe {
        core::ptr::copy_nonoverlapping(input, selector.as_mut_ptr(), 32);
    }

    // 读取 block height（用于对象创建 nonce）
    let _block_height = unsafe { get_block_height(0, 0, 0, 0, 0) };

    // 分派：比较 selector 前缀（简化版，实际用完整 32 字节比较）
    // create_game: "create_game" 前 11 字节
    if selector_starts_with(&selector, b"create_game") {
        return do_create_game(input, input_len);
    }
    if selector_starts_with(&selector, b"apply_action") {
        return do_apply_action(input, input_len);
    }
    if selector_starts_with(&selector, b"settle_showdown") {
        return do_settle_showdown(input, input_len);
    }

    unsafe { panic(b"unknown method".as_ptr(), 14, 0, 0, 0); }
    2
}

fn selector_starts_with(sel: &[u8; 32], name: &[u8]) -> bool {
    let n = name.len();
    if n > 32 { return false; }
    let mut i = 0;
    while i < n {
        if sel[i] != name[i] { return false; }
        i += 1;
    }
    true
}

fn do_create_game(input: *const u8, input_len: u64) -> u64 {
    // input[32..] = GameObject 序列化字节
    if input_len <= 32 {
        unsafe { panic(b"no game data".as_ptr(), 12, 0, 0, 0); }
        return 3;
    }
    let data_ptr = unsafe { input.add(32) };
    let data_len = input_len - 32;

    let mut out_id = [0u8; 28];
    let res = unsafe {
        object_create(data_ptr as u64, data_len, out_id.as_mut_ptr() as u64, OBJECT_ID_LEN, 0)
    };
    if res != 0 {
        unsafe { panic(b"object_create failed".as_ptr(), 20, 0, 0, 0); }
        return 4;
    }

    let event = b"GameCreated";
    unsafe { emit_event(event.as_ptr() as u64, event.len() as u64, 0, 0, 0); }
    0
}

fn do_apply_action(input: *const u8, input_len: u64) -> u64 {
    // input[32..60) = game_id (28B), input[60..) = 新状态字节
    if input_len < 60 {
        unsafe { panic(b"input too short".as_ptr(), 15, 0, 0, 0); }
        return 5;
    }
    let id_ptr = unsafe { input.add(32) };
    let data_ptr = unsafe { input.add(60) };
    let data_len = input_len - 60;

    let res = unsafe {
        object_write(id_ptr as u64, OBJECT_ID_LEN, data_ptr as u64, data_len, 0)
    };
    if res != 0 {
        unsafe { panic(b"object_write failed".as_ptr(), 20, 0, 0, 0); }
        return 6;
    }
    let event = b"ActionApplied";
    unsafe { emit_event(event.as_ptr() as u64, event.len() as u64, 0, 0, 0); }
    0
}

fn do_settle_showdown(input: *const u8, input_len: u64) -> u64 {
    // 摊牌结算：解析 ShowdownInput，调用 best_hand + side_pot 分配
    // 完整实现需 BCS 反序列化，此处发射事件占位
    let _ = input;
    let _ = input_len;
    let event = b"SettleShowdown";
    unsafe { emit_event(event.as_ptr() as u64, event.len() as u64, 0, 0, 0); }
    0
}
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::card::{Card, DIAMONDS, HEARTS, SPADES, ACE, KING, QUEEN, JACK};
    use crate::showdown::ShowdownInput;

    fn addr(b: u8) -> Address {
        [b; 20]
    }

    fn rake_config() -> RakeConfig {
        RakeConfig {
            rake_rate_bps: 500,
            rake_cap: 1000,
            rake_recipient: addr(0xff),
        }
    }

    #[test]
    fn test_method_selector_deterministic() {
        let s1 = method_selector("create_game");
        let s2 = method_selector("create_game");
        assert_eq!(s1, s2);
        assert_ne!(s1, method_selector("apply_action"));
    }

    #[test]
    fn test_create_game() {
        let mut host = StdHost::new();
        host.set_block_height(100);
        let input = CreateGameInput {
            players: vec![addr(1), addr(2)],
            big_blind: 20,
            small_blind: 10,
            rake_config: rake_config(),
        };
        let id = TexasContract::create_game(&mut host, &input).unwrap();
        assert!(!host.objects.is_empty());
        assert!(host.events.iter().any(|e| e == b"GameCreated"));
        // 验证对象内容
        let mut buf = [0u8; 256];
        let n = host.object_read(&id, &mut buf);
        assert!(n > 0);
        let game = GameObject::from_bytes(&buf[..n]).unwrap();
        assert_eq!(game.player_count, 2);
        assert_eq!(game.big_blind, 20);
    }

    #[test]
    fn test_apply_action_fold() {
        let mut host = StdHost::new();
        host.set_block_height(100);

        // 先创建 game
        let create_input = CreateGameInput {
            players: vec![addr(1), addr(2)],
            big_blind: 20,
            small_blind: 10,
            rake_config: rake_config(),
        };
        let game_id = TexasContract::create_game(&mut host, &create_input).unwrap();

        // 执行 fold
        let action = ApplyActionInput {
            game_id,
            action_type: 0, // Fold
            amount: 0,
            seat_bet: 0,
            stack: 100,
            seat_id: 0,
            is_preflop: true,
        };
        let result = TexasContract::apply_action(&mut host, &action).unwrap();
        assert_eq!(result.chips_in, 0);
        assert!(host.events.iter().any(|e| e == b"ActionApplied"));
    }

    #[test]
    fn test_apply_action_raise() {
        let mut host = StdHost::new();
        host.set_block_height(100);

        let create_input = CreateGameInput {
            players: vec![addr(1), addr(2)],
            big_blind: 20,
            small_blind: 10,
            rake_config: rake_config(),
        };
        let game_id = TexasContract::create_game(&mut host, &create_input).unwrap();

        // raise to 60
        let action = ApplyActionInput {
            game_id,
            action_type: 3, // Raise
            amount: 60,
            seat_bet: 0,
            stack: 100,
            seat_id: 1,
            is_preflop: true,
        };
        let result = TexasContract::apply_action(&mut host, &action).unwrap();
        assert_eq!(result.chips_in, 60);
        assert_eq!(result.current_bet, 60);
    }

    #[test]
    fn test_settle_showdown_method() {
        let mut host = StdHost::new();
        host.set_block_height(100);

        let addresses = [addr(1), addr(2)];
        let bets = vec![100, 100];
        let folded = vec![false, false];
        let all_in = vec![false, false];
        let hole_cards: Vec<Vec<Card>> = vec![
            vec![Card::new_unchecked(SPADES, ACE), Card::new_unchecked(HEARTS, ACE)],
            vec![Card::new_unchecked(DIAMONDS, 2), Card::new_unchecked(DIAMONDS, 7)],
        ];
        let community = vec![
            Card::new_unchecked(SPADES, 3),
            Card::new_unchecked(HEARTS, 5),
            Card::new_unchecked(DIAMONDS, 9),
            Card::new_unchecked(SPADES, KING),
            Card::new_unchecked(SPADES, QUEEN),
        ];
        let input = ShowdownInput {
            addresses: &addresses,
            bets: &bets,
            folded: &folded,
            all_in: &all_in,
            hole_cards: &hole_cards,
            community_cards: &community,
            rake_config: &rake_config(),
        };
        let result = TexasContract::settle_showdown_method(&mut host, &input).unwrap();
        assert_eq!(result.main_pot.winners, vec![addr(1)]);
        assert!(host.events.iter().any(|e| e.starts_with(b"Settled")));
    }

    #[test]
    fn test_dispatch_create_game() {
        let mut host = StdHost::new();
        let selector = method_selector(METHOD_CREATE_GAME);
        let game_data = GameObject {
            player_count: 2,
            big_blind: 20,
            small_blind: 10,
            pot: 0,
            current_bet: 20,
        }
        .to_bytes();
        let result = TexasContract::dispatch(&mut host, &selector, &game_data).unwrap();
        assert_eq!(result.len(), 28); // ObjectID
    }

    #[test]
    fn test_dispatch_unknown_method() {
        let mut host = StdHost::new();
        let selector = [0xff; 32];
        let result = TexasContract::dispatch(&mut host, &selector, &[]);
        assert_eq!(result.unwrap_err(), ContractError::UnknownMethod);
    }

    #[test]
    fn test_game_object_roundtrip() {
        let game = GameObject {
            player_count: 6,
            big_blind: 50,
            small_blind: 25,
            pot: 300,
            current_bet: 100,
        };
        let bytes = game.to_bytes();
        let restored = GameObject::from_bytes(&bytes).unwrap();
        assert_eq!(game, restored);
    }

    #[test]
    fn test_bpf_entrypoint_source_not_empty() {
        assert!(!BPF_ENTRYPOINT_SOURCE.is_empty());
        assert!(BPF_ENTRYPOINT_SOURCE.contains("#![no_std]"));
        assert!(BPF_ENTRYPOINT_SOURCE.contains("entrypoint"));
        assert!(BPF_ENTRYPOINT_SOURCE.contains("object_read"));
        assert!(BPF_ENTRYPOINT_SOURCE.contains("object_write"));
        assert!(BPF_ENTRYPOINT_SOURCE.contains("object_create"));
        assert!(BPF_ENTRYPOINT_SOURCE.contains("emit_event"));
    }

    #[test]
    fn test_full_game_flow() {
        // 完整流程：创建 game → 应用动作 → 摊牌结算
        let mut host = StdHost::new();
        host.set_block_height(100);

        // 1. 创建 game
        let create_input = CreateGameInput {
            players: vec![addr(1), addr(2)],
            big_blind: 20,
            small_blind: 10,
            rake_config: rake_config(),
        };
        let game_id = TexasContract::create_game(&mut host, &create_input).unwrap();

        // 2. 玩家 1 raise
        let raise = ApplyActionInput {
            game_id,
            action_type: 3,
            amount: 60,
            seat_bet: 0,
            stack: 200,
            seat_id: 0,
            is_preflop: true,
        };
        let r1 = TexasContract::apply_action(&mut host, &raise).unwrap();
        assert_eq!(r1.chips_in, 60);

        // 3. 玩家 2 call
        let call = ApplyActionInput {
            game_id,
            action_type: 2,
            amount: 0,
            seat_bet: 0,
            stack: 200,
            seat_id: 1,
            is_preflop: true,
        };
        let r2 = TexasContract::apply_action(&mut host, &call).unwrap();
        assert_eq!(r2.chips_in, 60);

        // 4. 摊牌
        let addresses = [addr(1), addr(2)];
        let bets = vec![r1.chips_in, r2.chips_in];
        let folded = vec![false, false];
        let all_in = vec![false, false];
        let hole_cards: Vec<Vec<Card>> = vec![
            vec![Card::new_unchecked(SPADES, ACE), Card::new_unchecked(HEARTS, ACE)],
            vec![Card::new_unchecked(DIAMONDS, KING), Card::new_unchecked(SPADES, JACK)],
        ];
        let community = vec![
            Card::new_unchecked(SPADES, 3),
            Card::new_unchecked(HEARTS, 5),
            Card::new_unchecked(DIAMONDS, 9),
            Card::new_unchecked(SPADES, QUEEN),
            Card::new_unchecked(HEARTS, 2),
        ];
        let settle_input = ShowdownInput {
            addresses: &addresses,
            bets: &bets,
            folded: &folded,
            all_in: &all_in,
            hole_cards: &hole_cards,
            community_cards: &community,
            rake_config: &rake_config(),
        };
        let result = TexasContract::settle_showdown_method(&mut host, &settle_input).unwrap();
        // 玩家 1 (AA) 应胜
        assert_eq!(result.main_pot.winners, vec![addr(1)]);
        assert_eq!(result.main_pot.pot_amount, 114); // 120 - 5% rake(6)
    }
}
