//! texas_zchain — Texas Hold'em poker contract for zchain (rBPF VM).
//!
//! 移植自 `texas_poker_move`（Sui Move），适配 zchain 合约模型：
//! - **业务逻辑层**（`card` / `hand_evaluator` / `side_pot` / `betting` / `showdown`）：
//!   纯 Rust 函数，可独立单元测试，对应合约在 VM 内执行的核心逻辑。
//! - **合约入口层**（`contract`）：rBPF entrypoint 模板，通过 syscall
//!   （`object_read` / `object_write` / `object_create` / `emit_event`）与链交互。
//!
//! # 类型约定（与 zchain `poker_l1` 保持一致）
//!
//! - `Address`：20 字节玩家地址
//! - `Hash`：32 字节 blake2b 哈希
//! - `ObjectID`：28 字节对象 ID（20B creator + 8B nonce）
//!
//! # 运行
//!
//! ```bash
//! cargo test          # 运行业务逻辑单元测试
//! cargo build --release
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod betting;
pub mod card;
pub mod contract;
pub mod hand_evaluator;
pub mod side_pot;
pub mod showdown;

/// 玩家地址（20 字节，与 zchain `poker_l1::Address` 一致）。
pub type Address = [u8; 20];

/// 32 字节哈希（blake2b_256 输出）。
pub type Hash = [u8; 32];

/// 对象 ID（28 字节 = 20B creator address + 8B creation nonce）。
pub type ObjectID = [u8; 28];

/// 玩家座位 ID。
pub type Seat = u64;

/// 通用合约错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ContractError {
    /// 输入数据过短。
    #[error("input too short")]
    InputTooShort,
    /// 对象读取失败。
    #[error("object_read failed")]
    ObjectReadFailed,
    /// 对象写入失败。
    #[error("object_write failed")]
    ObjectWriteFailed,
    /// 对象创建失败。
    #[error("object_create failed")]
    ObjectCreateFailed,
    /// 参数非法。
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
}
