module texas_poker::table_constants;

/// 所有牌桌相关常量
/// 从 table.move 中提取，供多个子模块共享

// ========== 游戏常量 ==========
const MIN_PLAYERS_TO_START: u64 = 2;
const MAX_PLAYERS: u64 = 9;
const CARDS_PER_PLAYER: u64 = 2;
const N_CARDS: u64 = 52;

// ========== Round State 常量 ==========
const ROUND_WAITING: u8 = 0;
// M-P3: 值 1 为保留值（ROUND_RESERVED），用于未来可能的中间状态扩展。
// 当前跳过 1 直接使用 2..6，保持 enum 语义稳定，避免破坏已发布数据。
#[allow(unused_const)]
const ROUND_RESERVED: u8 = 1; // Reserved for future use
const ROUND_PREFLOP: u8 = 2;
const ROUND_FLOP: u8 = 3;
const ROUND_TURN: u8 = 4;
const ROUND_RIVER: u8 = 5;
const ROUND_SHOWDOWN: u8 = 6;

// ========== Shuffle Phase 常量 ==========
const SHUFFLE_PHASE_NONE: u8 = 0;
const SHUFFLE_PHASE_WAITING: u8 = 1;
const SHUFFLE_PHASE_RECONSTRUCT: u8 = 2;
const SHUFFLE_PHASE_BEFORE_PREFLOP: u8 = 3;

// ========== Reveal Phase 常量 ==========
const REVEAL_PHASE_NONE: u8 = 0;
const REVEAL_PHASE_PREFLOP: u8 = 1;
const REVEAL_PHASE_REDEAL: u8 = 2;
const REVEAL_PHASE_FLOP: u8 = 3;
const REVEAL_PHASE_TURN: u8 = 4;
const REVEAL_PHASE_RIVER: u8 = 5;
const REVEAL_PHASE_SHOWDOWN: u8 = 6;

// ========== Reconstruct Phase 常量 ==========
const RECONSTRUCT_PHASE_NONE: u8 = 0;
const RECONSTRUCT_PHASE_COLLECTING: u8 = 1;
const RECONSTRUCT_PHASE_COMPLETE: u8 = 2;

// ========== 常量访问器 ==========

// 游戏常量
public fun min_players_to_start(): u64 { MIN_PLAYERS_TO_START }
public fun max_players(): u64 { MAX_PLAYERS }
public fun cards_per_player(): u64 { CARDS_PER_PLAYER }
public fun n_cards(): u64 { N_CARDS }

// Round State
public fun round_waiting(): u8 { ROUND_WAITING }
public fun round_preflop(): u8 { ROUND_PREFLOP }
public fun round_flop(): u8 { ROUND_FLOP }
public fun round_turn(): u8 { ROUND_TURN }
public fun round_river(): u8 { ROUND_RIVER }
public fun round_showdown(): u8 { ROUND_SHOWDOWN }

// Shuffle Phase
public fun shuffle_phase_none(): u8 { SHUFFLE_PHASE_NONE }
public fun shuffle_phase_waiting(): u8 { SHUFFLE_PHASE_WAITING }
public fun shuffle_phase_reconstruct(): u8 { SHUFFLE_PHASE_RECONSTRUCT }
public fun shuffle_phase_before_preflop(): u8 { SHUFFLE_PHASE_BEFORE_PREFLOP }

// Reveal Phase
public fun reveal_phase_none(): u8 { REVEAL_PHASE_NONE }
public fun reveal_phase_preflop(): u8 { REVEAL_PHASE_PREFLOP }
public fun reveal_phase_redeal(): u8 { REVEAL_PHASE_REDEAL }
public fun reveal_phase_flop(): u8 { REVEAL_PHASE_FLOP }
public fun reveal_phase_turn(): u8 { REVEAL_PHASE_TURN }
public fun reveal_phase_river(): u8 { REVEAL_PHASE_RIVER }
public fun reveal_phase_showdown(): u8 { REVEAL_PHASE_SHOWDOWN }

// Reconstruct Phase
public fun reconstruct_phase_none(): u8 { RECONSTRUCT_PHASE_NONE }
public fun reconstruct_phase_collecting(): u8 { RECONSTRUCT_PHASE_COLLECTING }
public fun reconstruct_phase_complete(): u8 { RECONSTRUCT_PHASE_COMPLETE }
