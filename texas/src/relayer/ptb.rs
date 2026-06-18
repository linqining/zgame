//! PTB (Programmable Transaction Block) builders for the `texas_poker_move` contract.
//!
//! Each builder constructs a [`sui_sdk_types::ProgrammableTransaction`] that calls a single
//! Move function in the `table` module of the deployed `texas_poker_move` package.
//!
//! Shared objects (`Table`, `Clock`) are added as [`sui_sdk_types::Input::Shared`] with a
//! placeholder `initial_shared_version` of `0`. The actual version is resolved by the Sui
//! RPC/SDK when the transaction is submitted (e.g. via `sui_tryGetPastObject` or during
//! transaction dry-run).

use base64::Engine;
use sui_sdk_types::Address;
use sui_sdk_types::Argument;
use sui_sdk_types::Command;
use sui_sdk_types::Identifier;
use sui_sdk_types::Input;
use sui_sdk_types::MoveCall;
use sui_sdk_types::ProgrammableTransaction;
use sui_sdk_types::SharedInput;
use sui_sdk_types::TransactionKind;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Parse a hex-encoded Sui [`Address`], returning an error on invalid input.
///
/// Callers are expected to pass valid hex addresses (e.g. `"0x6"` for the Clock,
/// or a 64-char hex string for a package/table object id).
fn parse_address(s: &str) -> Result<Address, String> {
    s.parse::<Address>()
        .map_err(|e| format!("invalid address '{}': {}", s, e))
}

/// BCS-encode a serializable value into a `Vec<u8>` suitable for [`Input::Pure`].
fn bcs_encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, String> {
    bcs::to_bytes(value).map_err(|e| format!("BCS serialization failed: {}", e))
}

/// Build a shared-object [`Input`].
///
/// `mutable` controls whether the object is taken by mutable reference (`&mut T`)
/// or immutable reference (`&T`). The `initial_shared_version` is set to `0` as a
/// placeholder; the real value is filled in by the RPC layer at submit time.
fn shared_input(object_id: &str, mutable: bool) -> Result<Input, String> {
    let id = parse_address(object_id)?;
    Ok(Input::Shared(SharedInput::new(id, 0, mutable)))
}

/// Build a `Command::MoveCall` targeting `package::table::<function>` with the
/// given input indices as arguments. The module name is always `table` and there
/// are no type arguments.
fn move_call_command(
    package_id: &str,
    function: &'static str,
    arg_indices: &[u16],
) -> Result<Command, String> {
    let package = parse_address(package_id)?;
    let arguments = arg_indices.iter().copied().map(Argument::Input).collect();
    Ok(Command::MoveCall(MoveCall {
        package,
        module: Identifier::from_static("table"),
        function: Identifier::from_static(function),
        type_arguments: Vec::new(),
        arguments,
    }))
}

// ---------------------------------------------------------------------------
// Public PTB builders
// ---------------------------------------------------------------------------

/// 构建 `table::fold` PTB。
///
/// Move signature: `fold(table: &mut Table, seat_index: u64, ctx: &mut TxContext)`
///
/// Inputs:
/// - `Input(0)`: `&mut Table` (shared, mutable)
/// - `Input(1)`: `seat_index: u64` (pure)
pub fn build_fold_ptb(
    package_id: &str,
    table_id: &str,
    seat_index: u64,
) -> Result<ProgrammableTransaction, String> {
    let inputs = vec![
        shared_input(table_id, true)?,          // Input(0): &mut Table
        Input::Pure(bcs_encode(&seat_index)?),  // Input(1): u64
    ];
    let commands = vec![move_call_command(package_id, "fold", &[0, 1])?];
    Ok(ProgrammableTransaction { inputs, commands })
}

/// 构建 `table::check` PTB。
///
/// Move signature: `check(table: &mut Table, seat_index: u64, ctx: &mut TxContext)`
///
/// Inputs:
/// - `Input(0)`: `&mut Table` (shared, mutable)
/// - `Input(1)`: `seat_index: u64` (pure)
pub fn build_check_ptb(
    package_id: &str,
    table_id: &str,
    seat_index: u64,
) -> Result<ProgrammableTransaction, String> {
    let inputs = vec![
        shared_input(table_id, true)?,          // Input(0): &mut Table
        Input::Pure(bcs_encode(&seat_index)?),  // Input(1): u64
    ];
    let commands = vec![move_call_command(package_id, "check", &[0, 1])?];
    Ok(ProgrammableTransaction { inputs, commands })
}

/// 构建 `table::call` PTB。
///
/// Move signature: `call(table: &mut Table, seat_index: u64, ctx: &mut TxContext)`
///
/// Inputs:
/// - `Input(0)`: `&mut Table` (shared, mutable)
/// - `Input(1)`: `seat_index: u64` (pure)
pub fn build_call_ptb(
    package_id: &str,
    table_id: &str,
    seat_index: u64,
) -> Result<ProgrammableTransaction, String> {
    let inputs = vec![
        shared_input(table_id, true)?,          // Input(0): &mut Table
        Input::Pure(bcs_encode(&seat_index)?),  // Input(1): u64
    ];
    let commands = vec![move_call_command(package_id, "call", &[0, 1])?];
    Ok(ProgrammableTransaction { inputs, commands })
}

/// 构建 `table::raise` PTB。
///
/// Move signature: `raise(table: &mut Table, seat_index: u64, total_bet: u64, ctx: &mut TxContext)`
///
/// Inputs:
/// - `Input(0)`: `&mut Table` (shared, mutable)
/// - `Input(1)`: `seat_index: u64` (pure)
/// - `Input(2)`: `total_bet: u64` (pure)
pub fn build_raise_ptb(
    package_id: &str,
    table_id: &str,
    seat_index: u64,
    total_bet: u64,
) -> Result<ProgrammableTransaction, String> {
    let inputs = vec![
        shared_input(table_id, true)?,          // Input(0): &mut Table
        Input::Pure(bcs_encode(&seat_index)?),  // Input(1): u64
        Input::Pure(bcs_encode(&total_bet)?),   // Input(2): u64
    ];
    let commands = vec![move_call_command(package_id, "raise", &[0, 1, 2])?];
    Ok(ProgrammableTransaction { inputs, commands })
}

/// 构建 `table::join_and_shuffle` PTB。
///
/// Move signature:
/// ```text
/// join_and_shuffle(
///     table: &mut Table,
///     seat_index: u64,
///     buy_in: u64,
///     pk: vector<u8>,
///     _pk_ownership_proof: vector<u8>,
///     output_cards: vector<u8>,
///     remask_proof_bytes: vector<u8>,
///     shuffle_proof_bytes: vector<u8>,
///     ctx: &mut TxContext,
/// )
/// ```
///
/// Inputs (8 total, `ctx` is implicit):
/// - `Input(0)`: `&mut Table` (shared, mutable)
/// - `Input(1)`: `seat_index: u64` (pure)
/// - `Input(2)`: `buy_in: u64` (pure)
/// - `Input(3)`: `pk: vector<u8>` (pure, BCS-encoded)
/// - `Input(4)`: `pk_ownership_proof: vector<u8>` (pure, BCS-encoded)
/// - `Input(5)`: `output_cards: vector<u8>` (pure, BCS-encoded)
/// - `Input(6)`: `remask_proof_bytes: vector<u8>` (pure, BCS-encoded)
/// - `Input(7)`: `shuffle_proof_bytes: vector<u8>` (pure, BCS-encoded)
pub fn build_join_and_shuffle_ptb(
    package_id: &str,
    table_id: &str,
    seat_index: u64,
    buy_in: u64,
    pk: Vec<u8>,
    pk_ownership_proof: Vec<u8>,
    output_cards: Vec<u8>,
    remask_proof_bytes: Vec<u8>,
    shuffle_proof_bytes: Vec<u8>,
) -> Result<ProgrammableTransaction, String> {
    let inputs = vec![
        shared_input(table_id, true)?,                   // Input(0): &mut Table
        Input::Pure(bcs_encode(&seat_index)?),           // Input(1): u64
        Input::Pure(bcs_encode(&buy_in)?),               // Input(2): u64
        Input::Pure(bcs_encode(&pk)?),                   // Input(3): vector<u8>
        Input::Pure(bcs_encode(&pk_ownership_proof)?),   // Input(4): vector<u8>
        Input::Pure(bcs_encode(&output_cards)?),         // Input(5): vector<u8>
        Input::Pure(bcs_encode(&remask_proof_bytes)?),   // Input(6): vector<u8>
        Input::Pure(bcs_encode(&shuffle_proof_bytes)?),  // Input(7): vector<u8>
    ];
    let commands = vec![move_call_command(
        package_id,
        "join_and_shuffle",
        &[0, 1, 2, 3, 4, 5, 6, 7],
    )?];
    Ok(ProgrammableTransaction { inputs, commands })
}

/// 构建 `table::tick` PTB。
///
/// Move signature: `tick(table: &mut Table, clock: &Clock)`
///
/// Inputs:
/// - `Input(0)`: `&mut Table` (shared, mutable)
/// - `Input(1)`: `&Clock` (shared, immutable — `0x6` on all Sui networks)
pub fn build_tick_ptb(
    package_id: &str,
    table_id: &str,
    clock_object_id: &str,
) -> Result<ProgrammableTransaction, String> {
    let inputs = vec![
        shared_input(table_id, true)?,          // Input(0): &mut Table
        shared_input(clock_object_id, false)?,  // Input(1): &Clock (immutable)
    ];
    let commands = vec![move_call_command(package_id, "tick", &[0, 1])?];
    Ok(ProgrammableTransaction { inputs, commands })
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

/// 将 [`ProgrammableTransaction`] 包装为 [`TransactionKind::ProgrammableTransaction`],
/// BCS 序列化后再 base64 编码，返回可供 Sui RPC (`sui_executeTransactionBlock` 等)
/// 使用的 `tx_kind` 字符串。
pub fn serialize_tx_kind(pt: ProgrammableTransaction) -> Result<String, String> {
    let tx_kind = TransactionKind::ProgrammableTransaction(pt);
    let bytes = bcs::to_bytes(&tx_kind)
        .map_err(|e| format!("TransactionKind BCS serialization failed: {}", e))?;
    let engine = base64::engine::general_purpose::STANDARD;
    Ok(engine.encode(&bytes))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// testnet package id for `texas_poker_move`
    const PACKAGE_ID: &str = "0x1c7f761168f1689bee0ed05aae2abc2d5b57e041c24acf7def8eba34a9dd3a98";
    /// a 32-byte hex object id used as a stand-in Table id
    const TABLE_ID: &str = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    /// Sui system Clock object id
    const CLOCK_ID: &str = "0x6";

    #[test]
    fn test_build_fold_ptb() {
        let ptb = build_fold_ptb(PACKAGE_ID, TABLE_ID, 1).expect("build_fold_ptb should succeed");
        assert_eq!(ptb.inputs.len(), 2, "fold should have 2 inputs (table + seat_index)");
        assert_eq!(ptb.commands.len(), 1, "fold should have 1 command");
        // Verify the command is a MoveCall to table::fold with 2 arguments
        match &ptb.commands[0] {
            Command::MoveCall(mc) => {
                assert_eq!(mc.module.as_str(), "table");
                assert_eq!(mc.function.as_str(), "fold");
                assert_eq!(mc.arguments.len(), 2);
                assert_eq!(mc.arguments[0], Argument::Input(0));
                assert_eq!(mc.arguments[1], Argument::Input(1));
            }
            other => panic!("expected MoveCall, got {:?}", other),
        }
    }

    #[test]
    fn test_build_check_ptb() {
        let ptb = build_check_ptb(PACKAGE_ID, TABLE_ID, 2).expect("build_check_ptb should succeed");
        assert_eq!(ptb.inputs.len(), 2, "check should have 2 inputs (table + seat_index)");
        assert_eq!(ptb.commands.len(), 1, "check should have 1 command");
        match &ptb.commands[0] {
            Command::MoveCall(mc) => {
                assert_eq!(mc.function.as_str(), "check");
                assert_eq!(mc.arguments.len(), 2);
            }
            other => panic!("expected MoveCall, got {:?}", other),
        }
    }

    #[test]
    fn test_build_call_ptb() {
        let ptb = build_call_ptb(PACKAGE_ID, TABLE_ID, 3).expect("build_call_ptb should succeed");
        assert_eq!(ptb.inputs.len(), 2, "call should have 2 inputs (table + seat_index)");
        assert_eq!(ptb.commands.len(), 1, "call should have 1 command");
        match &ptb.commands[0] {
            Command::MoveCall(mc) => {
                assert_eq!(mc.function.as_str(), "call");
                assert_eq!(mc.arguments.len(), 2);
            }
            other => panic!("expected MoveCall, got {:?}", other),
        }
    }

    #[test]
    fn test_build_raise_ptb() {
        let ptb = build_raise_ptb(PACKAGE_ID, TABLE_ID, 1, 500).expect("build_raise_ptb should succeed");
        assert_eq!(ptb.inputs.len(), 3, "raise should have 3 inputs (table + seat_index + total_bet)");
        assert_eq!(ptb.commands.len(), 1, "raise should have 1 command");
        match &ptb.commands[0] {
            Command::MoveCall(mc) => {
                assert_eq!(mc.function.as_str(), "raise");
                assert_eq!(mc.arguments.len(), 3);
                assert_eq!(mc.arguments[2], Argument::Input(2));
            }
            other => panic!("expected MoveCall, got {:?}", other),
        }
    }

    #[test]
    fn test_build_join_and_shuffle_ptb() {
        let ptb = build_join_and_shuffle_ptb(
            PACKAGE_ID,
            TABLE_ID,
            0,
            1_000_000,
            vec![0u8; 32],
            vec![0u8; 64],
            vec![1u8, 2, 3, 4],
            vec![0u8; 128],
            vec![0u8; 256],
        ).expect("build_join_and_shuffle_ptb should succeed");
        // 1 table + 1 seat_index + 1 buy_in + 5 vector<u8> = 8 inputs
        assert_eq!(ptb.inputs.len(), 8, "join_and_shuffle should have 8 inputs");
        assert_eq!(ptb.commands.len(), 1, "join_and_shuffle should have 1 command");
        match &ptb.commands[0] {
            Command::MoveCall(mc) => {
                assert_eq!(mc.function.as_str(), "join_and_shuffle");
                assert_eq!(mc.arguments.len(), 8);
                // Verify all 8 arguments reference the corresponding inputs
                for i in 0..8u16 {
                    assert_eq!(mc.arguments[i as usize], Argument::Input(i));
                }
            }
            other => panic!("expected MoveCall, got {:?}", other),
        }
    }

    #[test]
    fn test_build_tick_ptb() {
        let ptb = build_tick_ptb(PACKAGE_ID, TABLE_ID, CLOCK_ID).expect("build_tick_ptb should succeed");
        assert_eq!(ptb.inputs.len(), 2, "tick should have 2 inputs (table + clock)");
        assert_eq!(ptb.commands.len(), 1, "tick should have 1 command");
        match &ptb.commands[0] {
            Command::MoveCall(mc) => {
                assert_eq!(mc.function.as_str(), "tick");
                assert_eq!(mc.arguments.len(), 2);
            }
            other => panic!("expected MoveCall, got {:?}", other),
        }
        // Verify the clock input is shared & immutable
        match &ptb.inputs[1] {
            Input::Shared(s) => {
                assert_eq!(s.object_id(), parse_address(CLOCK_ID).expect("parse_address should succeed"));
                assert!(!s.mutability().is_mutable(), "Clock should be immutable");
            }
            other => panic!("expected Shared input for Clock, got {:?}", other),
        }
    }

    #[test]
    fn test_serialize_tx_kind_non_empty() {
        let ptb = build_fold_ptb(PACKAGE_ID, TABLE_ID, 1).expect("build_fold_ptb should succeed");
        let result = serialize_tx_kind(ptb).expect("serialize_tx_kind should succeed");
        assert!(!result.is_empty(), "serialized tx kind should be non-empty");
        // Verify it is valid base64 by decoding it
        let engine = base64::engine::general_purpose::STANDARD;
        let decoded = engine
            .decode(&result)
            .expect("serialized tx kind should be valid base64");
        assert!(!decoded.is_empty(), "decoded tx kind bytes should be non-empty");
    }

    #[test]
    fn test_serialize_tx_kind_all_builders() {
        // Verify serialization works for every builder
        let builders: Vec<ProgrammableTransaction> = vec![
            build_fold_ptb(PACKAGE_ID, TABLE_ID, 1).expect("build_fold_ptb"),
            build_check_ptb(PACKAGE_ID, TABLE_ID, 1).expect("build_check_ptb"),
            build_call_ptb(PACKAGE_ID, TABLE_ID, 1).expect("build_call_ptb"),
            build_raise_ptb(PACKAGE_ID, TABLE_ID, 1, 100).expect("build_raise_ptb"),
            build_join_and_shuffle_ptb(
                PACKAGE_ID,
                TABLE_ID,
                1,
                1000,
                vec![1, 2, 3],
                vec![4, 5, 6],
                vec![7, 8, 9],
                vec![10, 11, 12],
                vec![13, 14, 15],
            ).expect("build_join_and_shuffle_ptb"),
            build_tick_ptb(PACKAGE_ID, TABLE_ID, CLOCK_ID).expect("build_tick_ptb"),
        ];
        for (i, ptb) in builders.into_iter().enumerate() {
            let result = serialize_tx_kind(ptb).expect("serialize_tx_kind should succeed");
            assert!(
                !result.is_empty(),
                "serialized tx kind #{} should be non-empty",
                i
            );
        }
    }
}
