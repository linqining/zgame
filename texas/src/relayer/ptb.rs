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
use sui_sdk_types::Digest;
use sui_sdk_types::Identifier;
use sui_sdk_types::Input;
use sui_sdk_types::MoveCall;
use sui_sdk_types::Mutability;
use sui_sdk_types::ObjectReference;
use sui_sdk_types::ProgrammableTransaction;
use sui_sdk_types::SharedInput;
use sui_sdk_types::SplitCoins;
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

/// Build an owned/immutable-object [`Input`] with placeholder version (0) and
/// zero digest. The real version and digest are resolved by
/// [`resolve_owned_object_versions`] before the PTB is serialized.
fn owned_input(object_id: &str) -> Result<Input, String> {
    let id = parse_address(object_id)?;
    Ok(Input::ImmutableOrOwned(ObjectReference::new(
        id,
        0,
        Digest::ZERO,
    )))
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

/// 构建 `table::join_and_shuffle_verified` PTB。
///
/// Move signature:
/// ```text
/// join_and_shuffle_verified(
///     table: &mut Table,
///     seat_index: u64,
///     buy_in_coin: Coin<SUI>,            // 玩家存入的 SUI 代币
///     pk: vector<u8>,
///     pk_ownership_proof: vector<u8>,
///     mask_cards: vector<u8>,
///     output_cards: vector<u8>,
///     remask_proof_bytes: vector<u8>,
///     shuffle_proof_bytes: vector<u8>,
///     ctx: &mut TxContext,
/// )
/// ```
///
/// PTB 先将 Coin 拆分为精确金额，再传给合约，剩余部分自动返还给用户。
///
/// Inputs (10 total, `ctx` is implicit):
/// - `Input(0)`: `&mut Table` (shared, mutable)
/// - `Input(1)`: `seat_index: u64` (pure)
/// - `Input(2)`: `buy_in_coin: Coin<SUI>` (owned object — version/digest resolved later)
/// - `Input(3)`: `split_amount: u64` (pure, BCS-encoded) — 需要拆分出的 MIST 数量
/// - `Input(4)`: `pk: vector<u8>` (pure, BCS-encoded)
/// - `Input(5)`: `pk_ownership_proof: vector<u8>` (pure, BCS-encoded)
/// - `Input(6)`: `mask_cards: vector<u8>` (pure, BCS-encoded)
/// - `Input(7)`: `output_cards: vector<u8>` (pure, BCS-encoded)
/// - `Input(8)`: `remask_proof_bytes: vector<u8>` (pure, BCS-encoded)
/// - `Input(9)`: `shuffle_proof_bytes: vector<u8>` (pure, BCS-encoded)
///
/// Commands:
/// - `Command(0)`: `SplitCoins(Input(2), [Input(3)])` → `Result(0)`: 拆分后的精确金额 Coin
/// - `Command(1)`: `MoveCall(table::join_and_shuffle_verified(Input(0), Input(1), NestedResult(0,0), Input(4..9)))`
///   原始 Coin (Input(2)) 剩余余额自动返还给发送者
pub fn build_join_and_shuffle_ptb(
    package_id: &str,
    table_id: &str,
    seat_index: u64,
    coin_object_id: &str,
    amount_mist: u64,
    pk: Vec<u8>,
    pk_ownership_proof: Vec<u8>,
    mask_cards: Vec<u8>,
    output_cards: Vec<u8>,
    remask_proof_bytes: Vec<u8>,
    shuffle_proof_bytes: Vec<u8>,
) -> Result<ProgrammableTransaction, String> {
    let inputs = vec![
        shared_input(table_id, true)?,                   // Input(0): &mut Table
        Input::Pure(bcs_encode(&seat_index)?),           // Input(1): u64
        owned_input(coin_object_id)?,                    // Input(2): Coin<SUI> (owned)
        Input::Pure(bcs_encode(&amount_mist)?),          // Input(3): u64 (split amount in MIST)
        Input::Pure(bcs_encode(&pk)?),                   // Input(4): vector<u8>
        Input::Pure(bcs_encode(&pk_ownership_proof)?),   // Input(5): vector<u8>
        Input::Pure(bcs_encode(&mask_cards)?),           // Input(6): vector<u8>
        Input::Pure(bcs_encode(&output_cards)?),         // Input(7): vector<u8>
        Input::Pure(bcs_encode(&remask_proof_bytes)?),   // Input(8): vector<u8>
        Input::Pure(bcs_encode(&shuffle_proof_bytes)?),  // Input(9): vector<u8>
    ];
    // Command(0): SplitCoins — 从原始 Coin 中拆分出精确金额
    let split = Command::SplitCoins(SplitCoins {
        coin: Argument::Input(2),
        amounts: vec![Argument::Input(3)],
    });
    // Command(1): MoveCall — 使用拆分后的 Coin (NestedResult(0, 0)) 传入合约
    let mut mc = match move_call_command(
        package_id,
        "join_and_shuffle_verified",
        &[0, 1, 2, 4, 5, 6, 7, 8, 9], // placeholder indices; arg[2] will be replaced
    )? {
        Command::MoveCall(mc) => mc,
        other => return Err(format!("expected MoveCall, got {:?}", other)),
    };
    mc.arguments[2] = Argument::NestedResult(0, 0); // buy_in_coin = split result
    let commands = vec![split, Command::MoveCall(mc)];
    Ok(ProgrammableTransaction { inputs, commands })
}

/// 构建 `table::submit_shuffle_verified` PTB。
///
/// Move signature:
/// `submit_shuffle_verified(table: &mut Table, output_cards: vector<u8>, shuffle_proof_bytes: vector<u8>, ctx: &mut TxContext)`
///
/// Inputs (3 total, `ctx` is implicit):
/// - `Input(0)`: `&mut Table` (shared, mutable)
/// - `Input(1)`: `output_cards: vector<u8>` (pure, BCS-encoded)
/// - `Input(2)`: `shuffle_proof_bytes: vector<u8>` (pure, BCS-encoded)
pub fn build_submit_shuffle_ptb(
    package_id: &str,
    table_id: &str,
    output_cards: Vec<u8>,
    shuffle_proof_bytes: Vec<u8>,
) -> Result<ProgrammableTransaction, String> {
    let inputs = vec![
        shared_input(table_id, true)?,                  // Input(0): &mut Table
        Input::Pure(bcs_encode(&output_cards)?),        // Input(1): vector<u8>
        Input::Pure(bcs_encode(&shuffle_proof_bytes)?), // Input(2): vector<u8>
    ];
    let commands = vec![move_call_command(package_id, "submit_shuffle_verified", &[0, 1, 2])?];
    Ok(ProgrammableTransaction { inputs, commands })
}

/// 构建 `table::submit_player_reveal_tokens_verified` PTB。
///
/// Move signature:
/// ```text
/// submit_player_reveal_tokens_verified(
///     table: &mut Table,
///     assignment_indices: vector<u64>,
///     reveal_tokens: vector<vector<u8>>,
///     proof_bytes_list: vector<vector<u8>>,
///     ctx: &mut TxContext,
/// )
/// ```
///
/// Inputs (4 total, `ctx` is implicit):
/// - `Input(0)`: `&mut Table` (shared, mutable)
/// - `Input(1)`: `assignment_indices: vector<u64>` (pure, BCS-encoded)
/// - `Input(2)`: `reveal_tokens: vector<vector<u8>>` (pure, BCS-encoded)
/// - `Input(3)`: `proof_bytes_list: vector<vector<u8>>` (pure, BCS-encoded)
pub fn build_submit_reveal_tokens_ptb(
    package_id: &str,
    table_id: &str,
    assignment_indices: Vec<u64>,
    reveal_tokens: Vec<Vec<u8>>,
    proof_bytes_list: Vec<Vec<u8>>,
) -> Result<ProgrammableTransaction, String> {
    let inputs = vec![
        shared_input(table_id, true)?,                      // Input(0): &mut Table
        Input::Pure(bcs_encode(&assignment_indices)?),      // Input(1): vector<u64>
        Input::Pure(bcs_encode(&reveal_tokens)?),           // Input(2): vector<vector<u8>>
        Input::Pure(bcs_encode(&proof_bytes_list)?),        // Input(3): vector<vector<u8>>
    ];
    let commands = vec![move_call_command(
        package_id,
        "submit_player_reveal_tokens_verified",
        &[0, 1, 2, 3],
    )?];
    Ok(ProgrammableTransaction { inputs, commands })
}

/// 构建 `table::submit_reconstruct_deck_verified` PTB。
///
/// Move signature:
/// ```text
/// submit_reconstruct_deck_verified(
///     table: &mut Table,
///     output_cards: vector<u8>,
///     swap_cards: vector<u8>,
///     user_readable_cards: vector<u8>,
///     proof_bytes: vector<u8>,
///     ctx: &mut TxContext,
/// )
/// ```
///
/// Inputs (5 total, `ctx` is implicit):
/// - `Input(0)`: `&mut Table` (shared, mutable)
/// - `Input(1)`: `output_cards: vector<u8>` (pure, BCS-encoded)
/// - `Input(2)`: `swap_cards: vector<u8>` (pure, BCS-encoded)
/// - `Input(3)`: `user_readable_cards: vector<u8>` (pure, BCS-encoded)
/// - `Input(4)`: `proof_bytes: vector<u8>` (pure, BCS-encoded)
pub fn build_submit_reconstruct_deck_ptb(
    package_id: &str,
    table_id: &str,
    output_cards: Vec<u8>,
    swap_cards: Vec<u8>,
    user_readable_cards: Vec<u8>,
    proof_bytes: Vec<u8>,
) -> Result<ProgrammableTransaction, String> {
    let inputs = vec![
        shared_input(table_id, true)?,                      // Input(0): &mut Table
        Input::Pure(bcs_encode(&output_cards)?),            // Input(1): vector<u8>
        Input::Pure(bcs_encode(&swap_cards)?),              // Input(2): vector<u8>
        Input::Pure(bcs_encode(&user_readable_cards)?),     // Input(3): vector<u8>
        Input::Pure(bcs_encode(&proof_bytes)?),             // Input(4): vector<u8>
    ];
    let commands = vec![move_call_command(
        package_id,
        "submit_reconstruct_deck_verified",
        &[0, 1, 2, 3, 4],
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

/// 构建 `table::leave_with_proof_verified` PTB。
///
/// Move signature:
/// ```text
/// leave_with_proof_verified(
///     table: &mut Table,
///     seat_index: u64,
///     output_cards: vector<u8>,           // leave 后的牌组 (serialized ciphertexts, flat bytes)
///     _leave_proof_bytes: vector<u8>,      // LeaveProof (serialized, 链上不验证)
///     ctx: &mut TxContext,
/// )
/// ```
///
/// Inputs (4 total, `ctx` is implicit):
/// - `Input(0)`: `&mut Table` (shared, mutable)
/// - `Input(1)`: `seat_index: u64` (pure, BCS-encoded)
/// - `Input(2)`: `output_cards: vector<u8>` (pure, BCS-encoded)
/// - `Input(3)`: `leave_proof_bytes: vector<u8>` (pure, BCS-encoded)
pub fn build_leave_with_proof_ptb(
    package_id: &str,
    table_id: &str,
    seat_index: u64,
    output_cards: Vec<u8>,
    leave_proof_bytes: Vec<u8>,
) -> Result<ProgrammableTransaction, String> {
    let inputs = vec![
        shared_input(table_id, true)?,                   // Input(0): &mut Table
        Input::Pure(bcs_encode(&seat_index)?),           // Input(1): u64
        Input::Pure(bcs_encode(&output_cards)?),         // Input(2): vector<u8>
        Input::Pure(bcs_encode(&leave_proof_bytes)?),    // Input(3): vector<u8>
    ];
    let commands = vec![move_call_command(
        package_id,
        "leave_with_proof_verified",
        &[0, 1, 2, 3],
    )?];
    Ok(ProgrammableTransaction { inputs, commands })
}

/// 构建 `table::leave_table` PTB（简单离开，无需密码学证明）。
///
/// Move signature:
/// ```text
/// leave_table(
///     table: &mut Table,
///     seat_index: u64,
///     ctx: &mut TxContext,
/// )
/// ```
///
/// Inputs (2 total, `ctx` is implicit):
/// - `Input(0)`: `&mut Table` (shared, mutable)
/// - `Input(1)`: `seat_index: u64` (pure, BCS-encoded)
pub fn build_leave_table_ptb(
    package_id: &str,
    table_id: &str,
    seat_index: u64,
) -> Result<ProgrammableTransaction, String> {
    let inputs = vec![
        shared_input(table_id, true)?,          // Input(0): &mut Table
        Input::Pure(bcs_encode(&seat_index)?),  // Input(1): u64
    ];
    let commands = vec![move_call_command(package_id, "leave_table", &[0, 1])?];
    Ok(ProgrammableTransaction { inputs, commands })
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

/// Resolve the `initial_shared_version` for all shared objects in a [`ProgrammableTransaction`].
///
/// Shinami Gas Station requires the correct `initial_shared_version` to be embedded in the
/// TransactionKind — unlike Sui RPC nodes which resolve version `0` automatically. This
/// function queries the Sui RPC for each shared object and replaces the placeholder version
/// (`0`) with the real `initial_shared_version` from the object's owner metadata.
///
/// Only objects with `version == 0` are queried; objects with a non-zero version are left
/// untouched (e.g. the Clock at `0x6` which is shared at version `1`).
pub async fn resolve_shared_object_versions(
    http: &reqwest::Client,
    rpc_url: &str,
    mut pt: ProgrammableTransaction,
) -> Result<ProgrammableTransaction, String> {
    for input in &mut pt.inputs {
        match input {
            Input::Shared(shared) => {
                if shared.version() == 0 {
                    let id = shared.object_id();
                    let mutable = matches!(shared.mutability(), Mutability::Mutable);
                    let version = fetch_initial_shared_version(http, rpc_url, &id).await?;
                    *shared = SharedInput::new(id, version, mutable);
                }
            }
            Input::ImmutableOrOwned(obj_ref) => {
                if obj_ref.version() == 0 {
                    let id = *obj_ref.object_id();
                    let (version, digest) = fetch_owned_object_version_and_digest(http, rpc_url, &id).await?;
                    *obj_ref = ObjectReference::new(id, version, digest);
                }
            }
            _ => {}
        }
    }
    Ok(pt)
}

/// Query `sui_getObject` and extract `initial_shared_version` from the shared object's owner.
///
/// Some public fullnodes return incomplete object data (missing the `owner` field) for
/// recently-created or high-version objects. In that case, we fall back to using the
/// object's current `version` as the `initial_shared_version`. This is correct for
/// objects that were shared at creation time and haven't been modified since (the common
/// case for game table objects). A warning is logged when the fallback is used.
async fn fetch_initial_shared_version(
    http: &reqwest::Client,
    rpc_url: &str,
    object_id: &Address,
) -> Result<u64, String> {
    let id_str = object_id.to_string();
    let resp = crate::sponsor::sui_jsonrpc(
        http,
        rpc_url,
        "sui_getObject",
        vec![
            serde_json::Value::String(id_str.clone()),
            serde_json::json!({
                "showType": true,
                "showOwner": true,
                "showContent": false,
                "showBcs": false,
                "showDisplay": false,
                "showPreviousTransaction": false,
                "showStorageRebate": false
            }),
        ],
    )
    .await?;

    let data = resp
        .get("data")
        .ok_or_else(|| format!("Missing 'data' in sui_getObject response for {}", object_id))?;

    // Primary path: extract initial_shared_version from owner.Shared
    if let Some(owner) = data.get("owner") {
        if let Some(version) = owner
            .get("Shared")
            .and_then(|s| s.get("initial_shared_version"))
        {
            return version
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .or_else(|| version.as_u64())
                .ok_or_else(|| format!("Invalid initial_shared_version: {}", version));
        }
        tracing::warn!(
            "[resolve_shared_object_versions] sui_getObject for {} owner is not Shared: {:?}",
            id_str,
            owner
        );
    } else {
        tracing::warn!(
            "[resolve_shared_object_versions] sui_getObject for {} missing owner field, data keys: {:?}",
            id_str,
            data.as_object().map(|o| o.keys().collect::<Vec<_>>())
        );
    }

    // Fallback: some fullnodes don't return the `owner` field. Use the object's current
    // version as the initial_shared_version. This is correct for objects shared at
    // creation time that haven't been modified since.
    let version = data
        .get("version")
        .and_then(|v| {
            v.as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .or_else(|| v.as_u64())
        })
        .ok_or_else(|| format!("Missing 'version' in sui_getObject response for {}", object_id))?;

    tracing::warn!(
        "[resolve_shared_object_versions] sui_getObject for {} did not return owner.Shared; \
         falling back to current version {} as initial_shared_version",
        id_str,
        version
    );
    Ok(version)
}

/// Query `sui_getObject` and extract the `version` and `digest` for an owned or
/// immutable object (e.g. a `Coin<SUI>` used as buy-in). These are required by
/// `Input::ImmutableOrOwned(ObjectReference)`.
async fn fetch_owned_object_version_and_digest(
    http: &reqwest::Client,
    rpc_url: &str,
    object_id: &Address,
) -> Result<(u64, Digest), String> {
    let id_str = object_id.to_string();
    let resp = crate::sponsor::sui_jsonrpc(
        http,
        rpc_url,
        "sui_getObject",
        vec![
            serde_json::Value::String(id_str.clone()),
            serde_json::json!({
                "showType": false,
                "showOwner": false,
                "showContent": false,
                "showBcs": false,
                "showDisplay": false,
                "showPreviousTransaction": false,
                "showStorageRebate": false
            }),
        ],
    )
    .await?;

    let data = resp
        .get("data")
        .ok_or_else(|| format!("Missing 'data' in sui_getObject response for {}", object_id))?;

    let version = data
        .get("version")
        .and_then(|v| {
            v.as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .or_else(|| v.as_u64())
        })
        .ok_or_else(|| format!("Missing 'version' in sui_getObject response for {}", object_id))?;

    let digest_str = data
        .get("digest")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("Missing 'digest' in sui_getObject response for {}", object_id))?;

    let digest = Digest::from_base58(digest_str)
        .map_err(|e| format!("Failed to parse digest '{}' as base58: {:?}", digest_str, e))?;

    tracing::debug!(
        "[fetch_owned_object_version_and_digest] object_id={}, version={}, digest={}",
        id_str, version, digest_str
    );
    Ok((version, digest))
}

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

    /// testnet package id for `texas_poker_move` (upgraded/latest)
    const PACKAGE_ID: &str = "0xa03bc5d528ddc38fb3a777a4d86b2e91483b92ee3c9e7f4dcc1fe6e3e37b70b1";
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
            "0x0000000000000000000000000000000000000000000000000000000000000001",
            100_000_000u64, // 0.1 SUI in MIST
            vec![0u8; 32],
            vec![0u8; 64],
            vec![9u8, 10, 11, 12],
            vec![1u8, 2, 3, 4],
            vec![0u8; 128],
            vec![0u8; 256],
        ).expect("build_join_and_shuffle_ptb should succeed");
        // 1 table + 1 seat_index + 1 coin + 1 split_amount + 6 vector<u8> = 10 inputs
        assert_eq!(ptb.inputs.len(), 10, "join_and_shuffle should have 10 inputs");
        assert_eq!(ptb.commands.len(), 2, "join_and_shuffle should have 2 commands (SplitCoins + MoveCall)");
        // Command(0): SplitCoins
        match &ptb.commands[0] {
            Command::SplitCoins(sc) => {
                assert_eq!(sc.coin, Argument::Input(2));
                assert_eq!(sc.amounts.len(), 1);
                assert_eq!(sc.amounts[0], Argument::Input(3));
            }
            other => panic!("expected SplitCoins, got {:?}", other),
        }
        // Command(1): MoveCall with NestedResult(0, 0) for buy_in_coin
        match &ptb.commands[1] {
            Command::MoveCall(mc) => {
                assert_eq!(mc.function.as_str(), "join_and_shuffle_verified");
                assert_eq!(mc.arguments.len(), 9);
                assert_eq!(mc.arguments[0], Argument::Input(0)); // table
                assert_eq!(mc.arguments[1], Argument::Input(1)); // seat_index
                assert_eq!(mc.arguments[2], Argument::NestedResult(0, 0)); // split coin
                assert_eq!(mc.arguments[3], Argument::Input(4)); // pk
                assert_eq!(mc.arguments[4], Argument::Input(5)); // pk_proof
                assert_eq!(mc.arguments[5], Argument::Input(6)); // mask_cards
                assert_eq!(mc.arguments[6], Argument::Input(7)); // output_cards
                assert_eq!(mc.arguments[7], Argument::Input(8)); // remask_proof
                assert_eq!(mc.arguments[8], Argument::Input(9)); // shuffle_proof
            }
            other => panic!("expected MoveCall, got {:?}", other),
        }
    }

    #[test]
    fn test_build_submit_shuffle_ptb() {
        let ptb = build_submit_shuffle_ptb(
            PACKAGE_ID,
            TABLE_ID,
            vec![1u8, 2, 3, 4],
            vec![0u8; 64],
        )
        .expect("build_submit_shuffle_ptb should succeed");
        // 1 table + 2 vector<u8> = 3 inputs
        assert_eq!(ptb.inputs.len(), 3, "submit_shuffle should have 3 inputs");
        assert_eq!(ptb.commands.len(), 1, "submit_shuffle should have 1 command");
        match &ptb.commands[0] {
            Command::MoveCall(mc) => {
                assert_eq!(mc.module.as_str(), "table");
                assert_eq!(mc.function.as_str(), "submit_shuffle_verified");
                assert_eq!(mc.arguments.len(), 3);
                // Verify all 3 arguments reference the corresponding inputs
                for i in 0..3u16 {
                    assert_eq!(mc.arguments[i as usize], Argument::Input(i));
                }
            }
            other => panic!("expected MoveCall, got {:?}", other),
        }
        // Verify Input(0) is a shared mutable Table
        match &ptb.inputs[0] {
            Input::Shared(s) => {
                assert_eq!(
                    s.object_id(),
                    parse_address(TABLE_ID).expect("parse_address should succeed")
                );
                assert!(s.mutability().is_mutable(), "Table should be mutable");
            }
            other => panic!("expected Shared input for Table, got {:?}", other),
        }
    }

    #[test]
    fn test_build_submit_reveal_tokens_ptb() {
        let ptb = build_submit_reveal_tokens_ptb(
            PACKAGE_ID,
            TABLE_ID,
            vec![0u64, 1, 2],
            vec![vec![1u8, 2, 3], vec![4, 5, 6]],
            vec![vec![0u8; 32], vec![0u8; 32]],
        )
        .expect("build_submit_reveal_tokens_ptb should succeed");
        // 1 table + 3 vectors = 4 inputs
        assert_eq!(
            ptb.inputs.len(),
            4,
            "submit_player_reveal_tokens should have 4 inputs"
        );
        assert_eq!(
            ptb.commands.len(),
            1,
            "submit_player_reveal_tokens should have 1 command"
        );
        match &ptb.commands[0] {
            Command::MoveCall(mc) => {
                assert_eq!(mc.module.as_str(), "table");
                assert_eq!(mc.function.as_str(), "submit_player_reveal_tokens_verified");
                assert_eq!(mc.arguments.len(), 4);
                // Verify all 4 arguments reference the corresponding inputs
                for i in 0..4u16 {
                    assert_eq!(mc.arguments[i as usize], Argument::Input(i));
                }
            }
            other => panic!("expected MoveCall, got {:?}", other),
        }
        // Verify Input(0) is a shared mutable Table
        match &ptb.inputs[0] {
            Input::Shared(s) => {
                assert_eq!(
                    s.object_id(),
                    parse_address(TABLE_ID).expect("parse_address should succeed")
                );
                assert!(s.mutability().is_mutable(), "Table should be mutable");
            }
            other => panic!("expected Shared input for Table, got {:?}", other),
        }
    }

    #[test]
    fn test_build_submit_reconstruct_deck_ptb() {
        let ptb = build_submit_reconstruct_deck_ptb(
            PACKAGE_ID,
            TABLE_ID,
            vec![1u8, 2, 3, 4],
            vec![5u8, 6, 7, 8],
            vec![9u8, 10, 11, 12],
            vec![0u8; 128],
        )
        .expect("build_submit_reconstruct_deck_ptb should succeed");
        // 1 table + 4 vector<u8> = 5 inputs
        assert_eq!(
            ptb.inputs.len(),
            5,
            "submit_reconstruct_deck should have 5 inputs"
        );
        assert_eq!(
            ptb.commands.len(),
            1,
            "submit_reconstruct_deck should have 1 command"
        );
        match &ptb.commands[0] {
            Command::MoveCall(mc) => {
                assert_eq!(mc.module.as_str(), "table");
                assert_eq!(mc.function.as_str(), "submit_reconstruct_deck_verified");
                assert_eq!(mc.arguments.len(), 5);
                // Verify all 5 arguments reference the corresponding inputs
                for i in 0..5u16 {
                    assert_eq!(mc.arguments[i as usize], Argument::Input(i));
                }
            }
            other => panic!("expected MoveCall, got {:?}", other),
        }
        // Verify Input(0) is a shared mutable Table
        match &ptb.inputs[0] {
            Input::Shared(s) => {
                assert_eq!(
                    s.object_id(),
                    parse_address(TABLE_ID).expect("parse_address should succeed")
                );
                assert!(s.mutability().is_mutable(), "Table should be mutable");
            }
            other => panic!("expected Shared input for Table, got {:?}", other),
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
    fn test_build_leave_with_proof_ptb() {
        let output_cards = vec![0u8; 52 * 96]; // 52 cards * 96 bytes per ciphertext
        let leave_proof = vec![0u8; 80]; // dummy leave proof bytes
        let ptb = build_leave_with_proof_ptb(
            PACKAGE_ID,
            TABLE_ID,
            2,
            output_cards,
            leave_proof,
        )
        .expect("build_leave_with_proof_ptb should succeed");
        assert_eq!(ptb.inputs.len(), 4, "leave_with_proof should have 4 inputs");
        assert_eq!(ptb.commands.len(), 1, "leave_with_proof should have 1 command");
        match &ptb.commands[0] {
            Command::MoveCall(mc) => {
                assert_eq!(mc.function.as_str(), "leave_with_proof_verified");
                assert_eq!(mc.arguments.len(), 4);
            }
            other => panic!("expected MoveCall, got {:?}", other),
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
                "0x0000000000000000000000000000000000000000000000000000000000000002",
                100_000_000u64, // 0.1 SUI in MIST
                vec![1, 2, 3],
                vec![4, 5, 6],
                vec![16, 17, 18],
                vec![7, 8, 9],
                vec![10, 11, 12],
                vec![13, 14, 15],
            ).expect("build_join_and_shuffle_ptb"),
            build_tick_ptb(PACKAGE_ID, TABLE_ID, CLOCK_ID).expect("build_tick_ptb"),
            build_submit_shuffle_ptb(PACKAGE_ID, TABLE_ID, vec![1, 2, 3], vec![4, 5, 6])
                .expect("build_submit_shuffle_ptb"),
            build_submit_reveal_tokens_ptb(
                PACKAGE_ID,
                TABLE_ID,
                vec![0u64, 1],
                vec![vec![1u8, 2], vec![3, 4]],
                vec![vec![5u8, 6], vec![7, 8]],
            )
            .expect("build_submit_reveal_tokens_ptb"),
            build_submit_reconstruct_deck_ptb(
                PACKAGE_ID,
                TABLE_ID,
                vec![1u8, 2, 3],
                vec![4u8, 5, 6],
                vec![7u8, 8, 9],
                vec![10u8, 11, 12],
            )
            .expect("build_submit_reconstruct_deck_ptb"),
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
