use crate::sui_events::{TableSummaryV2, TableSummaryV2Chain};
use base64::Engine;

/// 通过 `suix_getBalance` 查询指定地址的 SUI 余额（MIST）。
///
/// # 参数
/// * `rpc_url` - Sui 全节点的 JSON-RPC URL
/// * `address` - 钱包地址（hex，如 "0x..."）
///
/// # 返回
/// 成功返回 SUI 余额（MIST，1 SUI = 10^9 MIST）
pub async fn fetch_sui_balance(rpc_url: &str, address: &str) -> Result<u64, String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "suix_getBalance",
        "params": [address, "0x2::sui::SUI"]
    });

    let client = reqwest::Client::new();
    let resp: serde_json::Value = client
        .post(rpc_url)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {}", e))?
        .json()
        .await
        .map_err(|e| format!("JSON parse failed: {}", e))?;

    if let Some(error) = resp.get("error") {
        return Err(format!("RPC error: {:?}", error));
    }

    // suix_getBalance 返回 { totalBalance: "..." }（字符串，因为可能超出 u64 范围）
    let balance_str = resp
        .get("result")
        .and_then(|r| r.get("totalBalance"))
        .and_then(|b| b.as_str())
        .ok_or("Missing totalBalance in response")?;

    balance_str
        .parse::<u64>()
        .map_err(|e| format!("Failed to parse balance '{}': {}", balance_str, e))
}

/// 推断 Move 合约的 shuffle_state.phase 值。
///
/// Move 的 TableSummaryState 未包含 shuffle_state.phase，但可通过 round_state + shuffle 活动推断：
/// - shuffle 不活跃（pending=0 且 completed=0 且 current_shuffler=None）→ 0 (NONE)
/// - shuffle 活跃 + round_state==0 (WAITING) → 3 (BEFORE_PREFLOP)
/// - shuffle 活跃 + round_state!=0 → 2 (RECONSTRUCT)
pub fn infer_shuffle_phase(
    round_state: u8,
    shuffle_pending_count: u64,
    shuffle_completed_count: u64,
    shuffle_current_shuffler: Option<u64>,
) -> u8 {
    let shuffle_active = shuffle_pending_count > 0
        || shuffle_completed_count > 0
        || shuffle_current_shuffler.is_some();

    if !shuffle_active {
        return 0; // SHUFFLE_PHASE_NONE
    }

    if round_state == 0 {
        3 // SHUFFLE_PHASE_BEFORE_PREFLOP
    } else {
        2 // SHUFFLE_PHASE_RECONSTRUCT
    }
}

/// 通过 sui_devInspectTransactionBlock 调用 get_table_summary_v2 获取链上 Table 快照（含加密状态）。
///
/// 构建 PTB 调用 `texas_poker::table::get_table_summary_v2(&Table, &TxContext)`，
/// 通过 dev inspect 提交（sender=0x0），从返回结果提取 BCS 字节并反序列化为 TableSummaryV2。
///
/// C4 修复：使用 relayer::ptb 模块构建正确的 PTB 并 BCS 序列化为 base64 字符串，
/// 符合 sui_devInspectTransactionBlock 的 JSON-RPC 规范（第二个参数为 base64 编码的
/// BCS TransactionBlockBytes / TransactionKind）。
///
/// # 参数
/// * `rpc_url` - Sui 全节点的 JSON-RPC URL
/// * `package_id` - Move 合约包 ID（hex 字符串，如 "0x..."）
/// * `table_object_id` - Table 对象的 Object ID
pub async fn fetch_table_summary_via_dev_inspect(
    rpc_url: &str,
    package_id: &str,
    table_object_id: &str,
) -> Result<TableSummaryV2, String> {
    // 1. 使用 relayer::ptb 构建正确的 PTB（ProgrammableTransaction）
    //    get_table_summary_v2 是只读函数，使用 shared immutable Table 引用。
    //    复用 ptb 模块的 shared_input 逻辑确保 BCS 编码正确。
    let pt = build_get_table_summary_ptb(package_id, table_object_id)?;

    // 1.5 解析 shared object 的 initial_shared_version（placeholder 0 → 真实版本）。
    //     部分 Sui 全节点不会自动解析 version 0，导致 "Could not find the referenced
    //     object ... at version None" 错误，因此必须显式解析。
    let http = crate::sponsor::shared_http_client();
    let pt = crate::relayer::ptb::resolve_shared_object_versions(http, rpc_url, pt).await?;

    // 2. BCS 序列化 TransactionKind::ProgrammableTransaction 并 base64 编码
    //    sui_devInspectTransactionBlock 的第二个参数要求 base64 编码的 BCS
    //    TransactionBlockBytes（实际是 TransactionKind 的 BCS 字节）。
    let tx_kind_b64 = crate::relayer::ptb::serialize_tx_kind(pt)?;

    // 3. 构建 sui_devInspectTransactionBlock 请求
    //    sender = 0x0 (zero address for read-only dev inspect)
    //    params: [sender, tx_bytes_b64, gas_price?, epoch?, dev_inspect_args]
    //    dev_inspect_args 为 DevInspectArgs 结构体（新版 Sui RPC 不再接受字符串格式）。
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "sui_devInspectTransactionBlock",
        "params": [
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            tx_kind_b64,
            null,
            null,
            {
                "show_effects": true,
                "show_input": true,
                "show_object_changes": true,
                "show_raw_input": false,
                "show_raw_effects": false
            }
        ]
    });

    // 4. 发送请求
    let client = reqwest::Client::new();
    let resp: serde_json::Value = client
        .post(rpc_url)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {}", e))?
        .json()
        .await
        .map_err(|e| format!("JSON parse failed: {}", e))?;

    // 5. 检查错误
    if let Some(error) = resp.get("error") {
        return Err(format!("RPC error: {:?}", error));
    }

    let result = resp.get("result")
        .ok_or("No result in dev inspect response")?;

    // 6. 检查执行状态
    let status = result
        .get("effects")
        .and_then(|e| e.get("status"))
        .and_then(|s| s.get("status"))
        .and_then(|s| s.as_str())
        .ok_or("Missing execution status in dev inspect response")?;

    if status != "success" {
        let error = result
            .get("effects")
            .and_then(|e| e.get("status"))
            .and_then(|s| s.get("error"))
            .and_then(|e| e.as_str())
            .unwrap_or("unknown error");
        return Err(format!("Dev inspect execution failed: {}", error));
    }

    // 7. 从 results[0].returnValues[0] 提取 BCS 字节
    let results = result.get("results");
    let return_value = result
        .get("results")
        .and_then(|r| r.get(0))
        .and_then(|r| r.get("returnValues"))
        .and_then(|rv| rv.get(0))
        .ok_or_else(|| {
            format!(
                "No return values in dev inspect response, results={:?}",
                results
            )
        })?;

    // returnValues[0] 通常是 [base64_string, type_string]，
    // 但部分 Sui 节点返回 [Vec<u8>, type_string]（JSON 数字数组）。
    // 兼容两种格式。
    let bcs_bytes = {
        let bytes_val = return_value.get(0).ok_or_else(|| {
            format!(
                "Missing BCS bytes in return value, return_value={:?}",
                return_value
            )
        })?;
        if let Some(s) = bytes_val.as_str() {
            // 标准 base64 字符串格式
            let engine = base64::engine::general_purpose::STANDARD;
            engine.decode(s).map_err(|e| format!("Base64 decode error: {}", e))?
        } else if let Some(arr) = bytes_val.as_array() {
            // JSON 数字数组格式（部分 Sui 节点）
            arr.iter()
                .map(|v| v.as_u64().unwrap_or(0) as u8)
                .collect::<Vec<u8>>()
        } else {
            return Err(format!(
                "Unexpected BCS bytes format in return value, bytes_val={:?}",
                bytes_val
            ));
        }
    };

    // // 9. BCS 反序列化为 TableSummaryV2
    // tracing::info!(
    //     "[fetch_table_summary] BCS bytes len={}, first 200 bytes hex: {}",
    //     bcs_bytes.len(),
    //     bcs_bytes.iter().take(200).map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("")
    // );
    bcs::from_bytes::<TableSummaryV2Chain>(&bcs_bytes)
        .map(TableSummaryV2::from)
        .map_err(|e| format!("BCS deserialization failed: {}", e))
}

/// 构建 `table::get_table_summary_v2` 的 ProgrammableTransaction。
///
/// Move signature: `get_table_summary_v2(table: &Table, ctx: &TxContext): TableSummaryV2`
///
/// Inputs:
/// - `Input(0)`: `&Table` (shared, immutable — 只读快照)
///
/// 复用 relayer::ptb 的内部逻辑确保 BCS 编码与 Sui SDK 一致。
fn build_get_table_summary_ptb(
    package_id: &str,
    table_object_id: &str,
) -> Result<sui_sdk_types::ProgrammableTransaction, String> {
    use sui_sdk_types::{Address, Argument, Command, Identifier, Input, MoveCall, ProgrammableTransaction, SharedInput};

    let parse_address = |s: &str| -> Result<Address, String> {
        s.parse::<Address>()
            .map_err(|e| format!("invalid address '{}': {}", s, e))
    };

    let table_id = parse_address(table_object_id)?;
    let package = parse_address(package_id)?;

    // Shared immutable input for &Table
    let inputs = vec![Input::Shared(SharedInput::new(table_id, 0, false))];
    let arguments = vec![Argument::Input(0)];
    let commands = vec![Command::MoveCall(MoveCall {
        package,
        module: Identifier::from_static("table"),
        function: Identifier::from_static("get_table_summary_v2"),
        type_arguments: Vec::new(),
        arguments,
    })];

    Ok(ProgrammableTransaction { inputs, commands })
}

/// 获取链上 Table 的完整快照（含加密状态，V2）。
///
/// 内部调用 `fetch_table_summary_via_dev_inspect` 通过 dev inspect 获取 BCS 编码的 TableSummaryV2。
///
/// # 参数
/// * `rpc_url` - Sui 全节点的 JSON-RPC URL
/// * `package_id` - Move 合约包 ID
/// * `table_object_id` - Table 对象的 Object ID
pub async fn fetch_table_summary(
    rpc_url: &str,
    package_id: &str,
    table_object_id: &str,
) -> Result<TableSummaryV2, String> {
    fetch_table_summary_via_dev_inspect(rpc_url, package_id, table_object_id).await
}

// ---------------------------------------------------------------------------
// Reveal Assignments - 通过 dev inspect 获取链上 reveal assignments
// ---------------------------------------------------------------------------

/// Move 合约 `RevealTokenData` 的 BCS 反序列化结构。
/// 字段顺序必须与 `table.move` 中的 `RevealTokenData` struct 一致。
#[derive(Debug, serde::Deserialize)]
struct RevealTokenDataBcs {
    seat_index: u64,
    token: Vec<u8>,
}

/// Move 合约 `RevealAssignment` 的 BCS 反序列化结构。
/// 字段顺序必须与 `table.move` 中的 `RevealAssignment` struct 一致。
#[derive(Debug, serde::Deserialize)]
struct RevealAssignmentBcs {
    encrypted_card_index: u64,
    pending_players: Vec<u64>,
    reveal_tokens: Vec<RevealTokenDataBcs>,
    decrypted: bool,
}

/// 构建 `table::reveal_assignments` + `bcs::to_bytes` 的 ProgrammableTransaction。
///
/// Move signature: `reveal_assignments(table: &Table): &vector<RevealAssignment>`
///
/// 由于 `reveal_assignments` 返回引用，dev inspect 不会自动序列化引用返回值。
/// 因此使用 `0x2::bcs::to_bytes<vector<origin::table::RevealAssignment>>(&vector)` 将其转为字节。
///
/// PTB 结构：
/// - Command 0: `table::reveal_assignments(&Table)` → Result(0)
/// - Command 1: `0x2::bcs::to_bytes<vector<origin::table::RevealAssignment>>(&Result(0))` → Result(1)
///
/// # 参数
/// * `package_id` - Move 合约当前包 ID（函数所在）
/// * `origin_package_id` - Move 合约原始包 ID（struct 类型锚定）
/// * `table_object_id` - Table 对象的 Object ID
fn build_reveal_assignments_ptb(
    package_id: &str,
    origin_package_id: &str,
    table_object_id: &str,
) -> Result<sui_sdk_types::ProgrammableTransaction, String> {
    use sui_sdk_types::{
        Address, Argument, Command, Identifier, Input, MoveCall, ProgrammableTransaction,
        SharedInput, StructTag, TypeTag,
    };

    let parse_address = |s: &str| -> Result<Address, String> {
        s.parse::<Address>()
            .map_err(|e| format!("invalid address '{}': {}", s, e))
    };

    let table_id = parse_address(table_object_id)?;
    let package = parse_address(package_id)?;
    let origin_package = parse_address(origin_package_id)?;
    let bcs_package = parse_address("0x2")?;

    // Shared immutable input for &Table
    let inputs = vec![Input::Shared(SharedInput::new(table_id, 0, false))];

    // Command 0: table::reveal_assignments(&Table) → Result(0)
    let cmd0 = Command::MoveCall(MoveCall {
        package,
        module: Identifier::from_static("table"),
        function: Identifier::from_static("reveal_assignments"),
        type_arguments: Vec::new(),
        arguments: vec![Argument::Input(0)],
    });

    // Command 1: 0x2::bcs::to_bytes<vector<origin::table::RevealAssignment>>(&Result(0)) → Result(1)
    let reveal_assignment_type = TypeTag::Struct(Box::new(StructTag::new(
        origin_package,
        Identifier::from_static("table"),
        Identifier::from_static("RevealAssignment"),
        Vec::new(),
    )));
    let cmd1 = Command::MoveCall(MoveCall {
        package: bcs_package,
        module: Identifier::from_static("bcs"),
        function: Identifier::from_static("to_bytes"),
        type_arguments: vec![TypeTag::Vector(Box::new(reveal_assignment_type))],
        arguments: vec![Argument::Result(0)],
    });

    Ok(ProgrammableTransaction {
        inputs,
        commands: vec![cmd0, cmd1],
    })
}

/// 通过 dev inspect 获取链上 `reveal_assignments`。
///
/// 返回 `Vec<RevealAssignmentBcs>`，按链上 `assignments` vector 的顺序排列。
///
/// # 参数
/// * `rpc_url` - Sui 全节点的 JSON-RPC URL
/// * `package_id` - Move 合约当前包 ID（函数所在）
/// * `origin_package_id` - Move 合约原始包 ID（struct 类型锚定）
/// * `table_object_id` - Table 对象的 Object ID
pub async fn fetch_reveal_assignments(
    rpc_url: &str,
    package_id: &str,
    origin_package_id: &str,
    table_object_id: &str,
) -> Result<Vec<RevealAssignmentBcs>, String> {
    let pt = build_reveal_assignments_ptb(package_id, origin_package_id, table_object_id)?;

    let http = crate::sponsor::shared_http_client();
    let pt = crate::relayer::ptb::resolve_shared_object_versions(http, rpc_url, pt).await?;

    let tx_kind_b64 = crate::relayer::ptb::serialize_tx_kind(pt)?;

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "sui_devInspectTransactionBlock",
        "params": [
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            tx_kind_b64,
            null,
            null,
            {
                "show_effects": true,
                "show_input": true,
                "show_object_changes": true,
                "show_raw_input": false,
                "show_raw_effects": false
            }
        ]
    });

    let client = reqwest::Client::new();
    let resp: serde_json::Value = client
        .post(rpc_url)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {}", e))?
        .json()
        .await
        .map_err(|e| format!("JSON parse failed: {}", e))?;

    if let Some(error) = resp.get("error") {
        return Err(format!("RPC error: {:?}", error));
    }

    let result = resp
        .get("result")
        .ok_or("No result in dev inspect response")?;

    let status = result
        .get("effects")
        .and_then(|e| e.get("status"))
        .and_then(|s| s.get("status"))
        .and_then(|s| s.as_str())
        .ok_or("Missing execution status in dev inspect response")?;

    if status != "success" {
        let error = result
            .get("effects")
            .and_then(|e| e.get("status"))
            .and_then(|s| s.get("error"))
            .and_then(|e| e.as_str())
            .unwrap_or("unknown error");
        return Err(format!("Dev inspect execution failed: {}", error));
    }

    // bcs::to_bytes 是 command 1，所以返回值在 results[1].returnValues[0]
    let return_value = result
        .get("results")
        .and_then(|r| r.get(1))
        .and_then(|r| r.get("returnValues"))
        .and_then(|rv| rv.get(0))
        .ok_or("No return values for bcs::to_bytes in dev inspect response")?;

    // 提取 BCS 字节（bcs::to_bytes 返回 vector<u8>）
    let bcs_bytes = {
        let bytes_val = return_value
            .get(0)
            .ok_or("Missing BCS bytes in return value")?;
        if let Some(s) = bytes_val.as_str() {
            let engine = base64::engine::general_purpose::STANDARD;
            engine
                .decode(s)
                .map_err(|e| format!("Base64 decode error: {}", e))?
        } else if let Some(arr) = bytes_val.as_array() {
            arr.iter()
                .map(|v| v.as_u64().unwrap_or(0) as u8)
                .collect::<Vec<u8>>()
        } else {
            return Err("Unexpected BCS bytes format in return value".to_string());
        }
    };

    // bcs::to_bytes 返回 vector<u8>，BCS 序列化为外层 Vec<u8>
    // 先反序列化为 Vec<u8>（外层），再反序列化为 Vec<RevealAssignmentBcs>（内层）
    let inner_bytes = bcs::from_bytes::<Vec<u8>>(&bcs_bytes)
        .map_err(|e| format!("BCS outer deserialization failed: {}", e))?;
    bcs::from_bytes::<Vec<RevealAssignmentBcs>>(&inner_bytes)
        .map_err(|e| format!("BCS inner deserialization failed: {}", e))
}

/// 根据本地 `deck_encrypted` 和 `reveal_tokens` 推导每个 token 对应的链上 assignment 索引。
///
/// 修复 `submit_player_reveal_tokens_verified` 的 MoveAbort (ENotPendingRevealer)：
/// 原实现使用 `0..n` 作为 assignment_indices 占位，但链上 `assignments` 是跨所有玩家的全局
/// vector，`0..n` 可能指向属于其他玩家或已解密的 assignment。本函数通过匹配 token 的
/// `encrypted_card` 与本地 `deck_encrypted` 找到 `encrypted_card_index`，再映射到 assignment
/// 在 vector 中的位置。
///
/// 算法：
/// 1. 通过 dev inspect 获取链上 `reveal_assignments`
/// 2. 构建 `HashMap<encrypted_card_index, assignment_index>`（仅包含未解密的 assignment）
/// 3. 对每个 token 的 `encrypted_card`（c1_hex || c2_hex = 96 bytes），
///    在 `deck_encrypted` 中查找匹配的 `encrypted_card_index`
/// 4. 通过 HashMap 查找对应的 `assignment_index`
///
/// # 参数
/// * `rpc_url` - Sui 全节点的 JSON-RPC URL
/// * `package_id` - Move 合约当前包 ID（函数所在）
/// * `origin_package_id` - Move 合约原始包 ID（struct 类型锚定）
/// * `table_object_id` - Table 对象的 Object ID
/// * `reveal_tokens` - 待提交的 reveal tokens（含 encrypted_card）
/// * `deck_encrypted` - 本地缓存的加密牌组（每个元素 96 bytes: c1 || c2）
///
/// # 返回
/// 成功返回与 `reveal_tokens` 等长的 `Vec<u64>`，每个元素为对应 token 的 assignment 全局索引。
pub async fn fetch_reveal_assignment_indices(
    rpc_url: &str,
    package_id: &str,
    origin_package_id: &str,
    table_object_id: &str,
    reveal_tokens: &[crate::pokergame::game_state::SubmitRevealTokenJson],
    deck_encrypted: &[Vec<u8>],
) -> Result<Vec<u64>, String> {
    use std::collections::HashMap;

    // 1. 获取链上 assignments
    let assignments =
        fetch_reveal_assignments(rpc_url, package_id, origin_package_id, table_object_id).await?;

    // 2. 构建 encrypted_card_index → assignment_index 映射（仅未解密）
    let mut card_to_assignment: HashMap<u64, u64> = HashMap::new();
    for (idx, a) in assignments.iter().enumerate() {
        if !a.decrypted {
            card_to_assignment.insert(a.encrypted_card_index, idx as u64);
        }
    }

    // 3. 对每个 token，匹配 encrypted_card → encrypted_card_index → assignment_index
    let mut indices: Vec<u64> = Vec::with_capacity(reveal_tokens.len());
    for (i, token) in reveal_tokens.iter().enumerate() {
        // 将 token.encrypted_card (c1_hex, c2_hex) 转为 96 bytes (c1 || c2)
        let c1 = hex::decode(&token.encrypted_card.c1_hex)
            .map_err(|e| format!("token[{}] c1_hex decode failed: {}", i, e))?;
        let c2 = hex::decode(&token.encrypted_card.c2_hex)
            .map_err(|e| format!("token[{}] c2_hex decode failed: {}", i, e))?;
        let mut card_bytes = c1;
        card_bytes.extend_from_slice(&c2);

        // 在 deck_encrypted 中查找匹配的 encrypted_card_index
        let card_index = deck_encrypted
            .iter()
            .position(|d| d.as_slice() == card_bytes.as_slice())
            .ok_or_else(|| {
                format!(
                    "token[{}] encrypted_card not found in deck_encrypted (len={})",
                    i,
                    deck_encrypted.len()
                )
            })? as u64;

        // 查找对应的 assignment_index
        let assignment_index = card_to_assignment
            .get(&card_index)
            .copied()
            .ok_or_else(|| {
                format!(
                    "token[{}] encrypted_card_index={} not found in pending assignments (or already decrypted)",
                    i, card_index
                )
            })?;

        indices.push(assignment_index);
    }

    Ok(indices)
}

/// Move 合约 `DecryptedCardInfo` 的 BCS 反序列化结构。
/// 字段顺序必须与 `table.move` 中的 `DecryptedCardInfo` struct 一致。
#[derive(Debug, serde::Deserialize)]
pub struct DecryptedCardInfoBcs {
    pub owner_seat_index: u64,
    pub ciphertext_bytes: Vec<u8>,   // 96 bytes: c1+c2，部分解密后即为 readable_card
    pub plaintext_bytes: Vec<u8>,    // 48 bytes G1 compressed，空=仅部分解密
}

/// 构建 `table::decrypted_cards_info` + `bcs::to_bytes` 的 ProgrammableTransaction。
fn build_decrypted_cards_info_ptb(
    package_id: &str,
    origin_package_id: &str,
    table_object_id: &str,
) -> Result<sui_sdk_types::ProgrammableTransaction, String> {
    use sui_sdk_types::{
        Address, Argument, Command, Identifier, Input, MoveCall, ProgrammableTransaction,
        SharedInput, StructTag, TypeTag,
    };

    let parse_address = |s: &str| -> Result<Address, String> {
        s.parse::<Address>()
            .map_err(|e| format!("invalid address '{}': {}", s, e))
    };

    let table_id = parse_address(table_object_id)?;
    let package = parse_address(package_id)?;
    let origin_package = parse_address(origin_package_id)?;
    let bcs_package = parse_address("0x2")?;

    let inputs = vec![Input::Shared(SharedInput::new(table_id, 0, false))];

    // Command 0: table::decrypted_cards_info(&Table) → Result(0)
    let cmd0 = Command::MoveCall(MoveCall {
        package,
        module: Identifier::from_static("table"),
        function: Identifier::from_static("decrypted_cards_info"),
        type_arguments: Vec::new(),
        arguments: vec![Argument::Input(0)],
    });

    // Command 1: 0x2::bcs::to_bytes<vector<origin::table::DecryptedCardInfo>>(&Result(0))
    let info_type = TypeTag::Struct(Box::new(StructTag::new(
        origin_package,
        Identifier::from_static("table"),
        Identifier::from_static("DecryptedCardInfo"),
        Vec::new(),
    )));
    let cmd1 = Command::MoveCall(MoveCall {
        package: bcs_package,
        module: Identifier::from_static("bcs"),
        function: Identifier::from_static("to_bytes"),
        type_arguments: vec![TypeTag::Vector(Box::new(info_type))],
        arguments: vec![Argument::Result(0)],
    });

    Ok(ProgrammableTransaction {
        inputs,
        commands: vec![cmd0, cmd1],
    })
}

/// 通过 dev inspect 获取链上 `decrypted_cards_info`。
///
/// 返回 `Vec<DecryptedCardInfoBcs>`，每个元素包含 `owner_seat_index` 和 `ciphertext_bytes`
/// （96 bytes: c1+c2，部分解密后的 readable_card）。
///
/// relayer 在 `RevealPhaseComplete` 后调用此函数，用 `ciphertext_bytes` 作为
/// `HandRevealResultPayload` 的 `readable_cards`。
pub async fn fetch_decrypted_cards_info(
    rpc_url: &str,
    package_id: &str,
    origin_package_id: &str,
    table_object_id: &str,
) -> Result<Vec<DecryptedCardInfoBcs>, String> {
    let pt = build_decrypted_cards_info_ptb(package_id, origin_package_id, table_object_id)?;

    let http = crate::sponsor::shared_http_client();
    let pt = crate::relayer::ptb::resolve_shared_object_versions(http, rpc_url, pt).await?;

    let tx_kind_b64 = crate::relayer::ptb::serialize_tx_kind(pt)?;

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "sui_devInspectTransactionBlock",
        "params": [
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            tx_kind_b64,
            null,
            null,
            {
                "show_effects": true,
                "show_input": true,
                "show_object_changes": true,
                "show_raw_input": false,
                "show_raw_effects": false
            }
        ]
    });

    let client = reqwest::Client::new();
    let resp: serde_json::Value = client
        .post(rpc_url)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {}", e))?
        .json()
        .await
        .map_err(|e| format!("JSON parse failed: {}", e))?;

    if let Some(error) = resp.get("error") {
        return Err(format!("RPC error: {:?}", error));
    }

    let result = resp
        .get("result")
        .ok_or("No result in dev inspect response")?;

    let status = result
        .get("effects")
        .and_then(|e| e.get("status"))
        .and_then(|s| s.get("status"))
        .and_then(|s| s.as_str())
        .ok_or("Missing execution status in dev inspect response")?;

    if status != "success" {
        let error = result
            .get("effects")
            .and_then(|e| e.get("status"))
            .and_then(|s| s.get("error"))
            .and_then(|e| e.as_str())
            .unwrap_or("unknown error");
        return Err(format!("Dev inspect execution failed: {}", error));
    }

    let return_value = result
        .get("results")
        .and_then(|r| r.get(1))
        .and_then(|r| r.get("returnValues"))
        .and_then(|rv| rv.get(0))
        .ok_or("No return values for bcs::to_bytes in dev inspect response")?;

    let bcs_bytes = {
        let bytes_val = return_value
            .get(0)
            .ok_or("Missing BCS bytes in return value")?;
        if let Some(s) = bytes_val.as_str() {
            let engine = base64::engine::general_purpose::STANDARD;
            engine
                .decode(s)
                .map_err(|e| format!("Base64 decode error: {}", e))?
        } else if let Some(arr) = bytes_val.as_array() {
            arr.iter()
                .map(|v| v.as_u64().unwrap_or(0) as u8)
                .collect::<Vec<u8>>()
        } else {
            return Err("Unexpected BCS bytes format in return value".to_string());
        }
    };

    let inner_bytes = bcs::from_bytes::<Vec<u8>>(&bcs_bytes)
        .map_err(|e| format!("BCS outer deserialization failed: {}", e))?;
    bcs::from_bytes::<Vec<DecryptedCardInfoBcs>>(&inner_bytes)
        .map_err(|e| format!("BCS inner deserialization failed: {}", e))
}
