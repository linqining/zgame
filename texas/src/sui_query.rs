use crate::sui_events::TableSummary;
use base64::Engine;

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

/// 通过 sui_devInspectTransactionBlock 调用 get_table_summary 获取链上 Table 快照。
///
/// 构建 PTB 调用 `texas_poker::table::get_table_summary(&Table, &TxContext)`，
/// 通过 dev inspect 提交（sender=0x0），从返回结果提取 BCS 字节并反序列化为 TableSummary。
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
) -> Result<TableSummary, String> {
    // 1. 使用 relayer::ptb 构建正确的 PTB（ProgrammableTransaction）
    //    get_table_summary 是只读函数，使用 shared immutable Table 引用。
    //    复用 ptb 模块的 shared_input 逻辑确保 BCS 编码正确。
    let pt = build_get_table_summary_ptb(package_id, table_object_id)?;

    // 2. BCS 序列化 TransactionKind::ProgrammableTransaction 并 base64 编码
    //    sui_devInspectTransactionBlock 的第二个参数要求 base64 编码的 BCS
    //    TransactionBlockBytes（实际是 TransactionKind 的 BCS 字节）。
    let tx_kind_b64 = crate::relayer::ptb::serialize_tx_kind(pt)?;

    // 3. 构建 sui_devInspectTransactionBlock 请求
    //    sender = 0x0 (zero address for read-only dev inspect)
    //    params: [sender, tx_bytes_b64, gas_price?, epoch?, "ShowEffects,ShowInput,ShowObjectChanges"]
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "sui_devInspectTransactionBlock",
        "params": [
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            tx_kind_b64,
            null,
            null,
            "ShowEffects,ShowInput,ShowObjectChanges"
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
    let return_value = result
        .get("results")
        .and_then(|r| r.get(0))
        .and_then(|r| r.get("returnValues"))
        .and_then(|rv| rv.get(0))
        .ok_or("No return values in dev inspect response")?;

    // returnValues[0] is [base64_encoded_bytes, type]
    let bcs_b64 = return_value
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or("Missing BCS bytes in return value")?;

    // 8. Base64 解码
    let engine = base64::engine::general_purpose::STANDARD;
    let bcs_bytes = engine
        .decode(bcs_b64)
        .map_err(|e| format!("Base64 decode error: {}", e))?;

    // 9. BCS 反序列化为 TableSummary
    bcs::from_bytes::<TableSummary>(&bcs_bytes)
        .map_err(|e| format!("BCS deserialization failed: {}", e))
}

/// 构建 `table::get_table_summary` 的 ProgrammableTransaction。
///
/// Move signature: `get_table_summary(table: &Table, ctx: &TxContext): TableSummary`
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
        function: Identifier::from_static("get_table_summary"),
        type_arguments: Vec::new(),
        arguments,
    })];

    Ok(ProgrammableTransaction { inputs, commands })
}

/// 获取链上 Table 的完整快照。
///
/// 内部调用 `fetch_table_summary_via_dev_inspect` 通过 dev inspect 获取 BCS 编码的 TableSummary。
///
/// # 参数
/// * `rpc_url` - Sui 全节点的 JSON-RPC URL
/// * `package_id` - Move 合约包 ID
/// * `table_object_id` - Table 对象的 Object ID
pub async fn fetch_table_summary(
    rpc_url: &str,
    package_id: &str,
    table_object_id: &str,
) -> Result<TableSummary, String> {
    fetch_table_summary_via_dev_inspect(rpc_url, package_id, table_object_id).await
}
