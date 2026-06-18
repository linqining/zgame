use std::sync::Arc;

use crate::config::Config;
use crate::handlers::AppState;
use crate::sui_events::parse_chain_event;

// ============================================================
// SuiEventProvider enum — 事件监听提供者抽象
// ============================================================

/// 事件监听提供者枚举，支持多种实现间切换
pub enum SuiEventProvider {
    /// 官方/第三方 gRPC 订阅
    Grpc,
    /// Inodra Webhook 被动接收
    InodraWebhook,
    /// 组合多个提供者同时运行
    Both,
}

impl SuiEventProvider {
    /// 提供者名称（用于日志）
    pub fn name(&self) -> &str {
        match self {
            SuiEventProvider::Grpc => "gRPC",
            SuiEventProvider::InodraWebhook => "InodraWebhook",
            SuiEventProvider::Both => "Composite(gRPC+Inodra)",
        }
    }

    /// 启动事件监听（阻塞，通常在 tokio::spawn 中运行）
    pub async fn run(&self, config: &Config, state: Arc<AppState>) {
        match self {
            SuiEventProvider::Grpc => {
                crate::sui_grpc::subscribe_with_reconnect(config.clone(), state).await;
            }
            SuiEventProvider::InodraWebhook => {
                tracing::info!(
                    "[InodraWebhook] webhook mode active, endpoint: POST /api/sui/webhook, secret configured: {}",
                    !config.inodra_webhook_secret.is_empty()
                );
                // Webhook 模式是被动接收，永久挂起
                std::future::pending::<()>().await;
            }
            SuiEventProvider::Both => {
                let grpc_state = state.clone();
                let grpc_config = config.clone();
                let webhook_config = config.clone();

                let grpc_handle = tokio::spawn(async move {
                    tracing::info!("[Composite] starting gRPC provider");
                    crate::sui_grpc::subscribe_with_reconnect(grpc_config, grpc_state).await;
                });

                let webhook_handle = tokio::spawn(async move {
                    tracing::info!("[Composite] starting InodraWebhook provider");
                    tracing::info!(
                        "[InodraWebhook] webhook mode active, endpoint: POST /api/sui/webhook, secret configured: {}",
                        !webhook_config.inodra_webhook_secret.is_empty()
                    );
                    std::future::pending::<()>().await;
                });

                let _ = grpc_handle.await;
                let _ = webhook_handle.await;
            }
        }
    }
}

// ============================================================
// GraphQL 历史事件回填
// ============================================================

const CHECKPOINT_FILE: &str = ".sui_last_cursor";

/// G14 修复：cursor 文件使用绝对路径，基于当前可执行文件目录解析，
/// 避免相对路径依赖进程工作目录。可通过环境变量 SUI_CURSOR_FILE 覆盖。
fn checkpoint_file_path() -> std::path::PathBuf {
    if let Ok(custom) = std::env::var("SUI_CURSOR_FILE") {
        return std::path::PathBuf::from(custom);
    }
    // 基于当前可执行文件目录解析相对路径
    match std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join(CHECKPOINT_FILE)))
    {
        Some(p) => p,
        None => std::path::PathBuf::from(CHECKPOINT_FILE),
    }
}

fn load_last_cursor() -> Option<String> {
    std::fs::read_to_string(checkpoint_file_path())
        .ok()
        .and_then(|s| {
            let trimmed = s.trim();
            if trimmed.is_empty() { None } else { Some(trimmed.to_string()) }
        })
}

/// G15 修复：原子写入 cursor 文件——先写临时文件再 rename，避免写入过程中
/// 进程崩溃导致 cursor 文件损坏（部分写入）。
fn save_last_cursor(cursor: &str) {
    let path = checkpoint_file_path();
    let tmp = path.with_extension("tmp");
    if let Err(e) = std::fs::write(&tmp, cursor).and_then(|_| std::fs::rename(&tmp, &path)) {
        tracing::warn!("[sui_listener] failed to save cursor: {}", e);
    }
}

/// 使用 Sui GraphQL RPC 回填历史事件
///
/// `start_cursor` 为 `Some(cursor)` 时从该 cursor 之后继续分页，否则从头开始。
/// 返回 `(total_events, last_cursor)`，`last_cursor` 为最后一页的 `endCursor`，
/// 可用于下次启动时续传。
pub async fn backfill_historical_events(
    config: &Config,
    state: &Arc<AppState>,
    start_cursor: Option<String>,
) -> Result<(u64, Option<String>), String> {
    let graphql_url = match config.sui_network.as_str() {
        "mainnet" => "https://graphql.mainnet.sui.io/graphql",
        "testnet" => "https://graphql.testnet.sui.io/graphql",
        "devnet" => "https://graphql.devnet.sui.io/graphql",
        _ => return Err(format!("Unknown sui_network: {}", config.sui_network)),
    };

    let package_id = &config.sui_package_id;
    if package_id.is_empty() {
        tracing::warn!("[sui_listener] SUI_PACKAGE_ID not configured, skipping backfill");
        return Ok((0, None));
    }

    tracing::info!(
        "[sui_listener] starting backfill from cursor {:?} for package {}",
        start_cursor,
        package_id
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;
    let mut total_events = 0u64;
    let mut cursor: Option<String> = start_cursor;
    let mut last_cursor: Option<String> = None;

    loop {
        let query = r#"
query Events($package: SuiAddress!, $cursor: String) {
  events(
    first: 50
    after: $cursor
    filter: { emittingModule: { package: $package } }
  ) {
    nodes {
      eventType { repr }
      json
      timestamp
      transaction { digest }
    }
    pageInfo { hasNextPage endCursor }
  }
}
"#;

        let variables = serde_json::json!({
            "package": package_id,
            "cursor": cursor,
        });

        let response = client
            .post(graphql_url)
            .json(&serde_json::json!({
                "query": query,
                "variables": variables,
            }))
            .send()
            .await
            .map_err(|e| format!("GraphQL request failed: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("GraphQL request failed: status={}, body={}", status, body));
        }

        let result: serde_json::Value = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse GraphQL response: {}", e))?;

        let events = result
            .get("data")
            .and_then(|d| d.get("events"))
            .and_then(|e| e.get("nodes"))
            .and_then(|n| n.as_array());

        let events = match events {
            Some(e) => e,
            None => {
                tracing::warn!("[sui_listener] no events found in GraphQL response");
                break;
            }
        };

        if events.is_empty() {
            break;
        }

        for event_node in events {
            let event_type = event_node
                .get("eventType")
                .and_then(|t| t.get("repr"))
                .and_then(|r| r.as_str())
                .unwrap_or("");

            let json_data = event_node.get("json").cloned().unwrap_or(serde_json::Value::Null);

            if let Some(chain_event) = parse_chain_event(event_type, &json_data) {
                tracing::info!("[sui_listener] backfill event: {:?}", chain_event);
                crate::relayer::process_event(&state.relayer_state, &config.fullnode_url, &config.sui_package_id, &chain_event).await;
                crate::relayer::apply_event_to_socket(state, &chain_event).await;
                total_events += 1;
            }
        }

        let page_info = result
            .get("data")
            .and_then(|d| d.get("events"))
            .and_then(|e| e.get("pageInfo"));

        let has_next = page_info
            .and_then(|p| p.get("hasNextPage"))
            .and_then(|h| h.as_bool())
            .unwrap_or(false);

        cursor = page_info
            .and_then(|p| p.get("endCursor"))
            .and_then(|c| c.as_str())
            .map(|s| s.to_string());
        last_cursor = cursor.clone();

        if !has_next {
            break;
        }
    }

    tracing::info!("[sui_listener] backfill complete, {} events processed", total_events);
    Ok((total_events, last_cursor))
}

/// 从指定 checkpoint 序号开始回填事件，用于 gRPC 重连后填补间隙。
///
/// 与 `backfill_historical_events` 不同，本函数不使用 cursor 分页，
/// 而是基于 checkpoint 序号过滤事件，仅处理 `seq > start_checkpoint` 的事件。
/// 调用方（如 gRPC 重连逻辑）应在重连前调用本函数填补断连期间丢失的事件。
///
/// # 参数
/// * `config` - 配置
/// * `state` - 应用状态
/// * `start_checkpoint` - 上次成功处理的 checkpoint 序号（exclusive，仅处理大于此值的事件）
pub async fn backfill_from_checkpoint(
    config: &Config,
    state: &Arc<AppState>,
    start_checkpoint: u64,
) -> Result<u64, String> {
    let graphql_url = match config.sui_network.as_str() {
        "mainnet" => "https://graphql.mainnet.sui.io/graphql",
        "testnet" => "https://graphql.testnet.sui.io/graphql",
        "devnet" => "https://graphql.devnet.sui.io/graphql",
        _ => return Err(format!("Unknown sui_network: {}", config.sui_network)),
    };

    let package_id = &config.sui_package_id;
    if package_id.is_empty() {
        tracing::warn!("[sui_listener] SUI_PACKAGE_ID not configured, skipping backfill_from_checkpoint");
        return Ok(0);
    }

    tracing::info!(
        "[sui_listener] backfill_from_checkpoint: starting from checkpoint > {} for package {}",
        start_checkpoint,
        package_id
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;
    let mut total_events = 0u64;
    let mut cursor: Option<String> = None;

    loop {
        // 使用 checkpoint 序号过滤事件，仅查询 start_checkpoint 之后的事件
        let query = r#"
query Events($package: SuiAddress!, $cursor: String, $minCheckpoint: Int!) {
  events(
    first: 50
    after: $cursor
    filter: { emittingModule: { package: $package }, checkpoint: { minSequenceNumber: $minCheckpoint } }
  ) {
    nodes {
      eventType { repr }
      json
      timestamp
      transaction { digest }
      checkpoint { sequenceNumber }
    }
    pageInfo { hasNextPage endCursor }
  }
}
"#;

        let variables = serde_json::json!({
            "package": package_id,
            "cursor": cursor,
            "minCheckpoint": start_checkpoint,
        });

        let response = client
            .post(graphql_url)
            .json(&serde_json::json!({
                "query": query,
                "variables": variables,
            }))
            .send()
            .await
            .map_err(|e| format!("GraphQL request failed: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("GraphQL request failed: status={}, body={}", status, body));
        }

        let result: serde_json::Value = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse GraphQL response: {}", e))?;

        // 检查 GraphQL 错误（filter 字段可能不被支持，回退到无 checkpoint 过滤）
        if let Some(errors) = result.get("errors") {
            tracing::warn!(
                "[sui_listener] backfill_from_checkpoint GraphQL returned errors: {:?}, falling back to unfiltered backfill",
                errors
            );
            // 回退到不带 checkpoint 过滤的查询，依赖客户端过滤
            return backfill_historical_events_fallback(config, state, start_checkpoint).await;
        }

        let events = result
            .get("data")
            .and_then(|d| d.get("events"))
            .and_then(|e| e.get("nodes"))
            .and_then(|n| n.as_array());

        let events = match events {
            Some(e) if !e.is_empty() => e,
            _ => break,
        };

        let mut processed_in_page = 0u64;
        for event_node in events {
            // 客户端再次校验 checkpoint 序号（防御性）
            let cp_seq = event_node
                .get("checkpoint")
                .and_then(|c| c.get("sequenceNumber"))
                .and_then(|s| s.as_u64())
                .unwrap_or(0);
            if cp_seq <= start_checkpoint {
                continue;
            }

            let event_type = event_node
                .get("eventType")
                .and_then(|t| t.get("repr"))
                .and_then(|r| r.as_str())
                .unwrap_or("");

            let json_data = event_node.get("json").cloned().unwrap_or(serde_json::Value::Null);

            if let Some(chain_event) = parse_chain_event(event_type, &json_data) {
                tracing::info!(
                    "[sui_listener] backfill_from_checkpoint event at cp={}: {:?}",
                    cp_seq,
                    chain_event
                );
                crate::relayer::process_event(
                    &state.relayer_state,
                    &config.fullnode_url,
                    &config.sui_package_id,
                    &chain_event,
                )
                .await;
                crate::relayer::apply_event_to_socket(state, &chain_event).await;
                total_events += 1;
                processed_in_page += 1;
            }
        }

        let page_info = result
            .get("data")
            .and_then(|d| d.get("events"))
            .and_then(|e| e.get("pageInfo"));

        let has_next = page_info
            .and_then(|p| p.get("hasNextPage"))
            .and_then(|h| h.as_bool())
            .unwrap_or(false);

        cursor = page_info
            .and_then(|p| p.get("endCursor"))
            .and_then(|c| c.as_str())
            .map(|s| s.to_string());

        if !has_next || processed_in_page == 0 {
            break;
        }
    }

    tracing::info!(
        "[sui_listener] backfill_from_checkpoint complete, {} events processed",
        total_events
    );
    Ok(total_events)
}

/// 回退实现：当 GraphQL 不支持 checkpoint 过滤时，使用 cursor 分页 + 客户端过滤。
async fn backfill_historical_events_fallback(
    config: &Config,
    state: &Arc<AppState>,
    start_checkpoint: u64,
) -> Result<u64, String> {
    let graphql_url = match config.sui_network.as_str() {
        "mainnet" => "https://graphql.mainnet.sui.io/graphql",
        "testnet" => "https://graphql.testnet.sui.io/graphql",
        "devnet" => "https://graphql.devnet.sui.io/graphql",
        _ => return Err(format!("Unknown sui_network: {}", config.sui_network)),
    };

    let package_id = &config.sui_package_id;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

    let mut total_events = 0u64;
    let mut cursor: Option<String> = None;
    let mut consecutive_old_pages = 0u32;

    loop {
        let query = r#"
query Events($package: SuiAddress!, $cursor: String) {
  events(
    first: 50
    after: $cursor
    filter: { emittingModule: { package: $package } }
  ) {
    nodes {
      eventType { repr }
      json
      timestamp
      transaction { digest }
      checkpoint { sequenceNumber }
    }
    pageInfo { hasNextPage endCursor }
  }
}
"#;
        let variables = serde_json::json!({
            "package": package_id,
            "cursor": cursor,
        });

        let response = client
            .post(graphql_url)
            .json(&serde_json::json!({
                "query": query,
                "variables": variables,
            }))
            .send()
            .await
            .map_err(|e| format!("GraphQL request failed: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("GraphQL request failed: status={}, body={}", status, body));
        }

        let result: serde_json::Value = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse GraphQL response: {}", e))?;

        let events = match result
            .get("data")
            .and_then(|d| d.get("events"))
            .and_then(|e| e.get("nodes"))
            .and_then(|n| n.as_array())
        {
            Some(e) if !e.is_empty() => e,
            _ => break,
        };

        let mut processed_in_page = 0u64;
        let mut all_old_in_page = true;
        for event_node in events {
            let cp_seq = event_node
                .get("checkpoint")
                .and_then(|c| c.get("sequenceNumber"))
                .and_then(|s| s.as_u64())
                .unwrap_or(0);
            if cp_seq <= start_checkpoint {
                continue;
            }
            all_old_in_page = false;

            let event_type = event_node
                .get("eventType")
                .and_then(|t| t.get("repr"))
                .and_then(|r| r.as_str())
                .unwrap_or("");
            let json_data = event_node.get("json").cloned().unwrap_or(serde_json::Value::Null);

            if let Some(chain_event) = parse_chain_event(event_type, &json_data) {
                tracing::info!(
                    "[sui_listener] backfill_fallback event at cp={}: {:?}",
                    cp_seq,
                    chain_event
                );
                crate::relayer::process_event(
                    &state.relayer_state,
                    &config.fullnode_url,
                    &config.sui_package_id,
                    &chain_event,
                )
                .await;
                crate::relayer::apply_event_to_socket(state, &chain_event).await;
                total_events += 1;
                processed_in_page += 1;
            }
        }

        if all_old_in_page {
            consecutive_old_pages += 1;
            // 连续 5 页全是旧事件，认为已经追上
            if consecutive_old_pages >= 5 {
                tracing::info!(
                    "[sui_listener] backfill_fallback: 5 consecutive old pages, stopping"
                );
                break;
            }
        } else {
            consecutive_old_pages = 0;
        }

        let page_info = result
            .get("data")
            .and_then(|d| d.get("events"))
            .and_then(|e| e.get("pageInfo"));
        let has_next = page_info
            .and_then(|p| p.get("hasNextPage"))
            .and_then(|h| h.as_bool())
            .unwrap_or(false);
        cursor = page_info
            .and_then(|p| p.get("endCursor"))
            .and_then(|c| c.as_str())
            .map(|s| s.to_string());

        if !has_next {
            break;
        }
    }

    tracing::info!(
        "[sui_listener] backfill_fallback complete, {} events processed",
        total_events
    );
    Ok(total_events)
}

// ============================================================
// 启动入口 — 根据配置选择事件提供者
// ============================================================

/// 根据配置构建事件提供者
fn build_provider(config: &Config) -> SuiEventProvider {
    match config.sui_event_provider.as_str() {
        "grpc" => {
            tracing::info!("[sui_listener] using gRPC event provider");
            SuiEventProvider::Grpc
        }
        "inodra" | "webhook" => {
            tracing::info!("[sui_listener] using Inodra Webhook event provider");
            SuiEventProvider::InodraWebhook
        }
        "both" | "all" => {
            tracing::info!("[sui_listener] using Composite event provider (gRPC + Inodra)");
            SuiEventProvider::Both
        }
        other => {
            tracing::warn!("[sui_listener] unknown SUI_EVENT_PROVIDER '{}', defaulting to gRPC", other);
            SuiEventProvider::Grpc
        }
    }
}

/// 启动 Sui 事件监听器后台任务
pub async fn start_sui_listener(state: Arc<AppState>) {
    let config = state.config.clone();

    if config.sui_package_id.is_empty() {
        tracing::warn!("[sui_listener] SUI_PACKAGE_ID not configured, listener not started");
        return;
    }

    // 启动时回填历史事件
    let start_cursor = load_last_cursor();
    match backfill_historical_events(&config, &state, start_cursor).await {
        Ok((count, last_cursor)) => {
            if let Some(cursor) = last_cursor {
                save_last_cursor(&cursor);
            }
            tracing::info!("[sui_listener] initial backfill completed: {} events", count);
        }
        Err(e) => {
            tracing::error!("[sui_listener] initial backfill failed: {}", e);
        }
    }

    // 根据配置选择并启动事件提供者
    let provider = build_provider(&config);
    tracing::info!("[sui_listener] starting event provider: {}", provider.name());
    provider.run(&config, state).await;
}
