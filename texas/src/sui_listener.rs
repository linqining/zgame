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
    /// GraphQL Subscriptions（WebSocket，公共端点可用）
    GraphQLSubscriptions,
    /// GraphQL 轮询（HTTP，公共端点可用，最可靠）
    GraphQLPolling,
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
            SuiEventProvider::GraphQLSubscriptions => "GraphQLSubscriptions",
            SuiEventProvider::GraphQLPolling => "GraphQLPolling",
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
            SuiEventProvider::GraphQLSubscriptions => {
                crate::sui_graphql_sub::subscribe_with_reconnect(config.clone(), state).await;
            }
            SuiEventProvider::GraphQLPolling => {
                poll_events_loop(config.clone(), state).await;
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
            if trimmed.is_empty() {
                return None;
            }
            // GraphQL cursors are Base64-encoded strings. The legacy JSON-RPC
            // cursor format is "<base58_digest>:<event_seq>" which contains a
            // colon — not valid Base64, so the GraphQL endpoint rejects it with
            // "Invalid Base64". Discard stale cursors in the old format so we
            // restart backfill from the beginning instead of failing every run.
            if trimmed.contains(':') {
                tracing::warn!(
                    "[sui_listener] discarding stale non-GraphQL cursor: {}",
                    trimmed
                );
                return None;
            }
            Some(trimmed.to_string())
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
    // 事件类型锚定到原始 Package ID，升级后仍用 origin 过滤
    let origin_package_id = &config.sui_origin_package_id;
    if package_id.is_empty() {
        tracing::warn!("[sui_listener] SUI_PACKAGE_ID not configured, skipping backfill");
        return Ok((0, None));
    }

    tracing::info!(
        "[sui_listener] starting backfill from cursor {:?} for package {} (origin={})",
        start_cursor,
        package_id,
        origin_package_id
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
query Events($package: String!, $cursor: String) {
  events(
    first: 50
    after: $cursor
    filter: { module: $package }
  ) {
    nodes {
      contents {
        type { repr }
        json
      }
      timestamp
      transaction { digest }
    }
    pageInfo { hasNextPage endCursor }
  }
}
"#;

        let variables = serde_json::json!({
            "package": origin_package_id,
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

        // 检查 GraphQL 错误
        if let Some(errors) = result.get("errors") {
            tracing::warn!(
                "[sui_listener] backfill GraphQL returned errors: {:?}",
                errors
            );
            break;
        }

        let events = result
            .get("data")
            .and_then(|d| d.get("events"))
            .and_then(|e| e.get("nodes"))
            .and_then(|n| n.as_array());
        tracing::info!("[backfill_historical_events] GraphQL response: {:?}", result);
        let events = match events {
            Some(e) => e,
            None => {
                tracing::warn!(
                    "[sui_listener] no events found in GraphQL response, data={:?}",
                    result.get("data")
                );
                break;
            }
        };

        if events.is_empty() {
            break;
        }

        for event_node in events {
            let contents = event_node.get("contents");
            let event_type = contents
                .and_then(|c| c.get("type"))
                .and_then(|t| t.get("repr"))
                .and_then(|r| r.as_str())
                .unwrap_or("");

            let json_data = contents
                .and_then(|c| c.get("json"))
                .cloned()
                .unwrap_or(serde_json::Value::Null);

            if let Some(chain_event) = parse_chain_event(event_type, &json_data) {
                tracing::info!("[sui_listener] backfill event: {:?}", chain_event);
                let summary = crate::relayer::process_event(&config.fullnode_url, &config.sui_package_id, &chain_event).await;
                let tx_digest = event_node.get("transaction").and_then(|t| t.get("digest")).and_then(|d| d.as_str());
                crate::relayer::apply_event_to_socket(state, &chain_event, summary.as_ref(), tx_digest).await;
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

        // Task 17: 分页保存 cursor——每处理完一页就立即落盘，
        // 中途失败时已保存的 cursor 不回滚，下次启动从最后成功位置续传。
        if let Some(ref c) = cursor {
            save_last_cursor(c);
        }

        if !has_next {
            break;
        }
    }

    tracing::info!("[sui_listener] backfill complete, {} events processed", total_events);
    Ok((total_events, last_cursor))
}

// ============================================================
// GraphQL 轮询 provider（公共端点可用，无需 gRPC/Subscriptions）
// ============================================================

/// GraphQL 轮询主循环：持续拉取新事件，cursor 持久化，断线自动重试。
///
/// 与 `backfill_historical_events` 的区别：
/// - backfill 是一次性拉取所有历史事件直到追上最新
/// - 本函数是持续运行的后台任务，追上最新后按 `sui_tick_interval_ms` 间隔轮询新事件
/// - 有积压事件时立即查下一页（不 sleep），无事件时才等待
pub async fn poll_events_loop(config: Config, state: Arc<AppState>) {
    let origin_package_id = &config.sui_origin_package_id;
    if origin_package_id.is_empty() {
        tracing::error!("[sui_graphql_poll] SUI_ORIGIN_PACKAGE_ID not configured, polling stopped");
        return;
    }

    let graphql_url = match config.sui_network.as_str() {
        "mainnet" => "https://graphql.mainnet.sui.io/graphql",
        "testnet" => "https://graphql.testnet.sui.io/graphql",
        "devnet" => "https://graphql.devnet.sui.io/graphql",
        other => {
            tracing::error!("[sui_graphql_poll] unknown sui_network: {}", other);
            return;
        }
    };

    let poll_interval = std::time::Duration::from_millis(config.sui_tick_interval_ms.max(2000));
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("[sui_graphql_poll] failed to build HTTP client for GraphQL polling: {}", e);
            return;
        }
    };

    // 从上次保存的 cursor 继续
    let mut cursor = load_last_cursor();
    let mut poll_count: u64 = 0;
    tracing::info!(
        "[sui_graphql_poll] starting polling for package {} (origin={}) from cursor {:?}, interval {:?}",
        config.sui_package_id,
        origin_package_id,
        cursor,
        poll_interval
    );

    let query = r#"
query Events($package: String!, $cursor: String) {
  events(
    first: 50
    after: $cursor
    filter: { module: $package }
  ) {
    nodes {
      contents {
        type { repr }
        json
      }
      timestamp
      transaction { digest }
    }
    pageInfo { hasNextPage endCursor }
  }
}
"#;

    loop {
        poll_count += 1;
        let variables = serde_json::json!({
            "package": origin_package_id,
            "cursor": cursor,
        });

        let response = match client
            .post(graphql_url)
            .json(&serde_json::json!({
                "query": query,
                "variables": variables,
            }))
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    "[sui_graphql_poll] request failed: {}, retrying in {:?}",
                    e,
                    poll_interval
                );
                tokio::time::sleep(poll_interval).await;
                continue;
            }
        };

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            tracing::warn!(
                "[sui_graphql_poll] HTTP {}: {}, retrying in {:?}",
                status,
                body.chars().take(200).collect::<String>(),
                poll_interval
            );
            tokio::time::sleep(poll_interval).await;
            continue;
        }

        let result: serde_json::Value = match response.json().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    "[sui_graphql_poll] failed to parse response: {}, retrying in {:?}",
                    e,
                    poll_interval
                );
                tokio::time::sleep(poll_interval).await;
                continue;
            }
        };

        // GraphQL 错误
        if let Some(errors) = result.get("errors") {
            tracing::warn!("[sui_graphql_poll] GraphQL errors: {:?}", errors);
            tokio::time::sleep(poll_interval).await;
            continue;
        }

        let events_data = match result
            .get("data")
            .and_then(|d| d.get("events"))
        {
            Some(e) => e,
            None => {
                tracing::warn!(
                    "[sui_graphql_poll] missing data.events in response, retrying in {:?}",
                    poll_interval
                );
                tokio::time::sleep(poll_interval).await;
                continue;
            }
        };

        let nodes = events_data
            .get("nodes")
            .and_then(|n| n.as_array())
            .map(|a| a.as_slice())
            .unwrap_or(&[]);

        let page_info = events_data.get("pageInfo");
        let has_next = page_info
            .and_then(|p| p.get("hasNextPage"))
            .and_then(|h| h.as_bool())
            .unwrap_or(false);
        let next_cursor = page_info
            .and_then(|p| p.get("endCursor"))
            .and_then(|c| c.as_str())
            .map(|s| s.to_string());

        // 处理本页事件
        let mut processed = 0u64;
        for event_node in nodes {
            let contents = event_node.get("contents");
            let event_type = contents
                .and_then(|c| c.get("type"))
                .and_then(|t| t.get("repr"))
                .and_then(|r| r.as_str())
                .unwrap_or("");

            let json_data = contents
                .and_then(|c| c.get("json"))
                .cloned()
                .unwrap_or(serde_json::Value::Null);

            if let Some(chain_event) = parse_chain_event(event_type, &json_data) {
                tracing::info!("[sui_graphql_poll] event: {:?}", chain_event);
                let summary = crate::relayer::process_event(
                    &config.fullnode_url,
                    &config.sui_package_id,
                    &chain_event,
                )
                .await;
                let tx_digest = event_node.get("transaction").and_then(|t| t.get("digest")).and_then(|d| d.as_str());
                crate::relayer::apply_event_to_socket(&state, &chain_event, summary.as_ref(), tx_digest)
                    .await;
                processed += 1;
            }
        }

        // 更新并持久化 cursor
        if let Some(ref c) = next_cursor {
            cursor = Some(c.clone());
            save_last_cursor(c);
        }

        if processed > 0 {
            tracing::info!(
                "[sui_graphql_poll] processed {} events, has_next={}, cursor={:?}",
                processed,
                has_next,
                cursor
            );
        } else if poll_count % 12 == 0 {
            // 约每分钟输出一次心跳，确认轮询在正常运行
            tracing::info!(
                "[sui_graphql_poll] heartbeat: poll #{}, no new events, cursor={:?}",
                poll_count,
                cursor
            );
        }

        // 有下一页时立即继续（处理积压），否则等待轮询间隔
        if !has_next {
            tokio::time::sleep(poll_interval).await;
        }
    }
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
    let origin_package_id = &config.sui_origin_package_id;
    if package_id.is_empty() {
        tracing::warn!("[sui_listener] SUI_PACKAGE_ID not configured, skipping backfill_from_checkpoint");
        return Ok(0);
    }

    tracing::info!(
        "[sui_listener] backfill_from_checkpoint: starting from checkpoint > {} for package {} (origin={})",
        start_checkpoint,
        package_id,
        origin_package_id
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;
    let mut total_events = 0u64;
    let mut cursor: Option<String> = None;

    loop {
        // Sui GraphQL RPC schema:
        //   EventFilter: { module: String, afterCheckpoint: UInt53, type: String, ... }
        //   Event.contents: MoveValue { json: JSON, type: MoveType { repr: String } }
        //   u64/u128/u256 在 JSON 中表示为字符串，parse_chain_event 需兼容
        let query = r#"
query Events($module: String!, $cursor: String, $afterCheckpoint: UInt53) {
  events(
    first: 50
    after: $cursor
    filter: { module: $module, afterCheckpoint: $afterCheckpoint }
  ) {
    nodes {
      contents {
        type { repr }
        json
      }
      timestamp
      transaction { digest }
    }
    pageInfo { hasNextPage endCursor }
  }
}
"#;

        let variables = serde_json::json!({
            "module": origin_package_id,
            "cursor": cursor,
            "afterCheckpoint": start_checkpoint,
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

        tracing::info!("[backfill_from_checkpoint] GraphQL response: {:?}", result);

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
            // 事件类型在 contents.type.repr
            let event_type = event_node
                .get("contents")
                .and_then(|c| c.get("type"))
                .and_then(|t| t.get("repr"))
                .and_then(|r| r.as_str())
                .unwrap_or("");

            // 事件 JSON 数据在 contents.json
            let json_data = event_node
                .get("contents")
                .and_then(|c| c.get("json"))
                .cloned()
                .unwrap_or(serde_json::Value::Null);

            if let Some(chain_event) = parse_chain_event(event_type, &json_data) {
                tracing::info!(
                    "[sui_listener] backfill_from_checkpoint event: {:?}",
                    chain_event
                );
                let summary = crate::relayer::process_event(
                    &config.fullnode_url,
                    &config.sui_package_id,
                    &chain_event,
                )
                .await;
                let tx_digest = event_node.get("transaction").and_then(|t| t.get("digest")).and_then(|d| d.as_str());
                crate::relayer::apply_event_to_socket(state, &chain_event, summary.as_ref(), tx_digest).await;
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

    let _package_id = &config.sui_package_id;
    let origin_package_id = &config.sui_origin_package_id;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

    let mut total_events = 0u64;
    let mut cursor: Option<String> = None;

    loop {
        let query = r#"
query Events($module: String!, $cursor: String) {
  events(
    first: 50
    after: $cursor
    filter: { module: $module }
  ) {
    nodes {
      contents {
        type { repr }
        json
      }
      timestamp
      transaction { digest }
    }
    pageInfo { hasNextPage endCursor }
  }
}
"#;
        let variables = serde_json::json!({
            "module": origin_package_id,
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
        for event_node in events {
            // 事件类型在 contents.type.repr
            let event_type = event_node
                .get("contents")
                .and_then(|c| c.get("type"))
                .and_then(|t| t.get("repr"))
                .and_then(|r| r.as_str())
                .unwrap_or("");

            // 事件 JSON 数据在 contents.json
            let json_data = event_node
                .get("contents")
                .and_then(|c| c.get("json"))
                .cloned()
                .unwrap_or(serde_json::Value::Null);

            if let Some(chain_event) = parse_chain_event(event_type, &json_data) {
                tracing::info!(
                    "[sui_listener] backfill_fallback event: {:?}",
                    chain_event
                );
                let summary = crate::relayer::process_event(
                    &config.fullnode_url,
                    &config.sui_package_id,
                    &chain_event,
                )
                .await;
                let tx_digest = event_node.get("transaction").and_then(|t| t.get("digest")).and_then(|d| d.as_str());
                crate::relayer::apply_event_to_socket(state, &chain_event, summary.as_ref(), tx_digest).await;
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
        "graphql_sub" | "graphql-sub" | "graphql_subscriptions" => {
            tracing::info!("[sui_listener] using GraphQL Subscriptions event provider");
            SuiEventProvider::GraphQLSubscriptions
        }
        "graphql_poll" | "graphql-poll" | "graphql_polling" => {
            tracing::info!("[sui_listener] using GraphQL Polling event provider");
            SuiEventProvider::GraphQLPolling
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
        Ok((count, _last_cursor)) => {
            // Task 17: cursor 已在 backfill 循环内分页保存，
            // 中途失败时已保存的 cursor 不回滚，此处无需再保存。
            tracing::info!("[sui_listener] initial backfill completed: {} events", count);
        }
        Err(e) => {
            tracing::error!("[sui_listener] initial backfill failed: {}", e);
        }
    }

    // 启动后拉取全量桌子的 TableSummaryV2 快照，同步到内存 table.summary
    // （包括 crypto 字段），建立内存与链上状态的初始一致性
    crate::relayer::sync_all_tables_from_chain(&state).await;

    // 根据配置选择并启动事件提供者
    let provider = build_provider(&config);
    tracing::info!("[sui_listener] starting event provider: {}", provider.name());
    provider.run(&config, state).await;
}
