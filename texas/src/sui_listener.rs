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

/// 使用 Sui GraphQL RPC 回填历史事件
pub async fn backfill_historical_events(
    config: &Config,
    _state: &Arc<AppState>,
    last_checkpoint: u64,
) -> Result<u64, String> {
    let graphql_url = match config.sui_network.as_str() {
        "mainnet" => "https://graphql.mainnet.sui.io/graphql",
        "testnet" => "https://graphql.testnet.sui.io/graphql",
        "devnet" => "https://graphql.devnet.sui.io/graphql",
        _ => return Err(format!("Unknown sui_network: {}", config.sui_network)),
    };

    let package_id = &config.sui_package_id;
    if package_id.is_empty() {
        tracing::warn!("[sui_listener] SUI_PACKAGE_ID not configured, skipping backfill");
        return Ok(0);
    }

    tracing::info!(
        "[sui_listener] starting backfill from checkpoint {} for package {}",
        last_checkpoint,
        package_id
    );

    let client = reqwest::Client::new();
    let mut total_events = 0u64;
    let mut cursor: Option<String> = None;

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

        if !has_next {
            break;
        }

        cursor = page_info
            .and_then(|p| p.get("endCursor"))
            .and_then(|c| c.as_str())
            .map(|s| s.to_string());
    }

    tracing::info!("[sui_listener] backfill complete, {} events processed", total_events);
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
    match backfill_historical_events(&config, &state, 0).await {
        Ok(count) => {
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
