use std::sync::Arc;

use prost_types::value::Kind;
use sui_rpc::Client;
use sui_rpc::client::HeadersInterceptor;
use sui_rpc::proto::sui::rpc::v2::SubscribeCheckpointsRequest;

use crate::config::Config;
use crate::handlers::AppState;
use crate::sui_events::parse_chain_event;

/// gRPC 订阅检查点流，过滤特定合约事件
pub async fn subscribe_checkpoints(
    config: &Config,
    state: Arc<AppState>,
    last_checkpoint: Arc<std::sync::atomic::AtomicU64>,
) -> Result<(), String> {
    let package_id = &config.sui_package_id;
    // 事件类型锚定到原始 Package ID，升级后仍用 origin 过滤
    let origin_package_id = &config.sui_origin_package_id;
    if package_id.is_empty() {
        return Err("SUI_PACKAGE_ID not configured".to_string());
    }

    let grpc_url = &config.grpc_url;
    tracing::warn!("[sui_grpc] connecting to gRPC endpoint: {}", grpc_url);

    let client = Client::new(grpc_url.as_str())
        .map_err(|e| format!("Failed to create gRPC client: {}", e))?;

    // BlockPi/Chainstack/QuickNode 等付费节点需要 x-token 认证
    let mut client = client;
    if !config.grpc_token.is_empty() {
        let mut headers = HeadersInterceptor::new();
        let token_value = tonic::metadata::MetadataValue::try_from(config.grpc_token.as_str())
            .map_err(|e| format!("GRPC_TOKEN contains invalid characters for gRPC header: {}", e))?;
        headers.headers_mut().insert("x-token", token_value);
        client = client.with_headers(headers);
        let masked = if config.grpc_token.len() > 8 {
            format!("{}...{}", &config.grpc_token[..4], &config.grpc_token[config.grpc_token.len()-4..])
        } else {
            "***".to_string()
        };
        tracing::info!("[sui_grpc] x-token authentication enabled (token={})", masked);
    } else {
        tracing::warn!("[sui_grpc] no GRPC_TOKEN set, connecting without authentication");
    }

    let mut subscription_client = client.subscription_client();

    // SubscribeCheckpointsRequest 使用 Default 创建，并设置 read_mask 以获取交易和事件
    // 注意：FieldMask 路径必须精确对应 proto 字段层级。
    //   Checkpoint.transactions (Vec<Transaction>)
    //     -> Transaction.events (Option<TxEvents>)
    //       -> TxEvents.events (Vec<Event>)
    //         -> Event.event_type / json / contents
    // 直接请求 "transactions.events" 会返回整个 TxEvents 子消息（含全部 Event 及其字段）。
    // 不要使用 "transactions.events.event_type" 这样的路径——它跳过了 TxEvents.events
    // 这一层，Chainstack 等严格遵循 FieldMask 的节点会判定为无效路径而不填充 events 字段，
    // 导致 tx.events 永远为 None（公共 testnet 节点会宽容地忽略无效路径，所以表现不同）。
    let read_mask = prost_types::FieldMask {
        paths: vec![
            "digest".to_string(),
            "transactions.events".to_string(),
            "transactions.digest".to_string(),
            "sequence_number".to_string(),
            "summary.timestamp".to_string(),
        ],
    };
    let request = SubscribeCheckpointsRequest::default().with_read_mask(read_mask);

    let start_cp = last_checkpoint.load(std::sync::atomic::Ordering::SeqCst);
    tracing::warn!("[sui_grpc] subscribing to checkpoint stream (last processed={}), filtering package {}", start_cp, package_id);

    let response = subscription_client
        .subscribe_checkpoints(request)
        .await
        .map_err(|e| format!("Failed to subscribe checkpoints: {}", e))?;

    let mut stream = response.into_inner();

    tracing::warn!("[sui_grpc] checkpoint stream established");

    while let Some(checkpoint_response) = stream
        .message()
        .await
        .map_err(|e| format!("Stream error: {}", e))?
    {
        let cursor = checkpoint_response.cursor.unwrap_or_default();

        if let Some(checkpoint) = checkpoint_response.checkpoint {
            let seq = checkpoint.sequence_number.unwrap_or_default();
            let tx_count = checkpoint.transactions.len();
            let event_count: usize = checkpoint
                .transactions
                .iter()
                .map(|tx| tx.events.as_ref().map(|e| e.events.len()).unwrap_or(0))
                .sum();
            // tracing::info!(
            //     "[sui_grpc] checkpoint #{}: {} transactions, {} events",
            //     seq, tx_count, event_count
            // );

            // 遍历检查点中的所有交易
            for tx in &checkpoint.transactions {
                // 获取交易事件
                if let Some(tx_events) = &tx.events {
                    for event in &tx_events.events {
                        // 获取事件类型
                        let event_type = match &event.event_type {
                            Some(t) => t.clone(),
                            None => continue,
                        };

                        // 过滤：只处理目标合约的事件（事件类型锚定到原始 Package ID）
                        if !event_type.starts_with(&format!("{}::", origin_package_id)) {
                            continue;
                        }
                        tracing::info!("[sui_grpc] event type from package: {}", event_type);

                        // 解析事件数据：优先使用 json 字段，回退到 BCS
                        let json_data = if let Some(json_val) = &event.json {
                            // 从 proto Value 转换
                            proto_value_to_serde(json_val)
                        } else if let Some(bcs_data) = &event.contents {
                            // json 字段未由服务端填充，尝试 BCS 反序列化
                            if let Some(bytes) = &bcs_data.value {
                                match crate::sui_events::parse_bcs_event(&event_type, bytes) {
                                    Some(v) => v,
                                    None => {
                                        tracing::warn!(
                                            "[sui_grpc] BCS parse failed for event '{}', bytes_len={}",
                                            event_type, bytes.len()
                                        );
                                        serde_json::Value::Null
                                    }
                                }
                            } else {
                                serde_json::Value::Null
                            }
                        } else {
                            serde_json::Value::Null
                        };

                        if let Some(chain_event) = parse_chain_event(&event_type, &json_data) {
                            tracing::warn!(
                                "[sui_grpc] event at checkpoint {}: {:?}",
                                seq,
                                chain_event
                            );
                            let tx_digest = tx.digest.as_deref().filter(|s| !s.is_empty());
                            crate::relayer::dispatch::handle_parsed_chain_event(
                                &state,
                                &chain_event,
                                tx_digest,
                                "sui_grpc",
                            )
                            .await;
                        }
                    }
                }
            }

            // 记录已处理的检查点（可用于断点续传）
            last_checkpoint.store(seq, std::sync::atomic::Ordering::SeqCst);
            // tracing::warn!("[sui_grpc] processed checkpoint {}", seq);
        } else {
            // checkpoint 为空时回退使用 cursor
            last_checkpoint.store(cursor, std::sync::atomic::Ordering::SeqCst);
            // tracing::warn!("[sui_grpc] processed checkpoint {}", cursor);
        }
    }

    // tracing::warn!("[sui_grpc] checkpoint stream ended");
    Ok(())
}

/// 将 prost_types::Value 转换为 serde_json::Value
fn proto_value_to_serde(val: &prost_types::Value) -> serde_json::Value {
    match &val.kind {
        Some(Kind::NullValue(_)) => serde_json::Value::Null,
        Some(Kind::BoolValue(b)) => serde_json::Value::Bool(*b),
        Some(Kind::NumberValue(n)) => {
            if *n == (*n as i64 as f64) {
                serde_json::Value::Number(serde_json::Number::from(*n as i64))
            } else {
                serde_json::Number::from_f64(*n)
                    .map(serde_json::Value::Number)
                    .unwrap_or(serde_json::Value::Null)
            }
        }
        Some(Kind::StringValue(s)) => {
            // 事件 JSON 可能是嵌套的 JSON 字符串，尝试解析
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(s) {
                parsed
            } else {
                serde_json::Value::String(s.clone())
            }
        }
        Some(Kind::StructValue(struct_val)) => {
            let mut map = serde_json::Map::new();
            for (key, value) in &struct_val.fields {
                map.insert(key.clone(), proto_value_to_serde(value));
            }
            serde_json::Value::Object(map)
        }
        Some(Kind::ListValue(list_val)) => {
            let arr: Vec<serde_json::Value> = list_val
                .values
                .iter()
                .map(proto_value_to_serde)
                .collect();
            serde_json::Value::Array(arr)
        }
        None => serde_json::Value::Null,
    }
}

/// 带自动重连的 gRPC 订阅
pub async fn subscribe_with_reconnect(config: Config, state: Arc<AppState>) {
    let mut retry_delay = std::time::Duration::from_secs(1);
    let max_retry_delay = std::time::Duration::from_secs(60);
    let last_checkpoint = Arc::new(std::sync::atomic::AtomicU64::new(0));

    loop {
        // 记录调用前的 checkpoint，用于判断本次调用是否取得进展
        let cp_before = last_checkpoint.load(std::sync::atomic::Ordering::SeqCst);

        match subscribe_checkpoints(&config, state.clone(), last_checkpoint.clone()).await {
            Ok(()) => {
                let cp = last_checkpoint.load(std::sync::atomic::Ordering::SeqCst);
                tracing::warn!(
                    "[sui_grpc] stream ended normally at checkpoint {}, reconnecting...",
                    cp
                );
                // 正常结束后也尝试 backfill，避免最后一段事件丢失
                if cp > 0 {
                    tracing::info!(
                        "[sui_grpc] backfilling from checkpoint {} before reconnecting...",
                        cp
                    );
                    if let Err(e) = crate::sui_listener::backfill_from_checkpoint(
                        &config,
                        &state,
                        cp,
                    )
                    .await
                    {
                        tracing::error!("[sui_grpc] backfill after normal end failed: {}", e);
                    }
                }
                // G13 修复：成功结束后重置 retry_delay，避免正常断连后也使用退避后的长延迟
                retry_delay = std::time::Duration::from_secs(1);
            }
            Err(e) => {
                let cp = last_checkpoint.load(std::sync::atomic::Ordering::SeqCst);
                tracing::error!(
                    "[sui_grpc] subscription error at checkpoint {}: {}, reconnecting in {:?}",
                    cp, e, retry_delay
                );
                // 若断连前已成功推进 checkpoint，说明连接本身是通的，
                // 此次错误属于短暂网络抖动，重置退避避免不必要的长延迟。
                if cp > cp_before {
                    retry_delay = std::time::Duration::from_secs(1);
                }
                // C1 修复：重连前先 backfill 断连期间丢失的事件
                if cp > 0 {
                    tracing::info!(
                        "[sui_grpc] backfilling from checkpoint {} before reconnecting...",
                        cp
                    );
                    if let Err(e) = crate::sui_listener::backfill_from_checkpoint(
                        &config,
                        &state,
                        cp,
                    )
                    .await
                    {
                        tracing::error!("[sui_grpc] backfill failed: {}", e);
                    }
                }
            }
        }

        tokio::time::sleep(retry_delay).await;
        retry_delay = (retry_delay * 2).min(max_retry_delay);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sui_rpc::Client;
    use sui_rpc::proto::sui::rpc::v2::SubscribeCheckpointsRequest;

    /// 测试 gRPC 连接和 checkpoint 订阅
    /// 使用 DeepBook V3 testnet 合约（交易量最大的 Sui DeFi 协议）
    /// 运行方式: cargo test --package texas -- sui_grpc::tests::test_grpc_checkpoint_stream --nocapture --ignored
    #[tokio::test]
    #[ignore] // 需要网络连接，默认跳过
    async fn test_grpc_checkpoint_stream() {
        let _ = tracing_subscriber::fmt::try_init();

        let grpc_url = "https://fullnode.testnet.sui.io:443";
        // DeepBook V3 testnet package ID（Sui 上交易量最大的 DeFi 协议）
        let deepbook_package_id = "0x22be4cade64bf2d02412c7e8d0e8beea2f78828b948118d46735315409371a3c";

        tracing::info!("[test] connecting to gRPC: {}", grpc_url);

        let mut client = Client::new(grpc_url)
            .expect("Failed to create gRPC client");

        let mut subscription_client = client.subscription_client();
        let read_mask = prost_types::FieldMask {
            paths: vec![
                "transactions.events".to_string(),
                "transactions.digest".to_string(),
                "sequence_number".to_string(),
                "summary.timestamp".to_string(),
            ],
        };
        let request = SubscribeCheckpointsRequest::default().with_read_mask(read_mask);

        let response = subscription_client
            .subscribe_checkpoints(request)
            .await
            .expect("Failed to subscribe checkpoints");

        let mut stream = response.into_inner();

        tracing::info!("[test] checkpoint stream established, waiting for events from DeepBook...");

        let mut total_checkpoints = 0u64;
        let mut total_events = 0u64;
        let mut deepbook_events = 0u64;
        let max_checkpoints = 2000; // 最多等待 20 个检查点

        while let Some(checkpoint_response) = stream
            .message()
            .await
            .expect("Stream error")
        {
            total_checkpoints += 1;

            if let Some(checkpoint) = checkpoint_response.checkpoint {
                let seq = checkpoint.sequence_number.unwrap_or_default();
                let tx_count = checkpoint.transactions.len();

                tracing::info!(
                    "[test] checkpoint #{}: {} transactions",
                    seq, tx_count
                );

                for tx in &checkpoint.transactions {
                    if let Some(tx_events) = &tx.events {
                        for event in &tx_events.events {
                            total_events += 1;

                            let event_type = match &event.event_type {
                                Some(t) => t.clone(),
                                None => continue,
                            };
                            println!("{:?}", event_type);
                            // 过滤 DeepBook 事件
                            if event_type.starts_with(&format!("{}::", deepbook_package_id)) {
                                deepbook_events += 1;

                                let json_data = if let Some(json_val) = &event.json {
                                    proto_value_to_serde(json_val)
                                } else {
                                    serde_json::Value::Null
                                };

                                // 提取事件名称（最后一个 :: 后的部分）
                                let event_name = event_type.rsplit("::").next().unwrap_or("unknown");

                                tracing::info!(
                                    "[test] DeepBook event #{}: {} | data: {}",
                                    deepbook_events,
                                    event_name,
                                    serde_json::to_string_pretty(&json_data).unwrap_or_default()
                                );
                            }
                        }
                    }
                }
            }

            if total_checkpoints >= max_checkpoints {
                tracing::info!("[test] reached max checkpoints ({}), stopping", max_checkpoints);
                break;
            }
        }

        tracing::info!(
            "[test] summary: {} checkpoints, {} total events, {} DeepBook events",
            total_checkpoints, total_events, deepbook_events
        );

        // 至少应该收到 1 个检查点
        assert!(total_checkpoints > 0, "Should receive at least 1 checkpoint");
    }

    /// 测试 proto_value_to_serde 转换函数
    #[test]
    fn test_proto_value_to_serde() {
        // 测试 null
        let null_val = prost_types::Value { kind: Some(Kind::NullValue(0)) };
        assert!(proto_value_to_serde(&null_val).is_null());

        // 测试 bool
        let bool_val = prost_types::Value { kind: Some(Kind::BoolValue(true)) };
        assert_eq!(proto_value_to_serde(&bool_val), serde_json::Value::Bool(true));

        // 测试整数
        let int_val = prost_types::Value { kind: Some(Kind::NumberValue(42.0)) };
        assert_eq!(
            proto_value_to_serde(&int_val),
            serde_json::Value::Number(serde_json::Number::from(42))
        );

        // 测试字符串
        let str_val = prost_types::Value { kind: Some(Kind::StringValue("hello".to_string())) };
        assert_eq!(
            proto_value_to_serde(&str_val),
            serde_json::Value::String("hello".to_string())
        );

        // 测试嵌套 JSON 字符串
        let json_str_val = prost_types::Value {
            kind: Some(Kind::StringValue(r#"{"key":"value"}"#.to_string())),
        };
        let result = proto_value_to_serde(&json_str_val);
        assert_eq!(result["key"], serde_json::Value::String("value".to_string()));

        // 测试 struct
        let struct_val = prost_types::Value {
            kind: Some(Kind::StructValue(prost_types::Struct {
                fields: [
                    ("name".to_string(), prost_types::Value {
                        kind: Some(Kind::StringValue("test".to_string())),
                    }),
                    ("amount".to_string(), prost_types::Value {
                        kind: Some(Kind::NumberValue(100.0)),
                    }),
                ].into_iter().collect(),
            })),
        };
        let result = proto_value_to_serde(&struct_val);
        assert_eq!(result["name"], serde_json::Value::String("test".to_string()));
        assert_eq!(result["amount"], serde_json::Value::Number(serde_json::Number::from(100)));

        // 测试 list
        let list_val = prost_types::Value {
            kind: Some(Kind::ListValue(prost_types::ListValue {
                values: vec![
                    prost_types::Value { kind: Some(Kind::NumberValue(1.0)) },
                    prost_types::Value { kind: Some(Kind::NumberValue(2.0)) },
                    prost_types::Value { kind: Some(Kind::NumberValue(3.0)) },
                ],
            })),
        };
        let result = proto_value_to_serde(&list_val);
        assert_eq!(result.as_array().unwrap().len(), 3);
    }
}
