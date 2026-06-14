use std::sync::Arc;

use prost_types::value::Kind;
use sui_rpc::Client;
use sui_rpc::proto::sui::rpc::v2::SubscribeCheckpointsRequest;

use crate::config::Config;
use crate::handlers::AppState;
use crate::sui_events::{parse_chain_event, SuiChainEvent};

/// gRPC 订阅检查点流，过滤特定合约事件
pub async fn subscribe_checkpoints(
    config: &Config,
    state: Arc<AppState>,
) -> Result<(), String> {
    let package_id = &config.sui_package_id;
    if package_id.is_empty() {
        return Err("SUI_PACKAGE_ID not configured".to_string());
    }

    let grpc_url = &config.fullnode_url;
    tracing::info!("[sui_grpc] connecting to gRPC endpoint: {}", grpc_url);

    let mut client = Client::new(grpc_url.as_str())
        .map_err(|e| format!("Failed to create gRPC client: {}", e))?;

    let mut subscription_client = client.subscription_client();

    // SubscribeCheckpointsRequest 使用 Default 创建，并设置 read_mask 以获取交易和事件
    let read_mask = prost_types::FieldMask {
        paths: vec![
            "transactions.events".to_string(),
            "transactions.digest".to_string(),
            "sequence_number".to_string(),
            "summary.timestamp".to_string(),
        ],
    };
    let request = SubscribeCheckpointsRequest::default().with_read_mask(read_mask);

    tracing::info!("[sui_grpc] subscribing to checkpoint stream, filtering package {}", package_id);

    let response = subscription_client
        .subscribe_checkpoints(request)
        .await
        .map_err(|e| format!("Failed to subscribe checkpoints: {}", e))?;

    let mut stream = response.into_inner();

    tracing::info!("[sui_grpc] checkpoint stream established");

    while let Some(checkpoint_response) = stream
        .message()
        .await
        .map_err(|e| format!("Stream error: {}", e))?
    {
        let cursor = checkpoint_response.cursor.unwrap_or_default();

        if let Some(checkpoint) = checkpoint_response.checkpoint {
            let seq = checkpoint.sequence_number.unwrap_or_default();

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

                        // 过滤：只处理目标合约的事件
                        if !event_type.starts_with(&format!("{}::", package_id)) {
                            continue;
                        }

                        // 解析事件数据：优先使用 json 字段，回退到 BCS
                        let json_data = if let Some(json_val) = &event.json {
                            // 从 proto Value 转换
                            proto_value_to_serde(json_val)
                        } else {
                            // BCS 反序列化需要类型信息，无法通用解析
                            serde_json::Value::Null
                        };

                        if let Some(chain_event) = parse_chain_event(&event_type, &json_data) {
                            tracing::info!(
                                "[sui_grpc] event at checkpoint {}: {:?}",
                                seq,
                                chain_event
                            );
                            handle_grpc_event(chain_event, &state).await;
                        }
                    }
                }
            }
        }

        // 记录已处理的检查点（可用于断点续传）
        tracing::trace!("[sui_grpc] processed checkpoint {}", cursor);
    }

    tracing::warn!("[sui_grpc] checkpoint stream ended");
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

    loop {
        match subscribe_checkpoints(&config, state.clone()).await {
            Ok(()) => {
                tracing::warn!("[sui_grpc] stream ended normally, reconnecting...");
            }
            Err(e) => {
                tracing::error!("[sui_grpc] subscription error: {}, reconnecting in {:?}", e, retry_delay);
            }
        }

        tokio::time::sleep(retry_delay).await;
        retry_delay = (retry_delay * 2).min(max_retry_delay);
    }
}

async fn handle_grpc_event(event: SuiChainEvent, _state: &Arc<AppState>) {
    match &event {
        SuiChainEvent::PlayerJoined { table_id, player, buy_in, .. } => {
            tracing::info!(
                "[sui_grpc] PlayerJoined: table={}, player={}, buy_in={}",
                table_id, player, buy_in
            );
        }
        SuiChainEvent::PlayerLeft { table_id, player, .. } => {
            tracing::info!(
                "[sui_grpc] PlayerLeft: table={}, player={}",
                table_id, player
            );
        }
        SuiChainEvent::HandSettled { table_id, pot } => {
            tracing::info!(
                "[sui_grpc] HandSettled: table={}, pot={}",
                table_id, pot
            );
        }
        _ => {
            tracing::debug!("[sui_grpc] event: {:?}", event);
        }
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
