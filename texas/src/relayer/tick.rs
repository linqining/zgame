use std::sync::Arc;
use std::time::Duration;

use crate::handlers::AppState;
use crate::relayer::submit;

/// 定时 tick 循环：周期性遍历所有缓存的 table，根据 `sui_on_chain_enabled` 分发到
/// 链上模式（调用 `submit_tick_tx`）或本地模式（调用 `process_tick`）。
pub async fn run_tick_loop(state: Arc<AppState>) {
    // G12 修复：校验 interval_ms > 0，否则使用默认值 5000，避免忙循环
    let interval_ms = if state.config.sui_tick_interval_ms == 0 {
        tracing::warn!(
            "[relayer::tick] sui_tick_interval_ms=0 would cause busy loop, falling back to 5000ms"
        );
        5000
    } else {
        state.config.sui_tick_interval_ms
    };
    // 配置不会运行时改变，循环外读取一次即可
    let on_chain_enabled = state.config.sui_on_chain_enabled;

    if on_chain_enabled {
        tracing::info!(
            "[relayer::tick] starting tick loop in ON-CHAIN mode, interval={}ms",
            interval_ms
        );
    } else {
        tracing::info!(
            "[relayer::tick] starting tick loop in OFF-CHAIN mode, interval={}ms",
            interval_ms
        );
    }

    loop {
        // 睡眠指定间隔
        tokio::time::sleep(Duration::from_millis(interval_ms)).await;

        if on_chain_enabled {
            // ===== 上链模式：遍历 relayer 缓存的 table_id，调用 submit_tick_tx =====
            let table_ids = state.relayer_state.list_ids();

            if table_ids.is_empty() {
                continue;
            }

            tracing::debug!("[relayer::tick] processing {} tables (on-chain)", table_ids.len());

            for table_id in table_ids {
                // F16 修复：更精细的 needs_tick 判断，减少不必要的链上 tick 交易
                // - active_count >= 2：至少 2 个活跃玩家
                // - round_state != 0：非 Waiting 状态
                // - round_state != 13：非 HandComplete 状态（hand_complete_wait 由 game loop 处理）
                // - current_turn.is_some()：有当前行动玩家（需要超时自动 fold）
                //   或处于 reveal/reconstruct 阶段（可能需要超时推进）
                let needs_tick = {
                    let summary = state.relayer_state.get(&table_id);
                    match summary {
                        Some(s) => {
                            let rs = s.meta.round_state;
                            s.meta.active_count >= 2
                                && rs != 0
                                && rs != 13
                                && (s.meta.current_turn.is_some()
                                    || rs == 2 || rs == 3 || rs == 4 || rs == 5
                                    || rs == 7 || rs == 9 || rs == 11)
                        }
                        None => false,
                    }
                };

                if !needs_tick {
                    tracing::trace!(
                        "[relayer::tick] skip table={}, no tick needed (round_state=0 or active_count<2)",
                        table_id
                    );
                    continue;
                }

                match submit::submit_tick_tx(&state.config, &table_id).await {
                    Ok(digest) => {
                        tracing::info!(
                            "[relayer::tick] tick success for table={}, digest={}",
                            table_id,
                            digest
                        );
                    }
                    Err(e) => {
                        // 单次 tick 失败时记录 warn 日志并继续下一个 table，不中断循环
                        tracing::warn!(
                            "[relayer::tick] tick failed for table={}: {}",
                            table_id,
                            e
                        );
                    }
                }
            }
        } else {
            // ===== 不上链模式：遍历本地 socket table，调用 process_tick =====
            let table_ids: Vec<u32> = {
                let gs = state.socket_state.state.read().await;
                gs.tables.keys().copied().collect()
            };

            if table_ids.is_empty() {
                continue;
            }

            tracing::debug!("[relayer::tick] processing {} tables (off-chain)", table_ids.len());

            let io = match crate::socket::get_socket_io() {
                Some(io) => io,
                None => {
                    tracing::warn!(
                        "[relayer::tick] socket io not available, skipping local tick"
                    );
                    continue;
                }
            };

            for table_id in table_ids {
                // 本地超时判断 + 状态推进，不产生任何链上交易
                crate::socket::game_loop::process_tick(&io, &state.socket_state, table_id).await;
            }
        }
    }
}
