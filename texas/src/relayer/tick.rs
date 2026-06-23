use std::sync::Arc;
use std::time::Duration;

use crate::handlers::AppState;
use crate::relayer::submit;

/// sui_tick_interval_ms 为 0 时的兜底间隔（毫秒）。
const TICK_FALLBACK_INTERVAL_MS: u64 = 50000;

/// 定时 tick 循环：周期性遍历所有缓存的 table，根据 `sui_on_chain_enabled` 分发到
/// 链上模式（调用 `submit_tick_tx`）或本地模式（调用 `process_tick`）。
pub async fn run_tick_loop(state: Arc<AppState>) {
    // G12 修复：校验 interval_ms > 0，否则使用默认值 5000，避免忙循环
    let interval_ms = if state.config.sui_tick_interval_ms == 0 {
        tracing::warn!(
            "[relayer::tick] sui_tick_interval_ms=0 would cause busy loop, falling back to 5000ms"
        );
        TICK_FALLBACK_INTERVAL_MS //todo 先这样好调试
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
        return;
    }

    loop {
        // 睡眠指定间隔
        tokio::time::sleep(Duration::from_millis(interval_ms)).await;

        if on_chain_enabled {
            // ===== 上链模式：从 GameState.tables 读取所有已绑定 chain_table_id 的 table =====
            // 注意：内存中的 summary 可能滞后（relayer 尚未处理 PlayerLeft 事件），
            // 因此在 needs_tick 判断前从链上拉取最新 TableSummaryV2。
            let chain_tables: Vec<String> = {
                let gs = state.socket_state.state.read().await;
                gs.tables.values()
                    .filter_map(|t| t.chain_table_id.clone())
                    .collect()
            };

            if chain_tables.is_empty() {
                continue;
            }

            for table_id in chain_tables {
                // 从链上拉取最新 summary，避免内存缓存滞后导致 tick 误判
                let summary = match crate::sui_query::fetch_table_summary(
                    &state.config.fullnode_url,
                    &state.config.sui_package_id,
                    &table_id,
                ).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(
                            "[relayer::tick] fetch_table_summary failed for table={}: {}",
                            table_id, e
                        );
                        continue;
                    }
                };
                // needs_tick 判断：对齐 Move 合约 tick 函数的处理范围。
                //
                // Move tick 函数优先处理以下阶段（不检查 active_count）：
                //   1. reconstruct_state.phase != none（reconstruct 进行中）
                //   2. shuffle_state.phase == reconstruct(2) || before_preflop(3)
                //   3. reveal_token_state.reveal_phase != none（reveal 进行中）
                // 然后处理正常逻辑（需要 active_count >= 2 才能开始手牌）：
                //   - round_waiting：检查是否可以 do_start_hand
                //   - is_betting_round：检查下注超时
                //   - round_showdown：检查是否可以 settle_hand
                //
                // 因此 needs_tick 分两部分：
                //   A) shuffle/reveal/reconstruct 阶段活跃 → 无需 active_count >= 2
                //   B) 正常游戏阶段 → 需要 active_count >= 2 且 round_state 有效
                let needs_tick = {
                    // A) shuffle/reveal/reconstruct 阶段（对齐 Move tick 优先处理逻辑）
                    let in_reconstruct = summary.state.reconstruct_phase != 0;
                    let in_shuffle = summary.state.shuffle_pending_count > 0
                        || summary.state.shuffle_completed_count > 0;
                    // shuffle_current_shuffler.is_some() 表示洗牌进行中
                    let shuffle_active = summary.state.shuffle_current_shuffler.is_some()
                        || in_shuffle;
                    let reveal_active = summary.state.reveal_phase != 0;

                    // active_count == 0 表示桌上没有活跃玩家，无论什么阶段都不需要 tick。
                    // 修复：之前 shuffle_completed_count > 0 会导致 shuffle_active = true，
                    // 即使所有玩家已离开（active_count=0），tick 仍继续运行。
                    if summary.meta.active_count < 2 {
                        // tracing::info!(
                        //     "[relayer::tick] needs_tick table={}, no active needed (active_count=0)",
                        //     table_id
                        // );
                        false
                    } else if in_reconstruct || shuffle_active || reveal_active {
                        tracing::info!(
                            "[relayer::tick] needs_tick table={}, shuffle/reveal/reconstruct active{} {} {}",
                            table_id,
                            in_reconstruct,
                            shuffle_active,
                            reveal_active
                        );
                        true
                    } else {
                        tracing::info!(
                            "[relayer::tick] needs_tick table={}, normal game stage",
                            table_id
                        );
                        // B) 正常游戏阶段：需要 active_count >= 2
                        summary.meta.active_count >= 2
                    }
                };

                if !needs_tick {
                    // tracing::info!(
                    //     "[relayer::tick] skip table={}, no tick needed (round_state={}, active_count={})",
                    //     table_id,
                    //     summary.meta.round_state,
                    //     summary.meta.active_count
                    // );
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

            // tracing::debug!("[relayer::tick] processing {} tables (off-chain)", table_ids.len());

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
