use std::sync::Arc;
use std::time::Duration;

use crate::handlers::AppState;
use crate::relayer::submit;

/// 定时 tick 循环：周期性遍历所有缓存的 table，调用链上 tick 函数处理超时
pub async fn run_tick_loop(state: Arc<AppState>) {
    let interval_ms = state.config.sui_tick_interval_ms;
    tracing::info!("[relayer::tick] starting tick loop, interval={}ms", interval_ms);

    loop {
        // 睡眠指定间隔
        tokio::time::sleep(Duration::from_millis(interval_ms)).await;

        // 获取所有缓存的 table_id
        let table_ids = state.relayer_state.list_ids();

        if table_ids.is_empty() {
            // 缓存为空，跳过本轮
            continue;
        }

        tracing::debug!("[relayer::tick] processing {} tables", table_ids.len());

        // 对每个 table 调用 submit_tick_tx
        for table_id in table_ids {
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
    }
}
