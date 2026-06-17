// 子模块声明
pub mod ptb;        // Task 4 实现
pub mod submit;     // Task 5 实现
pub mod tick;      // Task 6 实现

use std::collections::HashMap;
use std::sync::RwLock;

use crate::sui_events::{SuiChainEvent, TableSummary};
use crate::sui_query::fetch_table_summary;

/// 链上 Table 对象缓存，key 为 table_id (Object ID 字符串)
pub struct RelayerState {
    tables: RwLock<HashMap<String, TableSummary>>,
}

impl RelayerState {
    /// 创建空缓存
    pub fn new() -> Self {
        Self {
            tables: RwLock::new(HashMap::new()),
        }
    }

    /// 读取单个 table（clone 返回）
    pub fn get(&self, table_id: &str) -> Option<TableSummary> {
        let tables = self.tables.read().unwrap();
        tables.get(table_id).cloned()
    }

    /// 插入/更新
    pub fn insert(&self, table_id: String, summary: TableSummary) {
        let mut tables = self.tables.write().unwrap();
        tables.insert(table_id, summary);
    }

    /// 删除并返回
    pub fn remove(&self, table_id: &str) -> Option<TableSummary> {
        let mut tables = self.tables.write().unwrap();
        tables.remove(table_id)
    }

    /// 返回所有缓存的 clone 列表
    pub fn list(&self) -> Vec<TableSummary> {
        let tables = self.tables.read().unwrap();
        tables.values().cloned().collect()
    }

    /// 返回所有 table_id 列表（供 tick 任务遍历用）
    pub fn list_ids(&self) -> Vec<String> {
        let tables = self.tables.read().unwrap();
        tables.keys().cloned().collect()
    }
}

impl Default for RelayerState {
    fn default() -> Self {
        Self::new()
    }
}

/// 从 SuiChainEvent 中提取 table_id
fn table_id_from_event(event: &SuiChainEvent) -> &str {
    match event {
        SuiChainEvent::TableCreated { table_id, .. } => table_id,
        SuiChainEvent::PlayerJoined { table_id, .. } => table_id,
        SuiChainEvent::PlayerLeft { table_id, .. } => table_id,
        SuiChainEvent::HandStarted { table_id, .. } => table_id,
        SuiChainEvent::ShuffleVerified { table_id, .. } => table_id,
        SuiChainEvent::ShuffleComplete { table_id, .. } => table_id,
        SuiChainEvent::ShuffleTurn { table_id, .. } => table_id,
        SuiChainEvent::RevealTokenSubmitted { table_id, .. } => table_id,
        SuiChainEvent::RevealPhaseComplete { table_id, .. } => table_id,
        SuiChainEvent::PlayerFolded { table_id, .. } => table_id,
        SuiChainEvent::PlayerChecked { table_id, .. } => table_id,
        SuiChainEvent::PlayerCalled { table_id, .. } => table_id,
        SuiChainEvent::PlayerRaised { table_id, .. } => table_id,
        SuiChainEvent::HandSettled { table_id, .. } => table_id,
        SuiChainEvent::ReconstructInitiated { table_id, .. } => table_id,
        SuiChainEvent::ReconstructVote { table_id, .. } => table_id,
        SuiChainEvent::ReconstructDeckSubmitted { table_id, .. } => table_id,
        SuiChainEvent::ReconstructComplete { table_id, .. } => table_id,
        SuiChainEvent::RedealRequested { table_id, .. } => table_id,
        SuiChainEvent::PlayerKicked { table_id, .. } => table_id,
        SuiChainEvent::AutoFolded { table_id, .. } => table_id,
        SuiChainEvent::ForceFolded { table_id, .. } => table_id,
        SuiChainEvent::ShuffleTimeout { table_id, .. } => table_id,
        SuiChainEvent::RevealTimeout { table_id, .. } => table_id,
        SuiChainEvent::HandReset { table_id, .. } => table_id,
        SuiChainEvent::ReadyToStart { table_id, .. } => table_id,
        SuiChainEvent::HandCleanedUp { table_id, .. } => table_id,
    }
}

/// 处理链上事件，更新 RelayerState 缓存
pub async fn process_event(
    state: &RelayerState,
    fullnode_url: &str,
    event: &SuiChainEvent,
) {
    let table_id = table_id_from_event(event);

    match event {
        SuiChainEvent::TableCreated { .. } => {
            tracing::info!(
                table_id = table_id,
                "TableCreated event received, fetching full snapshot"
            );
            match fetch_table_summary(fullnode_url, table_id).await {
                Ok(summary) => {
                    state.insert(table_id.to_string(), summary);
                    tracing::info!(table_id = table_id, "TableCreated cached");
                }
                Err(e) => {
                    tracing::error!(
                        table_id = table_id,
                        error = %e,
                        "Failed to fetch table summary on TableCreated event"
                    );
                }
            }
        }
        _ => {
            if state.get(table_id).is_some() {
                tracing::debug!(
                    table_id = table_id,
                    "Event received for cached table, refreshing snapshot"
                );
                match fetch_table_summary(fullnode_url, table_id).await {
                    Ok(summary) => {
                        state.insert(table_id.to_string(), summary);
                        tracing::debug!(table_id = table_id, "Table cache refreshed");
                    }
                    Err(e) => {
                        tracing::warn!(
                            table_id = table_id,
                            error = %e,
                            "Failed to refresh table summary, keeping stale cache"
                        );
                    }
                }
            } else {
                tracing::info!(
                    table_id = table_id,
                    "Event received for uncached table, attempting to fetch"
                );
                match fetch_table_summary(fullnode_url, table_id).await {
                    Ok(summary) => {
                        state.insert(table_id.to_string(), summary);
                        tracing::info!(table_id = table_id, "Table auto-recovered into cache");
                    }
                    Err(e) => {
                        tracing::warn!(
                            table_id = table_id,
                            error = %e,
                            "Failed to fetch table summary for uncached table"
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    /// 辅助函数：构造一个填充合理默认值的 TableSummary
    fn make_test_summary(table_id: &str) -> TableSummary {
        TableSummary {
            table_id: table_id.to_string(),
            name: "test".to_string(),
            max_players: 6,
            small_blind: 10,
            big_blind: 20,
            active_count: 0,
            button: 0,
            pot: 0,
            side_pots_count: 0,
            community_cards_count: 0,
            round_state: 0,
            betting_round_exists: false,
            betting_round_current_bet: 0,
            betting_round_min_raise: 0,
            betting_round_big_blind: 0,
            betting_round_last_raiser_seat: None,
            betting_round_actions_taken: 0,
            current_turn: None,
            seats_occupied: vec![false; 6],
            seat_players: vec![String::new(); 6],
            seat_stacks: vec![0; 6],
            seat_bets: vec![0; 6],
            seat_total_bets: vec![0; 6],
            seat_folded: vec![false; 6],
            seat_all_in: vec![false; 6],
            shuffle_current_shuffler: None,
            shuffle_pending_count: 0,
            shuffle_completed_count: 0,
            reveal_phase: 0,
            reveal_assignment_count: 0,
            reconstruct_phase: 0,
            reconstruct_votes_yes: 0,
            reconstruct_votes_no: 0,
            deck_size: 52,
            deck_plaintext: Vec::new(),
            shuffle_timeout_ms: 0,
            reveal_timeout_ms: 0,
            betting_timeout_ms: 0,
            reconstruct_timeout_ms: 0,
            showdown_display_ms: 0,
            hand_complete_wait_ms: 0,
            ready_wait_ms: 0,
            ready_at: 0,
            shuffle_started_at: 0,
            reveal_started_at: 0,
            betting_started_at: 0,
            reconstruct_started_at: 0,
            showdown_at: 0,
            hand_complete_at: 0,
            epoch: 0,
        }
    }

    #[test]
    fn test_insert_and_get() {
        let state = RelayerState::new();
        let summary = make_test_summary("0xabc");
        state.insert("0xabc".to_string(), summary.clone());

        let got = state.get("0xabc").expect("should get inserted table");
        assert_eq!(got, summary);

        // 不存在的 key
        assert!(state.get("0xnotexist").is_none());
    }

    #[test]
    fn test_remove() {
        let state = RelayerState::new();
        let summary = make_test_summary("0xdef");
        state.insert("0xdef".to_string(), summary.clone());

        let removed = state.remove("0xdef").expect("should remove existing table");
        assert_eq!(removed, summary);

        // 删除后 get 返回 None
        assert!(state.get("0xdef").is_none());

        // 再次删除返回 None
        assert!(state.remove("0xdef").is_none());
    }

    #[test]
    fn test_list() {
        let state = RelayerState::new();
        assert_eq!(state.list().len(), 0);

        state.insert("0x1".to_string(), make_test_summary("0x1"));
        state.insert("0x2".to_string(), make_test_summary("0x2"));
        state.insert("0x3".to_string(), make_test_summary("0x3"));

        let list = state.list();
        assert_eq!(list.len(), 3);
    }

    #[test]
    fn test_list_ids() {
        let state = RelayerState::new();
        state.insert("0xaaa".to_string(), make_test_summary("0xaaa"));
        state.insert("0xbbb".to_string(), make_test_summary("0xbbb"));
        state.insert("0xccc".to_string(), make_test_summary("0xccc"));

        let mut ids = state.list_ids();
        ids.sort();
        assert_eq!(ids, vec!["0xaaa".to_string(), "0xbbb".to_string(), "0xccc".to_string()]);
    }

    #[test]
    fn test_concurrent_access() {
        let state = Arc::new(RelayerState::new());
        let mut handles = Vec::new();

        // 多个线程同时 insert
        for i in 0..8 {
            let state_clone = Arc::clone(&state);
            let handle = thread::spawn(move || {
                let id = format!("0x{:02x}", i);
                state_clone.insert(id.clone(), make_test_summary(&id));
                // insert 后立即 get 验证可见
                let got = state_clone.get(&id);
                assert!(got.is_some(), "thread {} should see its own insert", i);
            });
            handles.push(handle);
        }

        // 同时有读线程在并发 list / list_ids
        for _ in 0..4 {
            let state_clone = Arc::clone(&state);
            let handle = thread::spawn(move || {
                for _ in 0..100 {
                    let _ = state_clone.list();
                    let _ = state_clone.list_ids();
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().expect("thread should not panic");
        }

        // 所有线程结束后应有 8 条记录
        assert_eq!(state.list().len(), 8);
    }

    // ========== table_id_from_event 测试 ==========

    #[test]
    fn test_table_id_from_event() {
        let tid = "0xdeadbeef";

        let cases: Vec<(SuiChainEvent, &str)> = vec![
            (
                SuiChainEvent::TableCreated {
                    table_id: tid.to_string(),
                    name: "n".to_string(),
                },
                tid,
            ),
            (
                SuiChainEvent::PlayerJoined {
                    table_id: tid.to_string(),
                    seat_index: 0,
                    player: "p".to_string(),
                    buy_in: 0,
                },
                tid,
            ),
            (
                SuiChainEvent::PlayerLeft {
                    table_id: tid.to_string(),
                    seat_index: 0,
                    player: "p".to_string(),
                },
                tid,
            ),
            (
                SuiChainEvent::HandStarted {
                    table_id: tid.to_string(),
                    button: 0,
                },
                tid,
            ),
            (
                SuiChainEvent::ShuffleVerified {
                    table_id: tid.to_string(),
                    seat_index: 0,
                    player: "p".to_string(),
                },
                tid,
            ),
            (
                SuiChainEvent::ShuffleComplete {
                    table_id: tid.to_string(),
                },
                tid,
            ),
            (
                SuiChainEvent::ShuffleTurn {
                    table_id: tid.to_string(),
                    seat_index: 0,
                    pending_count: 0,
                    completed_count: 0,
                },
                tid,
            ),
            (
                SuiChainEvent::RevealTokenSubmitted {
                    table_id: tid.to_string(),
                    seat_index: 0,
                    card_index: 0,
                    phase: 0,
                },
                tid,
            ),
            (
                SuiChainEvent::RevealPhaseComplete {
                    table_id: tid.to_string(),
                    phase: 0,
                },
                tid,
            ),
            (
                SuiChainEvent::PlayerFolded {
                    table_id: tid.to_string(),
                    seat_index: 0,
                },
                tid,
            ),
            (
                SuiChainEvent::PlayerChecked {
                    table_id: tid.to_string(),
                    seat_index: 0,
                },
                tid,
            ),
            (
                SuiChainEvent::PlayerCalled {
                    table_id: tid.to_string(),
                    seat_index: 0,
                    amount: 0,
                },
                tid,
            ),
            (
                SuiChainEvent::PlayerRaised {
                    table_id: tid.to_string(),
                    seat_index: 0,
                    total_bet: 0,
                },
                tid,
            ),
            (
                SuiChainEvent::HandSettled {
                    table_id: tid.to_string(),
                    pot: 0,
                },
                tid,
            ),
            (
                SuiChainEvent::ReconstructInitiated {
                    table_id: tid.to_string(),
                },
                tid,
            ),
            (
                SuiChainEvent::ReconstructVote {
                    table_id: tid.to_string(),
                    seat_index: 0,
                    vote: true,
                },
                tid,
            ),
            (
                SuiChainEvent::ReconstructDeckSubmitted {
                    table_id: tid.to_string(),
                    seat_index: 0,
                },
                tid,
            ),
            (
                SuiChainEvent::ReconstructComplete {
                    table_id: tid.to_string(),
                },
                tid,
            ),
            (
                SuiChainEvent::RedealRequested {
                    table_id: tid.to_string(),
                    seat_index: 0,
                    card_indices: vec![],
                },
                tid,
            ),
            (
                SuiChainEvent::PlayerKicked {
                    table_id: tid.to_string(),
                    seat_index: 0,
                },
                tid,
            ),
            (
                SuiChainEvent::AutoFolded {
                    table_id: tid.to_string(),
                    seat_index: 0,
                },
                tid,
            ),
            (
                SuiChainEvent::ForceFolded {
                    table_id: tid.to_string(),
                    seat_index: 0,
                },
                tid,
            ),
            (
                SuiChainEvent::ShuffleTimeout {
                    table_id: tid.to_string(),
                    seat_index: 0,
                },
                tid,
            ),
            (
                SuiChainEvent::RevealTimeout {
                    table_id: tid.to_string(),
                    phase: 0,
                },
                tid,
            ),
            (
                SuiChainEvent::HandReset {
                    table_id: tid.to_string(),
                },
                tid,
            ),
            (
                SuiChainEvent::ReadyToStart {
                    table_id: tid.to_string(),
                    ready_at: 0,
                },
                tid,
            ),
            (
                SuiChainEvent::HandCleanedUp {
                    table_id: tid.to_string(),
                },
                tid,
            ),
        ];

        // 验证所有变体全部覆盖（实际为 27 个变体）
        assert_eq!(cases.len(), 27, "should cover all SuiChainEvent variants");

        for (event, expected) in cases {
            assert_eq!(table_id_from_event(&event), expected);
        }
    }

    // ========== process_event 测试 ==========

    /// 预先在 state 中插入一个 table，然后调用 process_event 处理一个非 TableCreated 事件。
    /// 由于使用无效的 fullnode_url，网络调用会失败，验证旧缓存被保留且不崩溃。
    #[tokio::test]
    async fn test_process_event_table_created_with_preinserted() {
        let state = RelayerState::new();
        let pre_summary = make_test_summary("0xpre");
        state.insert("0xpre".to_string(), pre_summary.clone());

        // 使用一个无效的 URL，确保 fetch_table_summary 失败
        let invalid_url = "http://127.0.0.1:1/invalid-rpc";

        let event = SuiChainEvent::PlayerFolded {
            table_id: "0xpre".to_string(),
            seat_index: 1,
        };

        // 调用 process_event，应不 panic
        process_event(&state, invalid_url, &event).await;

        // 网络失败后旧缓存应保留
        let got = state.get("0xpre").expect("stale cache should be preserved after fetch failure");
        assert_eq!(got, pre_summary);
    }

    /// 验证 process_event 处理 TableCreated 事件在网络失败时不崩溃、不污染缓存。
    #[tokio::test]
    async fn test_process_event_table_created_network_failure() {
        let state = RelayerState::new();
        let invalid_url = "http://127.0.0.1:1/invalid-rpc";

        let event = SuiChainEvent::TableCreated {
            table_id: "0xnew".to_string(),
            name: "TestTable".to_string(),
        };

        // 调用 process_event，应不 panic
        process_event(&state, invalid_url, &event).await;

        // 网络失败时缓存中不应有该 table
        assert!(state.get("0xnew").is_none());
        assert_eq!(state.list().len(), 0);
    }

    /// 验证 process_event 处理未缓存 table 的非 TableCreated 事件在网络失败时不崩溃。
    #[tokio::test]
    async fn test_process_event_uncached_table_network_failure() {
        let state = RelayerState::new();
        let invalid_url = "http://127.0.0.1:1/invalid-rpc";

        let event = SuiChainEvent::HandSettled {
            table_id: "0xuncached".to_string(),
            pot: 100,
        };

        // 调用 process_event，应不 panic
        process_event(&state, invalid_url, &event).await;

        // 网络失败时缓存中不应有该 table
        assert!(state.get("0xuncached").is_none());
        assert_eq!(state.list().len(), 0);
    }
}
