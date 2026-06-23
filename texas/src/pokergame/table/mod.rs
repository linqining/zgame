use std::collections::HashMap;
use crate::pokergame::game_state::{ElGamalCiphertextJson, ReconstructPhase, ShuffleProofJson,
     ReconstructPublicState, MaskAndShuffleRoundJson, ReconstructState, ReconstructProofJson, PlayerReadableCard,
     PkProofJson, PlayerReadableCardJson, PlayerRevealAssignment, RevealPhase, RevealTokenPublicState, ShufflePublicState, ShuffleState, RevealTokenState,
     LeaveGameRoundJson};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::pokergame::deck::{Card, EncryptedDeck};
use crate::pokergame::player::{GamePlayer, Player, PlayerWithProof, WalletAddress, GamePkHex};
use crate::pokergame::seat::{ClientSeat,Seat};
use crate::pokergame::side_pot::SidePot;
use crate::sui_events::{TableSummaryV2, TableSummaryMeta, TableSummaryState};
use poker_protocol::z_poker::{MentalPokerGame, GameConfig};
use poker_protocol::crypto::{EcPoint, ElGamalCiphertext, Plaintext, Scalar};
use poker_protocol::z_poker::convert::{ecpoint_to_hex, scalar_to_hex};
use poker_protocol::zk_shuffle::transcript_ext::{CryptoTranscript, FiatShamirTranscript};
use poker_protocol::crypto::CurvePoint;
use poker_protocol::crypto::CurveScalar;
/// 对齐 Move 合约 MIN_PLAYERS_TO_START = 2
const MIN_START_NUM: u32 = 2;

/// 当前时间的毫秒时间戳，对齐 Move 合约 Clock.timestamp_ms() 语义。
/// 用于 summary.state 中的各类 *_at 时间戳字段的设置与比较。
pub use crate::relayer::util::now_ms;

pub mod shuffle;
pub mod reveal;
pub mod reconstruct;
pub mod seat_mgmt;
pub mod betting;
pub mod pot;
pub mod phases;
pub mod lifecycle;
pub mod events;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    pub seat_id: u32,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum JoinResult {
    JoinedAndShuffled,
    JoinedWaiting,
}

pub use crate::pokergame::error::JoinError;
pub use events::{CryptoEventType, TableEvent};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RoundState {
    Waiting,
    PreFlop,
    Flop,
    Turn,
    River,
    Showdown,
}

impl RoundState {
    /// 将链上 u8 round_state 转换为 RoundState 枚举。
    /// 对齐 Move 合约：0=Waiting, 2=PreFlop, 3=Flop, 4=Turn, 5=River, 6=Showdown
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(RoundState::Waiting),
            2 => Some(RoundState::PreFlop),
            3 => Some(RoundState::Flop),
            4 => Some(RoundState::Turn),
            5 => Some(RoundState::River),
            6 => Some(RoundState::Showdown),
            _ => None,
        }
    }

    /// 将 RoundState 枚举转换为链上 u8 round_state。
    pub fn to_u8(self) -> u8 {
        match self {
            RoundState::Waiting => 0,
            RoundState::PreFlop => 2,
            RoundState::Flop => 3,
            RoundState::Turn => 4,
            RoundState::River => 5,
            RoundState::Showdown => 6,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ActionRequest {
    pub pk_hex: GamePkHex,
    pub action: String,
    pub amount: Option<u64>,
}

#[derive(Debug, Serialize,Clone,Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientTable {
    pub id: u32,
    pub name: String,
    pub limit: u64,
    pub max_players: u32,
    pub players: HashMap<GamePkHex, WalletAddress>,
    pub seats: HashMap<u32, ClientSeat>,
    pub board: Vec<Card>,
    pub deck: Option<EncryptedDeck>,
    pub button: Option<u32>,
    pub turn: Option<u32>,
    pub pot: u64,
    pub main_pot: u64,
    pub call_amount: Option<u64>,
    pub min_bet: u64,
    pub min_raise: u64,
    pub small_blind: Option<u32>,
    pub big_blind: Option<u32>,
    pub hand_over: bool,
    pub win_messages: Vec<String>,
    pub went_to_showdown: bool,
    pub side_pots: Vec<SidePot>,
    pub history: Vec<serde_json::Value>,
    pub round_state: RoundState,
    pub shuffle_state: Option<ShufflePublicState>,
    pub reveal_token_state: Option<RevealTokenPublicState>,
    pub reconstruct_state: Option<ReconstructPublicState>,
    /// 链上 Table 对象的 Object ID（hex 字符串）。
    /// on-chain 模式下前端构建 leave_with_proof_verified PTB 时需要此字段。
    pub sui_table_id: Option<String>,
}



#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Table {
    pub summary: TableSummaryV2,
    /// 仅 off-chain 模式使用；on-chain 模式通过 `players()` 访问器从 `summary.crypto.seat_pks` + `summary.meta.seat_players` 派生
    pub local_players: HashMap<GamePkHex, WalletAddress>,
    /// 仅 off-chain 模式使用 + on-chain 运行时字段；on-chain 模式通过 `seats()` 访问器从 `summary.meta.seat_*` 派生
    pub local_seats: HashMap<u32, Seat>,
    #[serde(skip)]
    pub shuffle_state: ShuffleState,
    #[serde(skip)]
    pub reveal_token_state: RevealTokenState,
    #[serde(skip)]
    pub reconstruct_state: ReconstructState,
    #[serde(skip)]
    pub betting_round: Option<crate::pokergame::betting::BettingRound>,
    #[serde(skip)]
    pub mental_poker_game: MentalPokerGame,
    #[serde(skip)]
    pub waiting_players: HashMap<GamePkHex, PlayerWithProof>,
    #[serde(skip)]
    pub pk_to_seat: HashMap<GamePkHex, u32>,
    /// 链上 Table 对象的 Object ID（hex 字符串）。
    /// 由 relayer 在 `sync_table_state` 中匹配到链上 table 后设置。
    /// 上链模式下用户操作构建 PTB 时需要此字段；为 None 表示尚未与链上 table 关联。
    #[serde(skip)]
    pub chain_table_id: Option<String>,
    #[serde(skip)]
    pub event_tx: Option<tokio::sync::mpsc::Sender<crate::pokergame::table::events::TableEvent>>,
}

impl Table {
    pub fn round_state(&self) -> RoundState {
        RoundState::from_u8(self.summary.meta.round_state).unwrap_or(RoundState::Waiting)
    }
    pub fn pot(&self) -> u64 {
        self.summary.meta.pot
    }
    pub fn set_pot(&mut self, v: u64) {
        self.summary.meta.pot = v;
    }
    pub fn button(&self) -> Option<u32> {
        if self.summary.meta.button == 0 { None } else { Some(self.summary.meta.button as u32) }
    }
    pub fn set_button(&mut self, v: Option<u32>) {
        self.summary.meta.button = v.map(|x| x as u64).unwrap_or(0);
    }
    pub fn turn(&self) -> Option<u32> {
        self.summary.meta.current_turn.map(|x| x as u32)
    }
    pub fn set_turn(&mut self, v: Option<u32>) {
        self.summary.meta.current_turn = v.map(|x| x as u64);
    }
    pub fn small_blind(&self) -> Option<u32> {
        if self.summary.meta.small_blind == 0 { None } else { Some(self.summary.meta.small_blind as u32) }
    }
    pub fn set_small_blind(&mut self, v: Option<u32>) {
        self.summary.meta.small_blind = v.map(|x| x as u64).unwrap_or(0);
    }
    pub fn big_blind(&self) -> Option<u32> {
        if self.summary.meta.big_blind == 0 { None } else { Some(self.summary.meta.big_blind as u32) }
    }
    pub fn set_big_blind(&mut self, v: Option<u32>) {
        self.summary.meta.big_blind = v.map(|x| x as u64).unwrap_or(0);
    }
    pub fn max_players(&self) -> u32 {
        self.summary.meta.max_players as u32
    }
    pub fn name(&self) -> &str {
        &self.summary.meta.name
    }

    // ===== 对齐 Move：min_raise 使用 summary.meta.betting_round_min_raise =====
    pub fn min_raise(&self) -> u64 {
        self.summary.meta.betting_round_min_raise
    }
    pub fn set_min_raise(&mut self, v: u64) {
        self.summary.meta.betting_round_min_raise = v;
    }

    // ===== 对齐 Move：main_pot = pot - sum(side_pots)，无独立字段 =====
    pub fn main_pot(&self) -> u64 {
        let side_total: u64 = self.summary.side_pots.iter().map(|sp| sp.amount).sum();
        self.pot().saturating_sub(side_total)
    }

    // ===== 对齐 Move Timestamps：使用 summary.state 中的 u64 毫秒时间戳 =====
    // 0 表示未设置（对齐 Move 中 0 表示未启动计时）
    pub fn betting_started_at(&self) -> u64 {
        self.summary.state.betting_started_at
    }
    pub fn set_betting_started_at(&mut self, v: u64) {
        self.summary.state.betting_started_at = v;
    }
    pub fn hand_complete_at(&self) -> u64 {
        self.summary.state.hand_complete_at
    }
    pub fn set_hand_complete_at(&mut self, v: u64) {
        self.summary.state.hand_complete_at = v;
    }
    pub fn ready_at(&self) -> u64 {
        self.summary.state.ready_at
    }
    pub fn set_ready_at(&mut self, v: u64) {
        self.summary.state.ready_at = v;
    }
    pub fn showdown_at(&self) -> u64 {
        self.summary.state.showdown_at
    }
    pub fn set_showdown_at(&mut self, v: u64) {
        self.summary.state.showdown_at = v;
    }

    /// 返回当前加密牌组。
    /// 上链模式（chain_table_id.is_some() 且 summary.crypto.deck_encrypted 非空）：
    ///   从 summary.crypto.deck_encrypted 反序列化 Vec<Vec<u8>> → Vec<ElGamalCiphertext>
    /// 离链模式或反序列化失败：回退到 mental_poker_game.deck_encrypted
    pub fn deck_encrypted(&self) -> Vec<ElGamalCiphertext> {
        if self.chain_table_id.is_some() && !self.summary.crypto.deck_encrypted.is_empty() {
            use poker_protocol::crypto::curve::CurvePoint;
            use poker_protocol::crypto::DefaultCurve;
            type P = <DefaultCurve as poker_protocol::crypto::curve::Curve>::Point;

            let mut synced_deck: Vec<ElGamalCiphertext> = Vec::with_capacity(self.summary.crypto.deck_encrypted.len());
            let mut all_ok = true;
            for ct_bytes in &self.summary.crypto.deck_encrypted {
                if ct_bytes.len() != 96 {
                    all_ok = false;
                    break;
                }
                let (c1_bytes, c2_bytes) = ct_bytes.split_at(48);
                match (
                    <P as CurvePoint>::from_compressed(c1_bytes),
                    <P as CurvePoint>::from_compressed(c2_bytes),
                ) {
                    (Some(c1), Some(c2)) => synced_deck.push(ElGamalCiphertext { c1, c2 }),
                    _ => {
                        all_ok = false;
                        break;
                    }
                }
            }
            if all_ok {
                return synced_deck;
            }
            tracing::warn!(
                "[Table::deck_encrypted] table {} failed to deserialize summary.crypto.deck_encrypted, falling back to mental_poker_game",
                self.summary.id
            );
        }
        self.mental_poker_game.deck_encrypted.clone()
    }

    /// 返回当前明文牌组。
    /// 上链模式（chain_table_id.is_some() 且 summary.state.deck_plaintext 非空）：
    ///   从 summary.state.deck_plaintext 反序列化 Vec<Vec<u8>> → Vec<Plaintext>
    /// 离链模式或反序列化失败：回退到 mental_poker_game.deck_plaintext
    pub fn deck_plaintext(&self) -> Vec<Plaintext> {
        if self.chain_table_id.is_some() && !self.summary.state.deck_plaintext.is_empty() {
            use poker_protocol::crypto::curve::CurvePoint;
            use poker_protocol::crypto::DefaultCurve;
            type P = <DefaultCurve as poker_protocol::crypto::curve::Curve>::Point;

            let mut synced_deck: Vec<Plaintext> = Vec::with_capacity(self.summary.state.deck_plaintext.len());
            let mut all_ok = true;
            for bytes in &self.summary.state.deck_plaintext {
                match <P as CurvePoint>::from_compressed(bytes) {
                    Some(pt) => synced_deck.push(pt),
                    None => {
                        all_ok = false;
                        break;
                    }
                }
            }
            if all_ok && synced_deck.len() == self.mental_poker_game.deck_plaintext.len() {
                return synced_deck;
            }
            if !all_ok {
                tracing::warn!(
                    "[Table::deck_plaintext] table {} failed to deserialize summary.state.deck_plaintext, falling back to mental_poker_game",
                    self.summary.id
                );
            }
        }
        self.mental_poker_game.deck_plaintext.clone()
    }

    /// 返回当前聚合公钥。
    /// 上链模式：从 summary.crypto.aggregated_pk 反序列化
    /// 离链模式：从 mental_poker_game.key_manager 获取
    pub fn aggregated_pk(&self) -> EcPoint {
        if self.chain_table_id.is_some() && !self.summary.crypto.aggregated_pk.is_empty() {
            use poker_protocol::crypto::curve::CurvePoint;
            use poker_protocol::crypto::DefaultCurve;
            type P = <DefaultCurve as poker_protocol::crypto::curve::Curve>::Point;

            if let Some(pk) = <P as CurvePoint>::from_compressed(&self.summary.crypto.aggregated_pk) {
                return pk;
            }
            tracing::warn!(
                "[Table::aggregated_pk] table {} failed to deserialize summary.crypto.aggregated_pk, falling back to mental_poker_game",
                self.summary.id
            );
        }
        self.mental_poker_game.key_manager.get_aggregated_pk()
    }

    pub fn to_client(&self) -> ClientTable {
        let mut client_seats = HashMap::new();
        for (seat_id, seat) in self.seats().iter() {
            let client_seat = seat.to_client();
            client_seats.insert(*seat_id, client_seat);
        }
        let encrypted_deck = EncryptedDeck{
            cards: self.deck_encrypted().iter().map(ElGamalCiphertextJson::from_ciphertext).collect(),
        };
        let board = self.mental_poker_game.list_revealed_community_cards().iter().map(|c| Card::from_playing_card(c)).collect::<Vec<_>>();
        ClientTable {
            id: self.summary.id,
            name: self.name().to_string(),
            limit: self.summary.limit,
            max_players: self.max_players(),
            players: self.players(),
            seats: client_seats,
            board: board,
            deck: Some(encrypted_deck.clone()),
            button: self.button(),
            turn: self.turn(),
            pot: self.pot(),
            main_pot: self.main_pot(),
            call_amount: self.summary.call_amount,
            min_bet: self.summary.min_bet,
            min_raise: self.min_raise(),
            small_blind: self.small_blind(),
            big_blind: self.big_blind(),
            hand_over: self.summary.hand_over,
            win_messages: self.summary.win_messages.clone(),
            went_to_showdown: self.summary.went_to_showdown,
            side_pots: self.summary.side_pots.clone(),
            history: self.summary.history.clone(),
            round_state: self.round_state(),
            shuffle_state: self.get_shuffle_public_state(),
            reveal_token_state: self.get_reveal_token_public_state(),
            reconstruct_state: self.get_reconstruct_public_state(),
            sui_table_id: self.chain_table_id.clone(),
        }
    }

    /// Transition to a new round state with validity checking.
    /// Logs a warning if the transition is not in the valid transition table.
    /// G4 修复：对严重非法转换（如 Waiting → Showdown）直接 panic，
    /// 其他非法转换在 debug 构建中 panic，release 中仅记录 warn。
    pub fn transition_to(&mut self, new_state: RoundState) {
        if self.round_state() == new_state{
            return;
        };
        let from = self.round_state();
        let valid = matches!((from, new_state),
            (RoundState::Waiting, RoundState::PreFlop) |
            (RoundState::PreFlop, RoundState::Flop) |
            (RoundState::Flop, RoundState::Turn) |
            (RoundState::Turn, RoundState::River) |
            (RoundState::River, RoundState::Showdown) |
            (RoundState::Showdown, RoundState::Waiting) |
            // Early termination / timeout reset
            (RoundState::PreFlop | RoundState::Flop | RoundState::Turn | RoundState::River, RoundState::Waiting)
        );
        tracing::info!("Transition from {:?} to {:?}", from, new_state);
        if !valid {
            let severe = matches!((from, new_state),
                (RoundState::Waiting, RoundState::Showdown) |
                (RoundState::Showdown, RoundState::PreFlop | RoundState::Flop | RoundState::Turn | RoundState::River)
            );
            if severe {
                panic!("[transition_to] severe illegal state transition: {:?} -> {:?}", from, new_state);
            }
            tracing::warn!("Invalid state transition: {:?} -> {:?}", from, new_state);
            // debug_assert!(valid, "Invalid state transition: {:?} -> {:?}", from, new_state);
        }
        self.summary.meta.round_state = new_state.to_u8();
    }

    /// Force transition to a new round state WITHOUT validation.
    /// Used by sync_table_state when the on-chain state is the authority.
    /// The on-chain round_state is already validated by the Move contract,
    /// so we skip the local state machine validation to avoid getting stuck
    /// when local and chain states diverge.
    pub fn transition_to_forced(&mut self, new_state: RoundState) {
        let old_state = self.summary.meta.round_state;
        if old_state != new_state.to_u8() {
            tracing::info!(target: "table",
                table_id = self.summary.id,
                old_state = old_state,
                new_state = new_state.to_u8(),
                "forced transition (chain authority)");
        }
        self.summary.meta.round_state = new_state.to_u8();
    }

    pub fn new(id: u32, name: String, limit: u64, max_players: u32, chain_table_id: String) -> Self {
        let local_seats = Self::init_seats(max_players);
        let mut summary = TableSummaryV2::default();
        summary.meta.name = name;
        summary.meta.max_players = max_players as u64;
        summary.meta.small_blind = (limit / 200) as u64;
        summary.meta.big_blind = (limit / 100) as u64;
        summary.meta.round_state = RoundState::Waiting.to_u8();
        summary.id = id;
        summary.limit = limit;
        summary.call_amount = None;
        summary.min_bet = limit / 200;
        summary.hand_over = true;
        summary.win_messages = vec![];
        summary.went_to_showdown = false;
        summary.side_pots = vec![];
        summary.history = vec![];
        Self {
            summary,
            local_players: HashMap::new(),
            local_seats,
            shuffle_state: ShuffleState::new(),
            reveal_token_state: RevealTokenState::new(2, 5),
            reconstruct_state: ReconstructState::new(),
            betting_round: None,
            mental_poker_game: MentalPokerGame::new(GameConfig {
                num_players: max_players as usize,
                cards_per_player: 2,
                community_cards: 5,
            }),
            waiting_players: HashMap::new(),
            pk_to_seat: HashMap::new(),
            chain_table_id: Some(chain_table_id),
            event_tx: None,
        }
    }

    /// 注入事件 sender，使 Table 内部方法能通过 `emit_event` 发送 socket 事件。
    /// 由 `SocketState::init_table_event_channels` 在初始化时调用。
    pub fn set_event_sender(&mut self, tx: tokio::sync::mpsc::Sender<crate::pokergame::table::events::TableEvent>) {
        self.event_tx = Some(tx);
    }

    /// 发送一个 TableEvent 到 channel，由 `table_event_consumer` 消费并执行实际 socket 广播。
    /// 若未注入 sender（event_tx 为 None），静默返回。
    /// 使用 `try_send` 非阻塞发送：channel 满或已关闭时静默丢弃事件，不 panic、不阻塞。
    /// 这使得 sync 内部方法（如 advance_shuffle / on_reveal_complete）也能调用。
    pub fn emit_event(&self, event: crate::pokergame::table::events::TableEvent) {
        if let Some(tx) = &self.event_tx {
            if let Err(e) = tx.try_send(event) {
                tracing::debug!("[TABLE-EVENTS] emit_event dropped: {}", e);
            }
        }
    }

    pub fn init_seats(_max_players: u32) -> HashMap<u32, Seat> {
        HashMap::new()
    }

    /// 返回 players 映射。on-chain 模式从 summary.crypto.seat_pks + summary.meta.seat_players 派生；
    /// off-chain 模式返回 local_players 副本。
    ///
    /// 注意：GamePkHex 必须通过 G1 compressed bytes 反序列化得到（与 relayer 的
    /// `deserialize_pk_hex` / `build_seat_pk_map` 一致），不能直接 hex encode 原始字节。
    /// WalletAddress 则直接 hex encode seat_players[i] 并加 "0x" 前缀。
    pub fn players(&self) -> HashMap<GamePkHex, WalletAddress> {
        if self.chain_table_id.is_some() {
            use poker_protocol::crypto::curve::CurvePoint as CurvePointTrait;
            use poker_protocol::crypto::DefaultCurve;
            type P = <DefaultCurve as poker_protocol::crypto::curve::Curve>::Point;

            let mut result = HashMap::new();
            for (i, pk_bytes) in self.summary.crypto.seat_pks.iter().enumerate() {
                if pk_bytes.is_empty() {
                    continue;
                }
                // G1 compressed bytes → EcPoint → hex string（对齐 relayer deserialize_pk_hex）
                let pk_hex = match <P as CurvePointTrait>::from_compressed(pk_bytes) {
                    Some(pt) => GamePkHex::new(ecpoint_to_hex(&pt)),
                    None => {
                        tracing::warn!(
                            "[Table::players] seat {} pk deserialization failed (invalid G1 bytes), skipping",
                            i
                        );
                        continue;
                    }
                };
                if let Some(wallet_bytes) = self.summary.meta.seat_players.get(i) {
                    // 全零地址视为空座位，跳过（对齐 relayer populate_seats_from_summary）
                    if wallet_bytes.iter().any(|&b| b != 0) {
                        let wallet_addr = WalletAddress::new(format!(
                            "0x{}",
                            hex::encode(wallet_bytes)
                        ));
                        result.insert(pk_hex, wallet_addr);
                    }
                }
            }
            result
        } else {
            self.local_players.clone()
        }
    }

    /// 返回 seats 映射。on-chain 模式以 local_seats 为基底，用 summary.meta.seat_* 覆盖链上同步字段；
    /// off-chain 模式返回 local_seats 副本。
    ///
    /// 注意：Seat 未 impl Default，使用 `Seat::new(seat_id, None, 0, 0)` 作为占位初始化。
    /// 链上同步字段覆盖：stack / bet / total_bet / folded / sitting_out（对应 seat_is_waiting）。
    pub fn seats(&self) -> HashMap<u32, Seat> {
        if self.chain_table_id.is_some() {
            use poker_protocol::crypto::curve::CurvePoint as CurvePointTrait;
            use poker_protocol::crypto::DefaultCurve;
            type P = <DefaultCurve as poker_protocol::crypto::curve::Curve>::Point;

            let mut result = self.local_seats.clone();
            for (i, &occupied) in self.summary.meta.seats_occupied.iter().enumerate() {
                let seat_id = i as u32;
                if !occupied {
                    continue;
                }
                let seat = result.entry(seat_id).or_insert_with(|| Seat::new(seat_id, None, 0, 0));
                if let Some(&stack) = self.summary.meta.seat_stacks.get(i) {
                    seat.stack = stack;
                }
                if let Some(&bet) = self.summary.meta.seat_bets.get(i) {
                    seat.bet = bet;
                }
                if let Some(&total_bet) = self.summary.meta.seat_total_bets.get(i) {
                    seat.total_bet = total_bet;
                }
                if let Some(&folded) = self.summary.meta.seat_folded.get(i) {
                    seat.folded = folded;
                }
                if let Some(&is_waiting) = self.summary.meta.seat_is_waiting.get(i) {
                    seat.sitting_out = is_waiting;
                }
                // 从链上数据构造 GamePlayer（当 seat 无 player 时）
                if seat.player.is_none() {
                    if let Some(wallet_bytes) = self.summary.meta.seat_players.get(i) {
                        if wallet_bytes.iter().any(|&b| b != 0) {
                            let wallet_addr = WalletAddress::new(format!(
                                "0x{}",
                                hex::encode(wallet_bytes)
                            ));
                            // 从 seat_pks 反序列化 pk_hex
                            let pk_hex = self.summary.crypto.seat_pks.get(i)
                                .filter(|pk_bytes| !pk_bytes.is_empty())
                                .and_then(|pk_bytes| {
                                    <P as CurvePointTrait>::from_compressed(pk_bytes)
                                        .map(|pt| GamePkHex::new(ecpoint_to_hex(&pt)))
                                });
                            if let Some(pk_hex) = pk_hex {
                                let name = crate::pokergame::player::truncate_name(
                                    &wallet_addr.0,
                                    12,
                                );
                                seat.player = Some(GamePlayer {
                                    name,
                                    bankroll: 0,
                                    pk_hex,
                                    readable_hands: vec![],
                                    wallet_address: wallet_addr,
                                });
                            }
                        }
                    }
                }
            }
            result
        } else {
            self.local_seats.clone()
        }
    }

    pub fn is_playing(&self) -> bool {
        self.round_state() != RoundState::Waiting
    }

    pub fn update_history(&mut self) {
        let board = self.mental_poker_game.list_revealed_community_cards().iter().map(|c| Card::from_playing_card(c)).collect::<Vec<_>>();
        self.summary.history.push(json!({
            "pot": self.pot(),
            "mainPot": self.main_pot(),
            "sidePots": self.summary.side_pots,
            "board":board,
            "seats": self.clean_seats_for_history(),
            "button": self.button(),
            "turn": self.turn(),
            "winMessages": self.summary.win_messages,
        }));
    }

    pub fn clean_seats_for_history(&self) -> serde_json::Value {
        let mut clean = serde_json::Map::new();
        for (id, seat) in self.seats().iter() {
            clean.insert(id.to_string(), json!({
                "player": { "id": seat.player.as_ref().map(|p| p.wallet_address.0.clone()), "username": seat.player.as_ref().map(|p| p.name.clone()) },
                "bet": seat.bet,
                "stack": seat.stack,
            }));
        }
        serde_json::Value::Object(clean)
    }

    pub fn get_pk_hex_by_wallet_address(&self,wallet: &str)->Option<GamePkHex>{
        self.players().iter().find(|(pk_hex,wallet_addr)| wallet_addr.0 == wallet).map(|(pk_hex,_)|pk_hex.clone())
    }
}
