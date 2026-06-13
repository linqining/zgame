use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use parking_lot::RwLock;
use tokio::sync::Notify;

use poker_protocol::z_poker::protocol::ClientPlayer;
use poker_protocol::crypto::{EcPoint, ElGamalCiphertext, Scalar};
use curve25519_dalek::traits::Identity;

pub mod wallet_login;
pub use wallet_login::*;

pub mod socketio_client;
pub use socketio_client::*;
use poker_protocol::crypto::CurveScalar;
use poker_protocol::crypto::CurvePoint;

const BASE_URL: &str = "http://localhost:3000/api";
const KEYSTORE_PATH: &str = "keys.json";
const KEYSTORE_COUNT: usize = 9;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ActionRequest {
    pk_hex: String,
    action: String,
    amount: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ApiError {
    error: String,
}

#[derive(Debug, Clone)]
pub struct SimulatorClientPlayer {
    inner: ClientPlayer,
}

impl SimulatorClientPlayer {
    pub fn new() -> Self {
        Self {
            inner: ClientPlayer::new(),
        }
    }

    pub fn get_pk_hex(&self) -> String {
        ecpoint_to_hex(&self.inner.pk)
    }

    pub fn join_game_and_shuffle_json(
        &self,
        deck_encrypted_json: &str,
        agg_pk_hex: &str,
    ) -> Result<serde_json::Value, String> {
        let deck = json_to_ct_vec(deck_encrypted_json)?;
        let agg_pk = hex_to_ecpoint(agg_pk_hex)?;

        let round = self.inner.join_game_and_shuffle(&deck, &agg_pk);
        let ms = &round.mask_and_shuffle_round;

        let result = serde_json::json!({
            "pk_hex": ecpoint_to_hex(&self.inner.pk),
            "pk_proof": {
                "commitment_hex": ecpoint_to_hex(&round.pk_ownership_proof.commitment),
                "response_hex": scalar_to_hex(&round.pk_ownership_proof.response)
            },
            "amount":1000,
            "mask_and_shuffle_round": {
                "mask_cards": ct_vec_to_json_array(&ms.mask_cards),
                "output_cards": ct_vec_to_json_array(&ms.output_cards),
                "remask_proof": {
                    "per_card_commitments_hex": ms.remask_proof.per_card_commitments.iter().map(ecpoint_to_hex).collect::<Vec<_>>(),
                    "commitment_pk_hex": ecpoint_to_hex(&ms.remask_proof.commitment_pk),
                    "response_hex": scalar_to_hex(&ms.remask_proof.response),
                    "nonce_hex": scalar_to_hex(&ms.remask_proof.nonce)
                },
                "shuffle_proof": {
                    "sum_c1_commit_hex": ecpoint_to_hex(&ms.proof.sum_c1_commit),
                    "sum_c2_commit_hex": ecpoint_to_hex(&ms.proof.sum_c2_commit),
                    "combined_schnorr_proof": {
                        "commitment_hex": ecpoint_to_hex(&ms.proof.combined_schnorr_proof.commitment),
                        "responses_hex": ms.proof.combined_schnorr_proof.responses.iter().map(scalar_to_hex).collect::<Vec<_>>()
                    },
                    "sum_c1_schnorr_proof": {
                        "commitment_hex": ecpoint_to_hex(&ms.proof.sum_c1_schnorr_proof.commitment),
                        "responses_hex": ms.proof.sum_c1_schnorr_proof.responses.iter().map(scalar_to_hex).collect::<Vec<_>>()
                    },
                    "sum_c2_schnorr_proof": {
                        "commitment_hex": ecpoint_to_hex(&ms.proof.sum_c2_schnorr_proof.commitment),
                        "responses_hex": ms.proof.sum_c2_schnorr_proof.responses.iter().map(scalar_to_hex).collect::<Vec<_>>()
                    },
                    "nonce_hex": scalar_to_hex(&ms.proof.nonce)
                }
            }
        });

        Ok(result)
    }

    pub fn batch_generate_reveal_tokens_json(&self, cts_json: &str) -> Result<String, String> {
        let cts = json_to_ct_vec(cts_json)?;
        let tokens = self.inner.batch_generate_reveal_token(&cts);

        let items: Vec<serde_json::Value> = tokens.iter().map(|token| {
            serde_json::json!({
                "encrypted_card": ct_to_json_obj(&token.encrypted_card),
                "reveal_token_proof": {
                    "user_public_key_hex": ecpoint_to_hex(&token.proof.user_public_key),
                    "commitment_t1_hex": ecpoint_to_hex(&token.proof.commitment_t1),
                    "commitment_t2_hex": ecpoint_to_hex(&token.proof.commitment_t2),
                    "response_s_hex": scalar_to_hex(&token.proof.response_s)
                },
                "reveal_token_hex": ecpoint_to_hex(&token.reveal_token)
            })
        }).collect();

        Ok(serde_json::json!(items).to_string())
    }
}

fn scalar_to_hex(s: &poker_protocol::crypto::Scalar) -> String {
    hex::encode(s.as_bytes())
}

fn ecpoint_to_hex(p: &EcPoint) -> String {
    hex::encode(p.compress().as_bytes())
}

fn hex_to_ecpoint(hex_str: &str) -> Result<EcPoint, String> {
    poker_protocol::z_poker::convert::hex_to_curve_point::<poker_protocol::crypto::DefaultCurve>(hex_str)
}

fn hex_to_scalar(hex_str: &str) -> Result<Scalar, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;
    Ok(Scalar::from_bytes_mod_order(&bytes))
}

fn ct_to_json_obj(ct: &ElGamalCiphertext) -> serde_json::Value {
    serde_json::json!({
        "c1_hex": ecpoint_to_hex(&ct.c1),
        "c2_hex": ecpoint_to_hex(&ct.c2)
    })
}

fn obj_to_ct(val: &serde_json::Value) -> Result<ElGamalCiphertext, String> {
    match val {
        serde_json::Value::Object(obj) => {
            Ok(ElGamalCiphertext {
                c1: hex_to_ecpoint(obj["c1_hex"].as_str().unwrap_or(""))?,
                c2: hex_to_ecpoint(obj["c2_hex"].as_str().unwrap_or(""))?,
            })
        }
        _ => Err("Invalid JSON object for ciphertext".to_string())
    }
}

fn ct_vec_to_json_array(cts: &[ElGamalCiphertext]) -> Vec<serde_json::Value> {
    cts.iter().map(ct_to_json_obj).collect()
}

fn json_to_ct_vec(json_str: &str) -> Result<Vec<ElGamalCiphertext>, String> {
    let arr: Vec<serde_json::Value> = serde_json::from_str(json_str)
        .map_err(|e| format!("JSON parse error: {}", e))?;
    let mut result: Vec<ElGamalCiphertext> = vec![];
    for v in arr {
        result.push(obj_to_ct(&v)?);
    }
    Ok(result)
}

struct SimulatedPlayer {
    name: String,
    client_player: ClientPlayer,
    json_client: SimulatorClientPlayer,
    pk_hex: String,
    table_id: u32,
    client: Client,
    wallet: RistrettoWalletLogin,
    token: Option<String>,
    socket_client: Option<SocketClient>,
}

impl std::fmt::Debug for SimulatedPlayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SimulatedPlayer")
            .field("name", &self.name)
            .field("pk_hex", &self.pk_hex)
            .field("table_id", &self.table_id)
            .field("token", &self.token)
            .finish()
    }
}

impl SimulatedPlayer {
    fn new(name: String, table_id: u32, client: Client, wallet: RistrettoWalletLogin) -> Self {
        let client_player = ClientPlayer::new();
        let pk_hex = hex::encode(client_player.pk.compress().as_bytes());
        let json_client = SimulatorClientPlayer { inner: client_player.clone() };

        println!("   🔑 Generated key pair for {}", name);
        println!("      Public Key: {}...", &pk_hex[..16]);

        Self {
            name,
            client_player,
            json_client,
            pk_hex,
            table_id,
            client,
            wallet,
            token: None,
            socket_client: None,
        }
    }

    async fn wallet_login(&mut self) -> Result<String, Box<dyn std::error::Error>> {
        println!("   🎲 Logging in player {}...", self.name);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let (sk_hex, pk_hex) = self.client_player.get_sk_and_pk_hex();
        let address = self.wallet.address();
        let signature = self.wallet.sign_login_message(&pk_hex)?;

        let resp = self.client
            .post(format!("{}/auth/wallet", BASE_URL))
            .json(&serde_json::json!({
                "address": address,
                "signature": signature,
                "message": pk_hex,
            }))
            .send()
            .await?;

        if !resp.status().is_success() {
            let err: ApiError = resp.json().await?;
            return Err(format!("Login failed: {}", err.error).into());
        }

        let body: serde_json::Value = resp.json().await?;
        let token = body["token"].as_str().unwrap_or("").to_string();
        self.token = Some(token.clone());

        println!("   ✅ {} logged in successfully", self.name);
        Ok(token)
    }

    async fn join_and_shuffle(&self, deck_encrypted_json_str: &str, agg_pk_hex: &str) -> Result<(), Box<dyn std::error::Error>> {
        println!("   🎲 Joining table {} and submitting shuffle...", self.table_id);
        let join_req_value = self.json_client.join_game_and_shuffle_json(
            deck_encrypted_json_str,
            agg_pk_hex,
        ).map_err(|e| format!("Shuffle computation failed: {}", e))?;

        let pk_proof = join_req_value.get("pk_proof").cloned().unwrap_or(serde_json::Value::Null);
        let mask_and_shuffle_round = join_req_value.get("mask_and_shuffle_round").cloned().unwrap_or(serde_json::Value::Null);

        let resp = self.client
            .post(format!("{}/tables/{}/join-and-shuffle", BASE_URL, self.table_id))
            .json(&serde_json::json!({
                "pk_hex": self.pk_hex,
                "name": self.name,
                "pk_proof": pk_proof,
                "mask_and_shuffle_round": mask_and_shuffle_round,
                "seat_id": 0,
                "amount": 1000,
            }))
            .send()
            .await?;

        if !resp.status().is_success() {
            let err: ApiError = resp.json().await?;
            return Err(format!("Join failed: {}", err.error).into());
        }

        println!("   ✅ {} joined and shuffled successfully", self.name);
        Ok(())
    }

    async fn send_action(&self, action: String, amount: Option<u64>) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let req = ActionRequest {
            pk_hex: self.pk_hex.clone(),
            action,
            amount,
        };

        let resp = self.client
            .post(format!("{}/games/{}/action", BASE_URL, self.table_id))
            .json(&req)
            .send()
            .await?;

        if resp.status().is_success() {
            let state: serde_json::Value = resp.json().await?;
            Ok(state)
        } else {
            let err: ApiError = resp.json().await?;
            Err(format!("Action failed: {}", err.error).into())
        }
    }

    fn get_sk_hex(&self) -> String {
        hex::encode(self.client_player.sk.as_bytes())
    }

    fn print_key_info(&self) {
        println!("   👤 Player: {}", self.name);
        println!("      🔑 Public Key: {}...", &self.pk_hex[..32.min(self.pk_hex.len())]);
        println!("      🔒 Secret Key: {}...", &self.get_sk_hex()[..32.min(self.get_sk_hex().len())]);
    }

    async fn submit_reveal_tokens(
        &self,
        table_id: u32,
        hand_cards_json: Vec<ElGamalCiphertextInfo>,
        community_cards_json: Vec<ElGamalCiphertextInfo>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut all_cards: Vec<serde_json::Value> = hand_cards_json.iter()
            .map(|c| serde_json::json!({"c1_hex": c.c1_hex, "c2_hex": c.c2_hex}))
            .collect();
        all_cards.extend(community_cards_json.iter()
            .map(|c| serde_json::json!({"c1_hex": c.c1_hex, "c2_hex": c.c2_hex})));

        if all_cards.is_empty() {
            println!("   ⚠️ No cards to reveal");
            return Ok(());
        }

        println!("   🔓 Generating reveal tokens for {} cards...", all_cards.len());
        let tokens_json = self.json_client.batch_generate_reveal_tokens_json(
            &serde_json::to_string(&all_cards)?
        ).map_err(|e| format!("Reveal token generation failed: {}", e))?;

        let reveal_tokens: serde_json::Value = serde_json::from_str(&tokens_json)
            .map_err(|e| format!("JSON parse error: {}", e))?;

        let resp = self.client
            .post(format!("{}/games/{}/reveal-token", BASE_URL, table_id))
            .json(&serde_json::json!({ "pk_hex": self.pk_hex, "reveal_tokens": reveal_tokens }))
            .send()
            .await?;

        if !resp.status().is_success() {
            let err: ApiError = resp.json().await?;
            return Err(format!("Reveal token submit failed: {}", err.error).into());
        }

        println!("   ✅ {} submitted reveal tokens for {} cards", self.name, all_cards.len());
        Ok(())
    }

    async fn connect_socket(&mut self, token: &str) -> Result<(), String> {
        let mut socket = SocketClient::new();
        socket.connect(token).await?;
        self.socket_client = Some(socket);
        println!("   🔗 {} connected to socket", self.name);
        Ok(())
    }

    async fn process_socket_events(&mut self) -> Vec<TableUpdatePayload> {
        let events: Vec<SocketEvent> = if let Some(ref mut socket) = self.socket_client {
            let mut events = Vec::new();
            while let Some(event) = socket.recv_event() {
                events.push(event);
            }
            events
        } else {
            return Vec::new();
        };

        let mut table_updates = Vec::new();

        for event in events {
            match event.event_type {
                SocketEventType::TableUpdated => {
                    if let Ok(payload) = serde_json::from_value::<TableUpdatePayload>(event.data) {
                        println!("   📊 [{}] Table {} update: state={}, pot={}",
                            self.name, payload.table.id, payload.table.round_state, payload.table.pot);
                        table_updates.push(payload);
                    }
                }
                SocketEventType::RevealNotice => {
                    if let Ok(payload) = serde_json::from_value::<RevealNoticePayload>(event.data) {
                        self.handle_reveal_notice(&payload).await;
                    }
                }
                SocketEventType::HandRevealResult => {
                    if let Ok(payload) = serde_json::from_value::<HandRevealResultPayload>(event.data) {
                        for card in payload.readable_cards {
                            if let Ok(ct) = card.to_ciphertext() {
                                let deck_plaintext: Result<Vec<EcPoint>, String> = payload.deck_plaintext.iter().map(|s| hex_to_ecpoint(s)).collect();
                                let deck_plaintext = deck_plaintext.map_err(|e| format!("Failed to parse deck plaintext: {}", e)).unwrap();
                                let decrypted_card = self.client_player.decrypt_readable_card(&ct, deck_plaintext);
                                println!("      🔑 [{}] Decrypted card: {:?}", self.name, decrypted_card);
                            }
                        }
                    }
                }
                SocketEventType::ShuffleNotice => {
                    if let Ok(payload) = serde_json::from_value::<ShuffleNoticePayload>(event.data) {
                        println!("   🔀 [{}] Shuffle notice for table {}", self.name, payload.table_id);
                    }
                }
                _ => {}
            }
        }

        table_updates
    }

    async fn handle_reveal_notice(&self, payload: &RevealNoticePayload) {
        println!("   🔓 [{}] Reveal notice for table {}: phase={}",
            self.name, payload.table_id, payload.phase);
        println!("      Pending: {:?}, Completed: {:?}",
            payload.pending_players, payload.completed_players);

        if payload.pending_players.contains(&self.pk_hex) {
            if let Some(assignment) = payload.player_assignments.get(&self.pk_hex) {
                println!("      🎯 [{}] Submitting reveal tokens!", self.name);
                if let Err(e) = self.submit_reveal_tokens(
                    payload.table_id,
                    assignment.hand_card.clone(),
                    assignment.community_card.clone(),
                ).await {
                    println!("   ❌ [{}] Failed to submit reveal tokens: {}", self.name, e);
                }
            } else {
                println!("   ⚠️ [{}] No assignment found", self.name);
            }
        }
    }

    async fn disconnect_socket(&mut self) {
        if let Some(ref mut socket) = self.socket_client {
            socket.disconnect().await;
            self.socket_client = None;
            println!("   🔗 [{}] Disconnected from socket", self.name);
        }
    }
}

fn decide_auto_action(available_actions: &[String], chips: u64, to_call: u64) -> (String, Option<u64>) {
    let random_val = random_u64() % 100;

    if available_actions.contains(&"check".to_string()) {
        if random_val > 70 && available_actions.contains(&"raise".to_string()) {
            ("raise".to_string(), Some(chips.min(100)))
        } else {
            ("check".to_string(), None)
        }
    } else if available_actions.contains(&"call".to_string()) {
        if to_call > chips {
            ("fold".to_string(), None)
        } else if random_val > 30 {
            ("call".to_string(), None)
        } else {
            ("fold".to_string(), None)
        }
    } else if available_actions.contains(&"fold".to_string()) {
        ("fold".to_string(), None)
    } else {
        ("check".to_string(), None)
    }
}

struct GameSimulator {
    client: Client,
    players: Vec<SimulatedPlayer>,
    table_states: Arc<RwLock<std::collections::HashMap<u32, ClientTable>>>,
    table_update_notify: Arc<Notify>,
}

impl GameSimulator {
    fn new() -> Self {
        Self {
            client: Client::new(),
            players: Vec::new(),
            table_states: Arc::new(RwLock::new(std::collections::HashMap::new())),
            table_update_notify: Arc::new(Notify::new()),
        }
    }

    async fn process_socket_events(&mut self) {
        for player in &mut self.players {
            let updates = player.process_socket_events().await;
            for payload in updates {
                self.table_states.write().insert(payload.table.id, payload.table);
                self.table_update_notify.notify_one();
            }
        }
    }

    async fn wait_for_table_update(&self, timeout: Duration) -> bool {
        tokio::select! {
            _ = self.table_update_notify.notified() => true,
            _ = tokio::time::sleep(timeout) => false,
        }
    }

    async fn add_player(&mut self, name: String, table_id: u32, wallet: &RistrettoWalletLogin) -> Result<(), Box<dyn std::error::Error>> {
        println!("👤 Adding player: {}...", name);

        let mut player = SimulatedPlayer::new(name, table_id, self.client.clone(), wallet.clone());
        let token = player.wallet_login().await?;

        player.connect_socket(&token).await.map_err(|e| e.to_string())?;

        let table_info = self.poll_game_state(table_id).await?;

        let deck_encrypted_value = table_info["shuffleState"]["deck_encrypted"].clone();

        let mut agg_pk = EcPoint::identity();
        if let Some(players) = table_info["players"].as_array() {
            for p in players {
                if let Some(pk_hex_str) = p["pkHex"].as_str() {
                    if let Ok(pk) = hex_to_ecpoint(pk_hex_str) {
                        agg_pk += &pk;
                    }
                }
            }
        }
        let agg_pk_hex = ecpoint_to_hex(&agg_pk);

        let deck_encrypted_json_str = serde_json::to_string(&deck_encrypted_value)?;
        tracing::debug!("add player input cards {:?}",deck_encrypted_json_str);   
        player.join_and_shuffle(&deck_encrypted_json_str, &agg_pk_hex).await?;

        self.players.push(player);
        Ok(())
    }

    async fn poll_game_state(&self, table_id: u32) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let resp = self.client
            .get(format!("{}/tables/{}", BASE_URL, table_id))
            .send()
            .await?;

        if resp.status().is_success() {
            let state: serde_json::Value = resp.json().await?;
            Ok(state)
        } else {
            Err("Failed to get game state".into())
        }
    }

    fn get_cached_table(&self, table_id: u32) -> Option<ClientTable> {
        self.table_states.read().get(&table_id).cloned()
    }

    async fn auto_play_round(&mut self, table_id: u32) -> Result<(), Box<dyn std::error::Error>> {
        println!("\n🎰 Starting automated gameplay (Socket.IO event-driven)...");

        let mut round_count = 0;
        let max_rounds = 200;
        let mut last_round_state = String::new();

        while round_count < max_rounds {
            self.process_socket_events().await;

            let game_state = match self.get_cached_table(table_id) {
                Some(s) => s,
                None => {
                    let raw = self.poll_game_state(table_id).await?;
                    match serde_json::from_value::<ClientTable>(raw) {
                        Ok(ct) => {
                            self.table_states.write().insert(table_id, ct.clone());
                            ct
                        }
                        Err(_) => {
                            tokio::time::sleep(Duration::from_millis(500)).await;
                            continue;
                        }
                    }
                }
            };

            if game_state.round_state != last_round_state {
                round_count += 1;
                last_round_state = game_state.round_state.clone();
                println!("\n--- Round {} --- Phase: {}, Pot: {}", round_count, game_state.round_state, game_state.pot);
            }

            if game_state.hand_over {
                println!("\n🏆 Hand complete!");
                self.print_final_state(&game_state).await;
                break;
            }

            if let Some(turn_seat_id) = game_state.turn {
                if let Some(current_player) = self.find_player_by_seat(&game_state, turn_seat_id) {
                    let available_actions = self.get_available_actions(&game_state, turn_seat_id);
                    let chips = self.get_player_chips(&game_state, turn_seat_id);
                    let to_call = self.get_to_call(&game_state, turn_seat_id);

                    println!("   🎲 {} (chips: {}) turn", current_player.name, chips);
                    println!("      Available actions: {:?}", available_actions);

                    let (action, amount) = decide_auto_action(&available_actions, chips, to_call);
                    println!("      🤖 Auto-play: {} ({:?})", action, amount);

                    match current_player.send_action(action.clone(), amount).await {
                        Ok(_) => println!("      ✅ Action succeeded"),
                        Err(e) => println!("      ❌ Action failed: {}", e),
                    }

                    tokio::time::sleep(Duration::from_millis(300)).await;
                    continue;
                }
            }

            if game_state.round_state == "shuffling" || game_state.round_state == "shuffleComplete" {
                println!("   ⏳ Waiting for shuffle phase...");
            }

            if !self.wait_for_table_update(Duration::from_secs(2)).await {
                self.process_socket_events().await;
            }
        }

        if round_count >= max_rounds {
            println!("⚠️ Max rounds reached");
        }

        Ok(())
    }

    fn find_player_by_seat(&self, game_state: &ClientTable, seat_id: u32) -> Option<&SimulatedPlayer> {
        let seat = game_state.seats.get(&seat_id)?.as_ref()?;
        let player = seat.player.as_ref()?;
        self.players.iter().find(|p| p.pk_hex == player.id)
    }

    fn get_available_actions(&self, game_state: &ClientTable, seat_id: u32) -> Vec<String> {
        let mut actions = vec!["fold".to_string()];

        let call_amount = game_state.call_amount.unwrap_or(0);

        let seat = match game_state.seats.get(&seat_id).and_then(|s| s.as_ref()) {
            Some(s) => s,
            None => return actions,
        };

        if call_amount == 0 || seat.bet >= call_amount {
            actions.push("check".to_string());
        }

        if call_amount > 0 && seat.bet < call_amount {
            actions.push("call".to_string());
        }

        actions.push("raise".to_string());

        actions
    }

    fn get_player_chips(&self, game_state: &ClientTable, seat_id: u32) -> u64 {
        game_state.seats.get(&seat_id)
            .and_then(|s| s.as_ref())
            .map(|s| s.stack)
            .unwrap_or(0)
    }

    fn get_to_call(&self, game_state: &ClientTable, seat_id: u32) -> u64 {
        let call_amount = game_state.call_amount.unwrap_or(0);
        let bet = game_state.seats.get(&seat_id)
            .and_then(|s| s.as_ref())
            .map(|s| s.bet)
            .unwrap_or(0);

        if call_amount > bet {
            call_amount - bet
        } else {
            0
        }
    }

    async fn print_final_state(&self, game_state: &ClientTable) {
        let separator = "=".repeat(60);
        println!("\n{}", separator);
        println!("FINAL GAME STATE");
        println!("{}", separator);
        println!("Phase: {}", game_state.round_state);
        println!("Pot: {}", game_state.pot);

        if !game_state.win_messages.is_empty() {
            println!("\n🏆 Winners:");
            for msg in &game_state.win_messages {
                println!("   {}", msg);
            }
        }

        println!("\nPlayers:");
        for (seat_id, seat_opt) in &game_state.seats {
            if let Some(seat) = seat_opt {
                if let Some(player) = &seat.player {
                    println!("  Seat {}: {} - Chips: {}, Folded: {}",
                        seat_id, player.name, seat.stack, seat.folded);
                }
            }
        }

        println!("{}", separator);
    }

    async fn run_full_simulation(&mut self, table_id: u32, num_players: usize) -> Result<(), Box<dyn std::error::Error>> {
        let separator = "=".repeat(60);
        println!("\n{}", separator);
        println!("🎮 VIN POKER GAME SIMULATOR (Socket.IO)");
        println!("Simulating a complete game with {} players on table {}", num_players, table_id);
        println!("{}", separator);
        let keystore = init_keystore();
        keystore.print_info();

        for i in 0..num_players {
            self.add_player(format!("Player{}", i + 1), table_id, &keystore.get(i + 1).unwrap()).await?;
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        println!("\n📋 Player Key Information:");
        for player in &self.players {
            player.print_key_info();
        }

        println!("\n⏳ Waiting for game to start...");
        tokio::time::sleep(Duration::from_secs(6)).await;

        self.auto_play_round(table_id).await?;

        for player in &mut self.players {
            player.disconnect_socket().await;
        }

        println!("\n✅ Simulation completed!");
        Ok(())
    }
}

fn random_u64() -> u64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u64(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64);
    hasher.finish()
}

fn init_keystore() -> RistrettoKeyStore {
    match KeyStore::load_or_create(KEYSTORE_PATH, KEYSTORE_COUNT) {
        Ok(store) => store,
        Err(e) => {
            eprintln!("❌ Failed to init keystore: {}", e);
            std::process::exit(1);
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into())
        )
        .init();

    let args: Vec<String> = std::env::args().collect();

    let table_id = if args.len() > 1 {
        args[1].parse::<u32>().unwrap_or(1)
    } else {
        1
    };

    let num_players = if args.len() > 2 {
        args[2].parse::<usize>().unwrap_or(2)
    } else {
        2
    };

    println!("🚀 Starting vin poker simulator with {} players on table {}...", num_players, table_id);

    let mut simulator = GameSimulator::new();

    if let Err(e) = simulator.run_full_simulation(table_id, num_players).await {
        eprintln!("\n❌ Simulation failed: {}", e);
        std::process::exit(1);
    }

    Ok(())
}
