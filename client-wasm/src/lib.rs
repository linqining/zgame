use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use z_game::z_poker::protocol::ClientPlayer;
use z_game::z_poker::protocol::{JoinGameAndShuffleRound,MaskAndShuffleRound};
use z_game::crypto::{ElGamalCiphertext, Scalar, EcPoint, Plaintext};
use z_game::card_reveal::VerificationError;
use z_game::crypto::types::BASE_G;
use rand_core::OsRng;
use ff::{Field, PrimeField};
use elliptic_curve::group::GroupEncoding;
use serde_wasm_bindgen;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

fn console_log(msg: &str) {
    let _ = log(&format!("[client-wasm] {}", msg));
}

pub fn scalar_to_hex(s: &Scalar) -> String {
    hex::encode(s.to_bytes())
}

fn hex_to_scalar(hex_str: &str) -> Result<Scalar, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err("Scalar must be 32 bytes".to_string());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Option::<Scalar>::from(Scalar::from_repr(arr.into()))
        .ok_or_else(|| "Invalid scalar value".to_string())
}

pub fn ecpoint_to_hex(p: &EcPoint) -> String {
    hex::encode(p.to_bytes())
}

fn hex_to_ecpoint(hex_str: &str) -> Result<EcPoint, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;
    Option::<EcPoint>::from(EcPoint::from_bytes(bytes.as_slice().into()))
        .ok_or_else(|| "Invalid EC point".to_string())
}

fn ct_to_json(ct: &ElGamalCiphertext) -> String {
    format!(
        r#"{{"c1_hex":"{}","c2_hex":"{}","c3_hex":"{}"}}"#,
        ecpoint_to_hex(&ct.c1),
        ecpoint_to_hex(&ct.c2),
        ecpoint_to_hex(&ct.c3)
    )
}

fn obj_string_to_ct(val: serde_json::Value) -> Result<ElGamalCiphertext, String> {
    match val {
        serde_json::Value::Object(obj) => {
            Ok(ElGamalCiphertext {
                c1: hex_to_ecpoint(obj["c1_hex"].as_str().unwrap_or(""))?,
                c2: hex_to_ecpoint(obj["c2_hex"].as_str().unwrap_or(""))?,
                c3: hex_to_ecpoint(obj["c3_hex"].as_str().unwrap_or(""))?,
            })
        }
        _ => {
            console_log(&format!("obj_string_to_ct: parsed {:?}", val));
            Err("Invalid JSON object".to_string())
        }
    }
}

fn json_to_ct(json_str: &str) -> Result<ElGamalCiphertext, String> {
    let val: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| format!("JSON parse error: {}", e))?;
    Ok(ElGamalCiphertext {
        c1: hex_to_ecpoint(val["c1_hex"].as_str().unwrap_or(""))?,
        c2: hex_to_ecpoint(val["c2_hex"].as_str().unwrap_or(""))?,
        c3: hex_to_ecpoint(val["c3_hex"].as_str().unwrap_or(""))?,
    })
}

fn ct_vec_to_json(cts: &[ElGamalCiphertext]) -> String {
    let arr: Vec<String> = cts.iter().map(ct_to_json).collect();
    format!("[{}]", arr.join(","))
}

fn json_to_ct_vec(json_str: &str) -> Result<Vec<ElGamalCiphertext>, String> {
    let arr: Vec<serde_json::Value> = serde_json::from_str(json_str)
        .map_err(|e| format!("JSON parse error: {}", e))?;
    let mut result:Vec<ElGamalCiphertext> = vec![];
    for v in arr {
        result.push(obj_string_to_ct(v)?);
    }
    Ok(result)
}

fn reveal_token_proof_to_json(proof: &z_game::card_reveal::RevealTokenProof) -> String {
    format!(
        r#"{{"user_public_key_hex":"{}","commitment_t1_hex":"{}","commitment_t2_hex":"{}","response_s_hex":"{}"}}"#,
        ecpoint_to_hex(&proof.user_public_key),
        ecpoint_to_hex(&proof.commitment_t1),
        ecpoint_to_hex(&proof.commitment_t2),
        scalar_to_hex(&proof.response_s)
    )
}

fn json_to_reveal_token_proof(json_str: &str) -> Result<z_game::card_reveal::RevealTokenProof, String> {
    let val: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| format!("JSON parse error: {}", e))?;
    Ok(z_game::card_reveal::RevealTokenProof {
        user_public_key: hex_to_ecpoint(val["user_public_key"].as_str().unwrap_or(""))?,
        commitment_t1: hex_to_ecpoint(val["commitment_t1"].as_str().unwrap_or(""))?,
        commitment_t2: hex_to_ecpoint(val["commitment_t2"].as_str().unwrap_or(""))?,
        response_s: hex_to_scalar(val["response_s"].as_str().unwrap_or(""))?,
    })
}

#[derive(Serialize, Deserialize)]
pub struct PlayerKeys {
    pub player_pk: String,
    pub sk: String,
    pub pk: String,
}

#[wasm_bindgen]
pub struct WasmClientPlayer {
    inner: ClientPlayer,
}

fn json_val_to_jsvalue(s: String) -> JsValue {
    JsValue::from_str(&s)
}

#[wasm_bindgen]
impl WasmClientPlayer {
    #[wasm_bindgen(constructor)]
    pub fn new() -> WasmClientPlayer {
        console_log("Creating client player");
        WasmClientPlayer {
            inner: ClientPlayer::new(),
        }
    }

    pub fn from_sk(sk_hex: &str) -> Result<WasmClientPlayer, JsValue> {
        let sk = match hex_to_scalar(sk_hex) {
            Ok(s) => s,
            Err(e) => return Err(JsValue::from_str(&e)),
        };
        let pk = *BASE_G * &sk;
        Ok(WasmClientPlayer {
            inner: ClientPlayer { sk, pk },
        })
    }

    pub fn get_pk_hex(&self) -> String { ecpoint_to_hex(&self.inner.pk) }

    pub fn get_sk_hex(&self) -> String { scalar_to_hex(&self.inner.sk) }

    pub fn to_keys(&self) -> JsValue {
        let keys = PlayerKeys {
            player_pk: ecpoint_to_hex(&self.inner.pk),
            sk: scalar_to_hex(&self.inner.sk),
            pk: ecpoint_to_hex(&self.inner.pk),
        };
        match serde_wasm_bindgen::to_value(&keys) {
            Ok(v) => v,
            Err(_) => JsValue::NULL,
        }
    }

    pub fn generate_pk_proof(&self) -> JsValue {
        let proof = self.inner.generate_pk_proof();
        let s = format!(
            r#"{{"commitment_hex":"{}","response_hex":"{}"}}"#,
            ecpoint_to_hex(&proof.commitment),
            scalar_to_hex(&proof.response)
        );
        json_val_to_jsvalue(s)
    }

    pub fn decrypt_card(&self, ct_json: &str) -> Result<String, JsValue> {
        let ct = json_to_ct(ct_json).map_err(|e| JsValue::from_str(&e))?;
        let pt = self.inner.decrypt_card(&ct);
        Ok(ecpoint_to_hex(&pt))
    }

    pub fn peek_own_card(&self, ct_json: &str) -> Result<String, JsValue> {
        let ct = json_to_ct(ct_json).map_err(|e| JsValue::from_str(&e))?;
        let pt = self.inner.peek_own_card(&ct);
        Ok(ecpoint_to_hex(&pt))
    }

    pub fn peek_card(&self, ct_json: &str, tokens_json: &str) -> Result<String, JsValue> {
        let ct = json_to_ct(ct_json).map_err(|e| JsValue::from_str(&e))?;
        let tokens_arr: Vec<serde_json::Value> = match serde_json::from_str(tokens_json) {
            Ok(arr) => arr,
            Err(e) => return Err(JsValue::from_str(&format!("JSON error: {}", e))),
        };

        use z_game::z_poker::protocol::RevealToken as RT;
        let mut tokens: Vec<RT> = vec![];
        for tval in &tokens_arr {
            let encrypted_card = match json_to_ct(&tval.to_string()) {
                Ok(ct) => ct,
                Err(e) => return Err(JsValue::from_str(&e)),
            };
            let reveal_token = match hex_to_ecpoint(tval["reveal_token"].as_str().unwrap_or("")) {
                Ok(p) => p,
                Err(e) => return Err(JsValue::from_str(&e)),
            };
            let proof = match json_to_reveal_token_proof(&tval["proof"].to_string()) {
                Ok(p) => p,
                Err(e) => return Err(JsValue::from_str(&e)),
            };
            tokens.push(RT { user_public_key: hex_to_ecpoint(tval["user_public_key"].as_str().unwrap_or(""))?, encrypted_card, proof, reveal_token });
        }

        let pt = self.inner.peek_card(&ct, &tokens).map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
        Ok(ecpoint_to_hex(&pt))
    }

    pub fn generate_reveal_token(&self, ct_json: &str) -> Result<JsValue, JsValue> {
        let ct = json_to_ct(ct_json).map_err(|e| JsValue::from_str(&e))?;
        let token = self.inner.generate_reveal_token(&ct);

        let s = format!(
            r#"{{"encrypted_card":{},"reveal_token":"{}","proof":{}}}"#,
            ct_to_json(&token.encrypted_card),
            ecpoint_to_hex(&token.reveal_token),
            reveal_token_proof_to_json(&token.proof)
        );
        Ok(json_val_to_jsvalue(s))
    }

    pub fn batch_generate_reveal_token(&self, cts_json: &str) -> Result<JsValue, JsValue> {
        let cts = json_to_ct_vec(cts_json).map_err(|e| JsValue::from_str(&e))?;
        let tokens = self.inner.batch_generate_reveal_token(&cts);

        let items: Vec<String> = tokens.iter().enumerate().map(|(i, token)| {
            format!(
                r#"{{"card_index":{},"encrypted_card":{},"reveal_token_proof":{},"reveal_token_hex":"{}"}}"#,
                i,
                ct_to_json(&token.encrypted_card),
                reveal_token_proof_to_json(&token.proof),
                ecpoint_to_hex(&token.reveal_token)
            )
        }).collect();
        Ok(json_val_to_jsvalue(format!("[{}]", items.join(","))))
    }

    pub fn verify_and_reveal_from_token(token_json: &str) -> Result<String, JsValue> {
        let val: serde_json::Value = match serde_json::from_str(token_json) {
            Ok(v) => v,
            Err(e) => return Err(JsValue::from_str(&format!("JSON error: {}", e))),
        };
        let encrypted_card = match json_to_ct(&val["encrypted_card"].to_string()) {
            Ok(ct) => ct,
            Err(e) => return Err(JsValue::from_str(&e)),
        };
        let reveal_token = match hex_to_ecpoint(val["reveal_token"].as_str().unwrap_or("")) {
            Ok(p) => p,
            Err(e) => return Err(JsValue::from_str(&e)),
        };
        let proof = match json_to_reveal_token_proof(&val["proof"].to_string()) {
            Ok(p) => p,
            Err(e) => return Err(JsValue::from_str(&e)),
        };

        let token = z_game::z_poker::protocol::RevealToken {
            user_public_key: hex_to_ecpoint(val["user_public_key_hex"].as_str().unwrap_or(""))?,
            encrypted_card,
            proof,
            reveal_token,
        };

        let pt = ClientPlayer::verify_and_reveal_from_token(&token)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
        Ok(ecpoint_to_hex(&pt))
    }

    pub fn shuffle(&self, deck_encrypted_json: &str, agg_pk_hex: &str) -> Result<JsValue, JsValue> {
        let deck = json_to_ct_vec(deck_encrypted_json).map_err(|e| JsValue::from_str(&e))?;
        let agg_pk = hex_to_ecpoint(agg_pk_hex).map_err(|e| JsValue::from_str(&e))?;

        let round = self.inner.shuffle(&deck, &agg_pk);

        let s = format!(
            r#"{{"player_pk":"{}","input_cards":{},"output_cards":{}}}"#,
            ecpoint_to_hex(&self.inner.pk),
            ct_vec_to_json(&round.input_cards),
            ct_vec_to_json(&round.output_cards),
        );
        Ok(json_val_to_jsvalue(s))
    }
    pub fn join_game_and_shuffle(
        &self,
        deck_encrypted_json: &str,
        agg_pk_hex: &str,
    ) -> Result<JsValue, JsValue> {
        let deck = json_to_ct_vec(deck_encrypted_json).map_err(|e| JsValue::from_str(&e))?;
        let agg_pk = hex_to_ecpoint(agg_pk_hex).map_err(|e| JsValue::from_str(&e))?;

        let round = self.inner.join_game_and_shuffle(&deck, &agg_pk);
        let ms = &round.mask_and_shuffle_round;
        let remask_proof_json = format!(
            r#"{{"a_hex":"{}","b_hex":"{}","sum_c1_hex":"{}","sum_d2_hex":"{}","s_hex":"{}","nonce_hex":"{}"}}"#,
            ecpoint_to_hex(&ms.remask_proof.A),
            ecpoint_to_hex(&ms.remask_proof.B),
            ecpoint_to_hex(&ms.remask_proof.sum_c1),
            ecpoint_to_hex(&ms.remask_proof.sum_d2),
            scalar_to_hex(&ms.remask_proof.s),
            scalar_to_hex(&ms.remask_proof.nonce),
        );

        let zk_consistency_json = format!(
            r#"{{"d1_hex":"{}","d2_hex":"{}","a_g_hex":"{}","a_pk_hex":"{}","s_hex":"{}"}}"#,
            ecpoint_to_hex(&ms.proof.zk_consistency.d1),
            ecpoint_to_hex(&ms.proof.zk_consistency.d2),
            ecpoint_to_hex(&ms.proof.zk_consistency.a_g),
            ecpoint_to_hex(&ms.proof.zk_consistency.a_pk),
            scalar_to_hex(&ms.proof.zk_consistency.s),
        );

        let triple_dleq_json = format!(
            r#"{{"a_g_hex":"{}","a_pk_hex":"{}","a_h_hex":"{}","s_hex":"{}"}}"#,
            ecpoint_to_hex(&ms.proof.triple_dleq.A_g),
            ecpoint_to_hex(&ms.proof.triple_dleq.A_pk),
            ecpoint_to_hex(&ms.proof.triple_dleq.A_h),
            scalar_to_hex(&ms.proof.triple_dleq.s),
        );

        let product_arg_json = format!(
            r#"{{"a_hex":"{}","b_hex":"{}","c_hex":"{}","d_hex":"{}","s_hex":"{}","t_hex":"{}"}}"#,
            ecpoint_to_hex(&ms.proof.product_arg.A),
            ecpoint_to_hex(&ms.proof.product_arg.B),
            ecpoint_to_hex(&ms.proof.product_arg.C),
            ecpoint_to_hex(&ms.proof.product_arg.D),
            scalar_to_hex(&ms.proof.product_arg.s),
            scalar_to_hex(&ms.proof.product_arg.t),
        );

        let shuffle_proof_json = format!(
            r#"{{"zk_consistency":{},"triple_dleq":{},"product_arg":{},"global_challenge_hex":"{}","nonce_hex":"{}"}}"#,
            zk_consistency_json,
            triple_dleq_json,
            product_arg_json,
            scalar_to_hex(&ms.proof.global_challenge),
            scalar_to_hex(&ms.proof.nonce),
        );

        let mask_and_shuffle_json = format!(
            r#"{{"mask_cards":{},"remask_proof":{},"output_cards":{},"shuffle_proof":{}}}"#,
            ct_vec_to_json(&ms.mask_cards),
            remask_proof_json,
            ct_vec_to_json(&ms.output_cards),
            shuffle_proof_json,
        );

        let proof = round.pk_ownership_proof;
        let pk_proof_json = format!(
            r#"{{"commitment_hex":"{}","response_hex":"{}"}}"#,
            ecpoint_to_hex(&proof.commitment),
            scalar_to_hex(&proof.response)
        );

        let join_game_and_shuffle_json = format!(
            r#"{{"pk_ownership_proof":{},"pk_hex":"{}","mask_and_shuffle_round":{}}}"#,
            pk_proof_json,
            round.pk_hex,
            mask_and_shuffle_json,
        );        
        Ok(json_val_to_jsvalue(join_game_and_shuffle_json))
    }

    pub fn verify_remask_proof(
        &self,
        input_cards_json: &str,
        mask_cards_json: &str,
        remask_proof_json: &str,
        pk_hex: &str,
    ) -> Result<JsValue, JsValue> {
        let input_cards = json_to_ct_vec(input_cards_json).map_err(|e| JsValue::from_str(&e))?;
        let mask_cards = json_to_ct_vec(mask_cards_json).map_err(|e| JsValue::from_str(&e))?;
        let pk = hex_to_ecpoint(pk_hex).map_err(|e| JsValue::from_str(&e))?;

        let proof_val: serde_json::Value = match serde_json::from_str(remask_proof_json) {
            Ok(v) => v,
            Err(e) => return Err(JsValue::from_str(&format!("JSON parse error: {}", e))),
        };

        let proof = z_game::zk_shuffle::remask_proof::RemaskProof {
            A: hex_to_ecpoint(proof_val["a_hex"].as_str().unwrap_or(""))?,
            B: hex_to_ecpoint(proof_val["b_hex"].as_str().unwrap_or(""))?,
            sum_c1: hex_to_ecpoint(proof_val["sum_c1_hex"].as_str().unwrap_or(""))?,
            sum_d2: hex_to_ecpoint(proof_val["sum_d2_hex"].as_str().unwrap_or(""))?,
            s: hex_to_scalar(proof_val["s_hex"].as_str().unwrap_or(""))?,
            nonce: hex_to_scalar(proof_val["nonce_hex"].as_str().unwrap_or(""))?,
        };

        let valid = proof.verify(&input_cards, &mask_cards, &pk);
        Ok(json_val_to_jsvalue(if valid { "true" } else { "false" }.to_string()))
    }

    pub fn reveal_own_card(
        &self,
        hand_index: usize,
        hand_encrypted_json: &str,
        deck_plaintext_json: &str,
        agg_pk_hex: &str,
    ) -> Result<JsValue, JsValue> {
        let hand = json_to_ct_vec(hand_encrypted_json).map_err(|e| JsValue::from_str(&e))?;

        let pt_arr: Vec<String> = match serde_json::from_str(deck_plaintext_json) {
            Ok(arr) => arr,
            Err(e) => return Err(JsValue::from_str(&format!("JSON error: {}", e))),
        };
        let deck_pt: Vec<Plaintext> = pt_arr.iter()
            .map(|s| hex_to_ecpoint(s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| JsValue::from_str(&e))?;

        let agg_pk = hex_to_ecpoint(agg_pk_hex).map_err(|e| JsValue::from_str(&e))?;

        let token = self.inner.reveal_own_card(hand_index, &hand, &deck_pt, &agg_pk)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

        let s = format!(
            r#"{{"encrypted_card":{},"reveal_token":"{}","proof":{}}}"#,
            ct_to_json(&token.encrypted_card),
            ecpoint_to_hex(&token.reveal_token),
            reveal_token_proof_to_json(&token.proof)
        );
        Ok(json_val_to_jsvalue(s))
    }

    pub fn reveal_community(&self, comm_plaintext_hex: &str) -> Result<JsValue, JsValue> {
        let comm_pt = hex_to_ecpoint(comm_plaintext_hex).map_err(|e| JsValue::from_str(&e))?;
        let token = self.inner.reveal_community(comm_pt);

        let s = format!(
            r#"{{"encrypted_card":{},"reveal_token":"{}","proof":{}}}"#,
            ct_to_json(&token.encrypted_card),
            ecpoint_to_hex(&token.reveal_token),
            reveal_token_proof_to_json(&token.proof)
        );
        Ok(json_val_to_jsvalue(s))
    }

    pub fn generate_expel_proof(
        &self,
        hand_encrypted_json: &str,
        deck_plaintext_json: &str,
        agg_pk_hex: &str,
        per_card_tokens_json: &str,
    ) -> Result<JsValue, JsValue> {
        let hand = json_to_ct_vec(hand_encrypted_json).map_err(|e| JsValue::from_str(&e))?;

        let pt_arr: Vec<String> = match serde_json::from_str(deck_plaintext_json) {
            Ok(arr) => arr,
            Err(e) => return Err(JsValue::from_str(&format!("JSON error: {}", e))),
        };
        let deck_pt: Vec<Plaintext> = pt_arr.iter()
            .map(|s| hex_to_ecpoint(s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| JsValue::from_str(&e))?;

        let agg_pk = hex_to_ecpoint(agg_pk_hex).map_err(|e| JsValue::from_str(&e))?;

        let tokens_outer: Vec<Vec<serde_json::Value>> = if per_card_tokens_json.is_empty() || per_card_tokens_json == "[]" {
            vec![]
        } else {
            match serde_json::from_str(per_card_tokens_json) {
                Ok(arr) => arr,
                Err(e) => return Err(JsValue::from_str(&format!("Tokens JSON error: {}", e))),
            }
        };

        use z_game::z_poker::protocol::RevealToken as RT;
        let mut per_card_tokens: Vec<Vec<RT>> = vec![];
        for card_tokens in &tokens_outer {
            let mut card_token_vec = vec![];
            for tval in card_tokens {
                let encrypted_card = match json_to_ct(&tval.to_string()) {
                    Ok(ct) => ct,
                    Err(e) => return Err(JsValue::from_str(&e)),
                };
                let reveal_token = match hex_to_ecpoint(tval["reveal_token"].as_str().unwrap_or("")) {
                    Ok(p) => p,
                    Err(e) => return Err(JsValue::from_str(&e)),
                };
                let proof = match json_to_reveal_token_proof(&tval["proof"].to_string()) {
                    Ok(p) => p,
                    Err(e) => return Err(JsValue::from_str(&e)),
                };
                card_token_vec.push(RT { user_public_key: hex_to_ecpoint(tval["user_public_key"].as_str().unwrap_or(""))?, encrypted_card, proof, reveal_token });
            }
            per_card_tokens.push(card_token_vec);
        }

        let record = self.inner.generate_expel_proof(&hand, &deck_pt, &agg_pk, &per_card_tokens)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

        let pos_str: Vec<String> = record.expelled_card_positions.iter().map(|x| x.to_string()).collect();
        let s = format!(
            r#"{{"expelled_player_pk":"{}","output_cards":{},"expelled_card_positions":[{}],"user_cards":{},"agg_pk_at_proof_time":"{}","departed_player_pk":"{}"}}"#,
            record.expelled_player_pk,
            ct_vec_to_json(&record.output_cards),
            pos_str.join(","),
            ct_vec_to_json(&record.user_cards),
            ecpoint_to_hex(&record.agg_pk_at_proof_time),
            ecpoint_to_hex(&record.departed_player_pk)
        );
        Ok(json_val_to_jsvalue(s))
    }

    pub fn remask_card(&self, ct_json: &str, pk_hex: &str) -> Result<JsValue, JsValue> {
        let ct = json_to_ct(ct_json).map_err(|e| JsValue::from_str(&e))?;
        let pk = hex_to_ecpoint(pk_hex).map_err(|e| JsValue::from_str(&e))?;

        let (remasked, _alpha) = self.inner.remask_card(&ct, &pk);
        Ok(json_val_to_jsvalue(ct_to_json(&remasked)))
    }

    pub fn distributed_decrypt(&self, ct_json: &str, tokens_hexes: &str) -> Result<String, JsValue> {
        let ct = json_to_ct(ct_json).map_err(|e| JsValue::from_str(&e))?;
        let token_hexes: Vec<String> = match serde_json::from_str(tokens_hexes) {
            Ok(arr) => arr,
            Err(e) => return Err(JsValue::from_str(&format!("JSON error: {}", e))),
        };
        let tokens: Vec<EcPoint> = token_hexes.iter()
            .map(|h| hex_to_ecpoint(h))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| JsValue::from_str(&e))?;

        let pt = self.inner.distributed_decrypt(&ct, &tokens);
        Ok(ecpoint_to_hex(&pt))
    }

    pub fn distributed_decrypt_from_tokens(&self, ct_json: &str, tokens_json: &str) -> Result<String, JsValue> {
        let ct = json_to_ct(ct_json).map_err(|e| JsValue::from_str(&e))?;
        let tokens_arr: Vec<serde_json::Value> = match serde_json::from_str(tokens_json) {
            Ok(arr) => arr,
            Err(e) => return Err(JsValue::from_str(&format!("JSON error: {}", e))),
        };

        use z_game::z_poker::protocol::RevealToken as RT;
        let mut tokens: Vec<RT> = vec![];
        for tval in &tokens_arr {
            let encrypted_card = json_to_ct(&tval.to_string()).map_err(|e| JsValue::from_str(&e))?;
            let reveal_token = hex_to_ecpoint(tval["reveal_token"].as_str().unwrap_or(""))
                .map_err(|e| JsValue::from_str(&e))?;
            let proof = json_to_reveal_token_proof(&tval["proof"].to_string())
                .map_err(|e| JsValue::from_str(&e))?;
            tokens.push(RT { user_public_key: hex_to_ecpoint(tval["user_public_key"].as_str().unwrap_or(""))?, encrypted_card, proof, reveal_token });
        }

        let pt = ClientPlayer::distributed_decrypt_from_tokens(&ct, &tokens)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
        Ok(ecpoint_to_hex(&pt))
    }

    pub fn mask_card(&self, plaintext_hex: &str, pk_hex: &str) -> Result<JsValue, JsValue> {
        let pt = hex_to_ecpoint(plaintext_hex).map_err(|e| JsValue::from_str(&e))?;
        let pk = hex_to_ecpoint(pk_hex).map_err(|e| JsValue::from_str(&e))?;

        let (encrypted, _r) = self.inner.mask_card(&pt, &pk);
        Ok(json_val_to_jsvalue(ct_to_json(&encrypted)))
    }

    pub fn decrypt_playing_card(&self, ct_json: &str, other_tokens_json: &str) -> Result<String, JsValue> {
        let ct = json_to_ct(ct_json).map_err(|e| JsValue::from_str(&e))?;
        let tokens_arr: Vec<serde_json::Value> = serde_json::from_str(other_tokens_json)
            .map_err(|e| JsValue::from_str(&format!("JSON error: {}", e)))?;
        let mut other_tokens = Vec::new();
        for tval in &tokens_arr {
            let token_hex = tval.as_str().unwrap_or("");
            other_tokens.push(hex_to_ecpoint(token_hex).map_err(|e| JsValue::from_str(&e))?);
        }

        self.inner.decrypt_playing_card(&ct, other_tokens)
            .map(|card| card.to_string())
            .ok_or_else(|| JsValue::from_str("Failed to decrypt playing card"))
    }

    pub fn decrypt_readable_card(&self, ct_json: &str) -> Result<String, JsValue>  {
        let ct = json_to_ct(ct_json).map_err(|e| JsValue::from_str(&e))?;
        self.inner.decrypt_readable_card(&ct)
        .map(|card| card.to_string())
        .ok_or_else(|| JsValue::from_str("Failed to decrypt readable card"))
    }
}

#[wasm_bindgen]
pub fn compute_aggregate_key(pk_hexes: &str) -> Result<String, JsValue> {
    let pks: Vec<String> = match serde_json::from_str(pk_hexes) {
        Ok(arr) => arr,
        Err(e) => return Err(JsValue::from_str(&format!("JSON error: {}", e))),
    };

    let mut agg = EcPoint::IDENTITY;
    for pk_hex in &pks {
        let pk = match hex_to_ecpoint(pk_hex) {
            Ok(p) => p,
            Err(e) => return Err(JsValue::from_str(&e)),
        };
        agg = agg + pk;
    }
    Ok(ecpoint_to_hex(&agg))
}

#[wasm_bindgen]
pub fn encrypt_plaintext(plaintext_hex: &str, pk_hex: &str) -> Result<JsValue, JsValue> {
    let pt = hex_to_ecpoint(plaintext_hex).map_err(|e| JsValue::from_str(&e))?;
    let pk = hex_to_ecpoint(pk_hex).map_err(|e| JsValue::from_str(&e))?;
    let r = Scalar::random(&mut OsRng);
    let ct = ElGamalCiphertext::encrypt(&pt, &pk, &r);
    Ok(json_val_to_jsvalue(ct_to_json(&ct)))
}
