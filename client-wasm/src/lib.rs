use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use poker_protocol::z_poker::protocol::ClientPlayer;
use poker_protocol::crypto::{ElGamalCiphertext, Scalar, EcPoint, Plaintext};
use poker_protocol::zk_shuffle::reveal_token_proof::RevealTokenProof;
use poker_protocol::crypto::types::BASE_G;
use rand_core::OsRng;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::traits::Identity;
use serde_wasm_bindgen;
use poker_protocol::crypto::RistrettoCurve;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

fn console_log(msg: &str) {
    let _ = log(&format!("[client-wasm] {}", msg));
}

pub fn scalar_to_hex(s: &Scalar) -> String {
    hex::encode(s.as_bytes())
}

fn hex_to_scalar(hex_str: &str) -> Result<Scalar, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err("Scalar must be 32 bytes".to_string());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Option::from(Scalar::from_canonical_bytes(arr)).ok_or_else(|| "Invalid scalar value".to_string())
}

pub fn ecpoint_to_hex(p: &EcPoint) -> String {
    hex::encode(p.compress().as_bytes())
}

fn hex_to_ecpoint(hex_str: &str) -> Result<EcPoint, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;
    CompressedRistretto::from_slice(&bytes).ok().and_then(|c| c.decompress()).ok_or_else(|| "Invalid EC point".to_string())
}

fn ct_to_json(ct: &ElGamalCiphertext) -> String {
    format!(
        r#"{{"c1_hex":"{}","c2_hex":"{}"}}"#,
        ecpoint_to_hex(&ct.c1),
        ecpoint_to_hex(&ct.c2)
    )
}

fn ct_generic_to_json(ct: &poker_protocol::crypto::ElGamalCiphertextGeneric<RistrettoCurve>) -> String {
    format!(
        r#"{{"c1_hex":"{}","c2_hex":"{}"}}"#,
        ecpoint_to_hex(&ct.c1),
        ecpoint_to_hex(&ct.c2)
    )
}

fn obj_string_to_ct(val: serde_json::Value) -> Result<ElGamalCiphertext, String> {
    match val {
        serde_json::Value::Object(obj) => {
            Ok(ElGamalCiphertext {
                c1: hex_to_ecpoint(obj["c1_hex"].as_str().unwrap_or(""))?,
                c2: hex_to_ecpoint(obj["c2_hex"].as_str().unwrap_or(""))?,
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

fn reveal_token_proof_to_json(proof: &RevealTokenProof<RistrettoCurve>) -> String {
    format!(
        r#"{{"user_public_key_hex":"{}","commitment_t1_hex":"{}","commitment_t2_hex":"{}","response_s_hex":"{}"}}"#,
        ecpoint_to_hex(&proof.user_public_key),
        ecpoint_to_hex(&proof.commitment_t1),
        ecpoint_to_hex(&proof.commitment_t2),
        scalar_to_hex(&proof.response_s)
    )
}

fn json_to_reveal_token_proof(json_str: &str) -> Result<RevealTokenProof<RistrettoCurve>, String> {
    let val: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| format!("JSON parse error: {}", e))?;
    Ok(RevealTokenProof {
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

    pub fn peek_card(&self, ct_json: &str, tokens_json: &str, plain_cards_json: &str) -> Result<String, JsValue> {
        let ct = json_to_ct(ct_json).map_err(|e| JsValue::from_str(&e))?;
        let tokens_arr: Vec<serde_json::Value> = match serde_json::from_str(tokens_json) {
            Ok(arr) => arr,
            Err(e) => return Err(JsValue::from_str(&format!("JSON error: {}", e))),
        };

        use poker_protocol::z_poker::protocol::RevealToken as RT;
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

        let pt_arr: Vec<String> = serde_json::from_str(plain_cards_json)
            .map_err(|e| JsValue::from_str(&format!("JSON error: {}", e)))?;
        let plain_cards: Vec<Plaintext> = pt_arr.iter()
            .map(|s| hex_to_ecpoint(s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| JsValue::from_str(&e))?;

        let pt = self.inner.peek_card(&ct, &tokens, &plain_cards).map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
        Ok(ecpoint_to_hex(&pt.0))
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

        let token = poker_protocol::z_poker::protocol::RevealToken {
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

        fn schnorr_proof_to_json(proof: &poker_protocol::zk_shuffle::generalized_schnorr_proof::GeneralizedSchnorrProof<RistrettoCurve>) -> String {
            let responses_hex: Vec<String> = proof.responses.iter().map(scalar_to_hex).collect();
            format!(
                r#"{{"commitment_hex":"{}","responses_hex":[{}]}}"#,
                ecpoint_to_hex(&proof.commitment),
                responses_hex.iter().map(|s| format!("\"{}\"", s)).collect::<Vec<_>>().join(",")
            )
        }

        let shuffle_proof_json = format!(
            r#"{{"sum_c1_commit_hex":"{}","sum_c2_commit_hex":"{}","combined_schnorr_proof":{},"sum_c1_schnorr_proof":{},"sum_c2_schnorr_proof":{},"nonce_hex":"{}"}}"#,
            ecpoint_to_hex(&round.proof.sum_c1_commit),
            ecpoint_to_hex(&round.proof.sum_c2_commit),
            schnorr_proof_to_json(&round.proof.combined_schnorr_proof),
            schnorr_proof_to_json(&round.proof.sum_c1_schnorr_proof),
            schnorr_proof_to_json(&round.proof.sum_c2_schnorr_proof),
            scalar_to_hex(&round.proof.nonce),
        );

        let s = format!(
            r#"{{"player_pk":"{}","input_cards":{},"output_cards":{},"shuffle_proof":{}}}"#,
            ecpoint_to_hex(&self.inner.pk),
            ct_vec_to_json(&round.input_cards),
            ct_vec_to_json(&round.output_cards),
            shuffle_proof_json,
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
        let per_card_commitments_hex: Vec<String> = ms.remask_proof.per_card_commitments.iter()
            .map(ecpoint_to_hex).collect();
        let remask_proof_json = format!(
            r#"{{"per_card_commitments_hex":{},"commitment_pk_hex":"{}","response_hex":"{}","nonce_hex":"{}"}}"#,
            serde_json::to_string(&per_card_commitments_hex).unwrap_or("[]".to_string()),
            ecpoint_to_hex(&ms.remask_proof.commitment_pk),
            scalar_to_hex(&ms.remask_proof.response),
            scalar_to_hex(&ms.remask_proof.nonce),
        );

        fn schnorr_proof_to_json(proof: &poker_protocol::zk_shuffle::generalized_schnorr_proof::GeneralizedSchnorrProof<RistrettoCurve>) -> String {
            let responses_hex: Vec<String> = proof.responses.iter().map(scalar_to_hex).collect();
            format!(
                r#"{{"commitment_hex":"{}","responses_hex":[{}]}}"#,
                ecpoint_to_hex(&proof.commitment),
                responses_hex.iter().map(|s| format!("\"{}\"", s)).collect::<Vec<_>>().join(",")
            )
        }

        let shuffle_proof_json = format!(
            r#"{{"sum_c1_commit_hex":"{}","sum_c2_commit_hex":"{}","combined_schnorr_proof":{},"sum_c1_schnorr_proof":{},"sum_c2_schnorr_proof":{},"nonce_hex":"{}"}}"#,
            ecpoint_to_hex(&ms.proof.sum_c1_commit),
            ecpoint_to_hex(&ms.proof.sum_c2_commit),
            schnorr_proof_to_json(&ms.proof.combined_schnorr_proof),
            schnorr_proof_to_json(&ms.proof.sum_c1_schnorr_proof),
            schnorr_proof_to_json(&ms.proof.sum_c2_schnorr_proof),
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
        _hand_encrypted_json: &str,
        _agg_pk_hex: &str,
        _per_card_tokens_json: &str,
    ) -> Result<JsValue, JsValue> {
        Err(JsValue::from_str("generate_expel_proof is no longer supported"))
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

        use poker_protocol::z_poker::protocol::RevealToken as RT;
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

    pub fn decrypt_playing_card(&self, ct_json: &str, other_tokens_json: &str, deck_plaintext_json: &str) -> Result<String, JsValue> {
        let ct = json_to_ct(ct_json).map_err(|e| JsValue::from_str(&e))?;
        let tokens_arr: Vec<serde_json::Value> = serde_json::from_str(other_tokens_json)
            .map_err(|e| JsValue::from_str(&format!("JSON error: {}", e)))?;
        let mut other_tokens = Vec::new();
        for tval in &tokens_arr {
            let token_hex = tval.as_str().unwrap_or("");
            other_tokens.push(hex_to_ecpoint(token_hex).map_err(|e| JsValue::from_str(&e))?);
        }

        let pt_arr: Vec<String> = serde_json::from_str(deck_plaintext_json)
            .map_err(|e| JsValue::from_str(&format!("JSON error: {}", e)))?;
        let deck_plaintext: Vec<Plaintext> = pt_arr.iter()
            .map(|s| hex_to_ecpoint(s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| JsValue::from_str(&e))?;

        self.inner.decrypt_playing_card(&ct, other_tokens, deck_plaintext)
            .map(|card| card.to_string())
            .ok_or_else(|| JsValue::from_str("Failed to decrypt playing card"))
    }

    pub fn decrypt_readable_card(&self, ct_json: &str, deck_plaintext_json: &str) -> Result<String, JsValue>  {
        let ct = json_to_ct(ct_json).map_err(|e| JsValue::from_str(&e))?;

        let pt_arr: Vec<String> = serde_json::from_str(deck_plaintext_json)
            .map_err(|e| JsValue::from_str(&format!("JSON error: {}", e)))?;
        let deck_plaintext: Vec<Plaintext> = pt_arr.iter()
            .map(|s| hex_to_ecpoint(s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| JsValue::from_str(&e))?;

        self.inner.decrypt_readable_card(&ct, deck_plaintext)
        .map(|card| card.to_string())
        .ok_or_else(|| JsValue::from_str("Failed to decrypt readable card"))
    }

    pub fn reconstruct(
        &self,
        origin_cards_json: &str,
        user_readable_cards_json: &str,
        coefficient_hex: &str,
    ) -> Result<JsValue, JsValue> {
        let origin_pt_arr: Vec<String> = serde_json::from_str(origin_cards_json)
            .map_err(|e| JsValue::from_str(&format!("JSON error: {}", e)))?;
        let origin_cards: Vec<EcPoint> = origin_pt_arr.iter()
            .map(|s| hex_to_ecpoint(s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| JsValue::from_str(&e))?;

        let user_readable_cards = json_to_ct_vec(user_readable_cards_json)
            .map_err(|e| JsValue::from_str(&e))?;

        let coefficient = hex_to_scalar(coefficient_hex)
            .map_err(|e| JsValue::from_str(&e))?;

        let result = self.inner.reconstruct(&origin_cards, &user_readable_cards, &coefficient)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

        fn schnorr_proof_to_json(proof: &poker_protocol::zk_shuffle::generalized_schnorr_proof::GeneralizedSchnorrProof<RistrettoCurve>) -> String {
            let responses_hex: Vec<String> = proof.responses.iter().map(scalar_to_hex).collect();
            format!(
                r#"{{"commitment_hex":"{}","responses_hex":[{}]}}"#,
                ecpoint_to_hex(&proof.commitment),
                responses_hex.iter().map(|s| format!("\"{}\"", s)).collect::<Vec<_>>().join(",")
            )
        }

        fn chaum_pedersen_proof_to_json(proof: &poker_protocol::zk_shuffle::reconstruction::ChaumPedersenDLEQProof<RistrettoCurve>) -> String {
            format!(
                r#"{{"commitment_a_hex":"{}","commitment_b_hex":"{}","response_hex":"{}"}}"#,
                ecpoint_to_hex(&proof.commitment_a),
                ecpoint_to_hex(&proof.commitment_b),
                scalar_to_hex(&proof.response)
            )
        }

        fn reconstruction_dleq_proof_to_json(proof: &poker_protocol::zk_shuffle::reconstruction::ReconstructionDLEQProof<RistrettoCurve>) -> String {
            format!(
                r#"{{"commitment_hex":"{}","response_hex":"{}","nonce_hex":"{}"}}"#,
                ecpoint_to_hex(&proof.commitment),
                scalar_to_hex(&proof.response),
                scalar_to_hex(&proof.nonce)
            )
        }

        fn swap_out_card_proof_to_json(proof: &poker_protocol::zk_shuffle::reconstruction::SwapOutCardProof<RistrettoCurve>) -> String {
            format!(
                r#"{{"user_readable_card":{},"swap_out_card":{},"chaum_pedersen_proof":{}}}"#,
                ct_generic_to_json(&proof.user_readable_card),
                ct_generic_to_json(&proof.swap_out_card),
                chaum_pedersen_proof_to_json(&proof.chaum_pedersen_proof)
            )
        }

        let swap_out_proofs_json: Vec<String> = result.proof.swap_out_cards_proofs.iter()
            .map(swap_out_card_proof_to_json).collect();

        let proof_json = format!(
            r#"{{"swap_out_cards_proofs":[{}],"sum_c1_r_commit_hex":"{}","sum_c2_r_commit_hex":"{}","swap_sum_c1_commit_hex":"{}","swap_sum_c2_commit_hex":"{}","nonce_hex":"{}","blind_dleq_proof":{},"total_dleq_proof":{},"swap_combined_schnorr_proof":{},"sum_swap_out_c1_schnorr_proof":{},"sum_swap_out_c2_schnorr_proof":{}}}"#,
            swap_out_proofs_json.join(","),
            ecpoint_to_hex(&result.proof.sum_c1_r_commit),
            ecpoint_to_hex(&result.proof.sum_c2_r_commit),
            ecpoint_to_hex(&result.proof.swap_sum_c1_commit),
            ecpoint_to_hex(&result.proof.swap_sum_c2_commit),
            scalar_to_hex(&result.proof.nonce),
            reconstruction_dleq_proof_to_json(&result.proof.blind_dleq_proof),
            chaum_pedersen_proof_to_json(&result.proof.total_dleq_proof),
            schnorr_proof_to_json(&result.proof.swap_combined_schnorr_proof),
            schnorr_proof_to_json(&result.proof.sum_swap_out_c1_schnorr_proof),
            schnorr_proof_to_json(&result.proof.sum_swap_out_c2_schnorr_proof)
        );

        let s = format!(
            r#"{{"output_cards":{},"swap_cards":{},"proof":{}}}"#,
            ct_vec_to_json(&result.output_cards),
            ct_vec_to_json(&result.swap_cards),
            proof_json
        );
        Ok(json_val_to_jsvalue(s))
    }
}

#[wasm_bindgen]
pub fn compute_aggregate_key(pk_hexes: &str) -> Result<String, JsValue> {
    let pks: Vec<String> = match serde_json::from_str(pk_hexes) {
        Ok(arr) => arr,
        Err(e) => return Err(JsValue::from_str(&format!("JSON error: {}", e))),
    };

    let mut agg = EcPoint::identity();
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
