use poker_protocol::crypto::EcPoint;
use poker_protocol::crypto::CurvePoint;
use poker_protocol::z_poker::convert::hex_to_ecpoint;

pub async fn verify_sui_wallet_signature<'a>(
    message: &'a str,
    signature: &'a sui_sdk_types::UserSignature,
    expected_address: &'a str,
) -> Result<(String, String), String> {
    tracing::debug!("[verify_sui_wallet_signature] verifying signature, expected_address={}", expected_address);
    let personal_msg = sui_sdk_types::PersonalMessage(message.as_bytes().into());

    match signature {
        sui_sdk_types::UserSignature::Simple(simple_sig) => {
            verify_simple_signature(&personal_msg, simple_sig, expected_address)
        }
        sui_sdk_types::UserSignature::ZkLogin(zklogin) => {
            verify_zklogin_signature(&personal_msg, zklogin, expected_address).await
        }
        _ => {
            tracing::warn!("[verify_sui_wallet_signature] unsupported signature scheme");
            Err("Unsupported signature scheme. Only Ed25519, Secp256k1, Secp256r1, zkLogin are supported".to_string())
        }
    }
}

pub fn verify_simple_signature(
    personal_msg: &sui_sdk_types::PersonalMessage,
    simple_sig: &sui_sdk_types::SimpleSignature,
    expected_address: &str,
) -> Result<(String, String), String> {
    use sui_sdk::sui_crypto::Verifier;
    let verifier = sui_sdk::sui_crypto::simple::SimpleVerifier;
    let signing_digest = personal_msg.signing_digest();
    verifier.verify(signing_digest.as_ref(), simple_sig)
        .map_err(|e| {
            tracing::warn!("[verify_sui_wallet_signature] simple signature verification failed: {}", e);
            format!("Signature verification failed: {}", e)
        })?;

    let derived_address = match simple_sig {
        sui_sdk_types::SimpleSignature::Ed25519 { public_key, .. } => {
            tracing::debug!("[verify_sui_wallet_signature] ed25519 signature detected");
            public_key.derive_address().to_string()
        }
        sui_sdk_types::SimpleSignature::Secp256k1 { public_key, .. } => {
            tracing::debug!("[verify_sui_wallet_signature] secp256k1 signature detected");
            public_key.derive_address().to_string()
        }
        sui_sdk_types::SimpleSignature::Secp256r1 { public_key, .. } => {
            tracing::debug!("[verify_sui_wallet_signature] secp256r1 signature detected");
            public_key.derive_address().to_string()
        }
        _ => unreachable!(),
    };

    let expected_normalized = normalize_address(expected_address);
    if derived_address != expected_normalized {
        tracing::warn!("[verify_sui_wallet_signature] address mismatch: derived={} expected={}", derived_address, expected_normalized);
        return Err(format!("Address mismatch: derived {} but expected {}", derived_address, expected_normalized));
    }

    let pk_hex = match simple_sig {
        sui_sdk_types::SimpleSignature::Secp256k1 { public_key, .. } => {
            let pk_bytes = public_key.as_bytes();
            let ecpoint: Option<EcPoint> = <EcPoint as CurvePoint>::from_compressed(pk_bytes);
            match ecpoint {
                Some(point) => hex::encode(point.compress().as_ref()),
                None => {
                    tracing::warn!("[verify_sui_wallet_signature] invalid EC point from secp256k1 public key");
                    return Err("Invalid EC point from public key".to_string());
                }
            }
        }
        sui_sdk_types::SimpleSignature::Ed25519 { public_key, .. } => {
            hex::encode(public_key.as_bytes())
        }
        sui_sdk_types::SimpleSignature::Secp256r1 { public_key, .. } => {
            hex::encode(public_key.as_bytes())
        }
        _ => unreachable!(),
    };

    tracing::debug!("[verify_sui_wallet_signature] simple verification successful, address={}, pk_hex={}", derived_address, pk_hex);
    Ok((derived_address, pk_hex))
}

pub async fn verify_zklogin_signature<'a, 'b>(
    personal_msg: &'a sui_sdk_types::PersonalMessage<'b>,
    zklogin: &'a sui_sdk_types::ZkLoginAuthenticator,
    expected_address: &'a str,
) -> Result<(String, String), String> {
    tracing::debug!("[verify_sui_wallet_signature] zkLogin signature detected, iss={}", zklogin.inputs.iss());

    // Build the zkLogin verifier with mainnet verifying key
    let mut verifier = sui_sdk::sui_crypto::zklogin::ZkloginVerifier::new_mainnet();

    // Fetch JWK from the OIDC provider and add to verifier
    let jwk_id = zklogin.inputs.jwk_id();
    let jwk = fetch_jwk(&jwk_id.iss, &jwk_id.kid).await?;
    verifier.jwks_mut().insert(jwk_id.clone(), jwk);

    // Verify the zkLogin signature
    use sui_sdk::sui_crypto::Verifier;
    let signing_digest = personal_msg.signing_digest();
    verifier.verify(signing_digest.as_ref(), &sui_sdk_types::UserSignature::ZkLogin(Box::new(zklogin.clone())))
        .map_err(|e| {
            tracing::warn!("[verify_sui_wallet_signature] zkLogin verification failed: {}", e);
            format!("zkLogin verification failed: {}", e)
        })?;

    // Derive address from the zkLogin public identifier
    let derived_addresses: Vec<sui_sdk_types::Address> = zklogin.inputs.public_identifier().derive_address().collect();
    let expected_normalized = normalize_address(expected_address);

    let derived_address = derived_addresses.iter()
        .find(|a| a.to_string() == expected_normalized)
        .map(|a| a.to_string())
        .ok_or_else(|| {
            let derived_strs: Vec<String> = derived_addresses.iter().map(|a| a.to_string()).collect();
            tracing::warn!("[verify_sui_wallet_signature] zkLogin address mismatch: derived={:?} expected={}", derived_strs, expected_normalized);
            format!("Address mismatch: derived {:?} but expected {}", derived_strs, expected_normalized)
        })?;

    // For zkLogin, pk_hex is the ephemeral public key from the embedded simple signature
    let pk_hex = match &zklogin.signature {
        sui_sdk_types::SimpleSignature::Secp256k1 { public_key, .. } => {
            let pk_bytes = public_key.as_bytes();
            let ecpoint: Option<EcPoint> = <EcPoint as CurvePoint>::from_compressed(pk_bytes);
            match ecpoint {
                Some(point) => hex::encode(point.compress().as_ref()),
                None => hex::encode(public_key.as_bytes()),
            }
        }
        sui_sdk_types::SimpleSignature::Ed25519 { public_key, .. } => {
            hex::encode(public_key.as_bytes())
        }
        sui_sdk_types::SimpleSignature::Secp256r1 { public_key, .. } => {
            hex::encode(public_key.as_bytes())
        }
        _ => String::new(),
    };

    tracing::debug!("[verify_sui_wallet_signature] zkLogin verification successful, address={}, pk_hex={}", derived_address, pk_hex);
    Ok((derived_address, pk_hex))
}

/// Fetch a JWK from the OIDC provider's JWKS endpoint
pub async fn fetch_jwk<'a>(iss: &'a str, kid: &'a str) -> Result<sui_sdk_types::Jwk, String> {
    // Map issuer to JWKS URL
    let jwks_url = if iss.contains("google") {
        "https://www.googleapis.com/oauth2/v3/certs".to_string()
    } else if iss.contains("apple") {
        "https://appleid.apple.com/auth/keys".to_string()
    } else if iss.contains("facebook") {
        "https://www.facebook.com/.well-known/oauth/openid/keys/".to_string()
    } else if iss.contains("twitch") {
        "https://id.twitch.tv/oauth2/keys".to_string()
    } else if iss.contains("microsoft") || iss.contains("login.microsoftonline") {
        // Microsoft uses tenant-specific endpoints; try common discovery
        format!("{}/.well-known/openid-configuration", iss)
    } else {
        // Try OpenID discovery
        format!("{}/.well-known/openid-configuration", iss)
    };

    tracing::debug!("[fetch_jwk] fetching JWK from iss={}, kid={}, url={}", iss, kid, jwks_url);

    // Asynchronous HTTP request to fetch JWKS
    let client = reqwest::Client::new();
    let response = client
        .get(&jwks_url)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
        .map_err(|e| format!("Failed to fetch JWKS from {}: {}", jwks_url, e))?;

    let body = response.text()
        .await
        .map_err(|e| format!("Failed to read JWKS response: {}", e))?;

    // Parse the JWKS response to find the matching key
    let jwks: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| format!("Failed to parse JWKS JSON: {}", e))?;

    // Try to find the key in "keys" array (standard JWKS format)
    let keys = jwks.get("keys").and_then(|k| k.as_array())
        .ok_or_else(|| format!("No 'keys' array found in JWKS response from {}", jwks_url))?;

    for key in keys {
        if key.get("kid").and_then(|v| v.as_str()) == Some(kid) {
            let jwk = sui_sdk_types::Jwk {
                kty: key.get("kty").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                e: key.get("e").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                n: key.get("n").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                alg: key.get("alg").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            };
            tracing::debug!("[fetch_jwk] found matching JWK, kid={}", kid);
            return Ok(jwk);
        }
    }

    Err(format!("JWK with kid={} not found in JWKS from {}", kid, jwks_url))
}

pub fn normalize_address(addr: &str) -> String {
    if addr.starts_with("0x") {
        addr.to_lowercase()
    } else {
        format!("0x{}", addr).to_lowercase()
    }
}
