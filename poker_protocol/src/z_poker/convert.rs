
use crate::crypto::{ElGamalCiphertext, Scalar, EcPoint, Plaintext};
use curve25519_dalek::ristretto::CompressedRistretto;

pub fn scalar_to_hex(s: &Scalar) -> String {
    hex::encode(s.as_bytes())
}

pub fn hex_to_scalar(hex_str: &str) -> Result<Scalar, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err("Scalar must be 32 bytes".to_string());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Option::from(Scalar::from_canonical_bytes(arr))
        .ok_or_else(|| "Invalid scalar value".to_string())
}

pub fn ecpoint_to_hex(p: &EcPoint) -> String {
    hex::encode(p.compress().as_bytes())
}

pub fn hex_to_ecpoint(hex_str: &str) -> Result<EcPoint, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;
    CompressedRistretto::from_slice(&bytes)
        .map_err(|e| format!("Invalid compressed point: {}", e))?
        .decompress()
        .ok_or_else(|| "Invalid EC point".to_string())
}
