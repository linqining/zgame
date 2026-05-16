
use crate::crypto::{ElGamalCiphertext, Scalar, EcPoint, Plaintext};
use ff::{Field, PrimeField};
use group::GroupEncoding;

pub fn scalar_to_hex(s: &Scalar) -> String {
    hex::encode(s.to_bytes())
}

pub fn hex_to_scalar(hex_str: &str) -> Result<Scalar, String> {
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

pub fn hex_to_ecpoint(hex_str: &str) -> Result<EcPoint, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;
    Option::<EcPoint>::from(EcPoint::from_bytes(bytes.as_slice().into()))
        .ok_or_else(|| "Invalid EC point".to_string())
}