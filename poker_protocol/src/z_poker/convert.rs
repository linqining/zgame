use crate::crypto::{Scalar, EcPoint};
use crate::crypto::curve::{CurveScalar, CurvePoint};

pub fn scalar_to_hex(s: &Scalar) -> String {
    hex::encode(s.as_bytes())
}

pub fn hex_to_scalar(hex_str: &str) -> Result<Scalar, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err("Scalar must be 32 bytes".to_string());
    }
    Ok(Scalar::from_bytes_mod_order(&bytes))
}

pub fn ecpoint_to_hex(p: &EcPoint) -> String {
    hex::encode(p.compress().as_ref())
}

pub fn hex_to_ecpoint(hex_str: &str) -> Result<EcPoint, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;
    if bytes.len() != 48 {
        return Err("EC point must be 48 bytes (BLS12-381 compressed)".to_string());
    }
    let arr: [u8; 48] = bytes.try_into().map_err(|_| "EC point must be 48 bytes".to_string())?;
    let ct_opt = EcPoint::from_compressed(&arr);
    if bool::from(ct_opt.is_some()) {
        Ok(ct_opt.unwrap())
    } else {
        Err("Invalid EC point".to_string())
    }
}
