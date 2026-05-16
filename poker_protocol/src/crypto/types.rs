pub use k256::ProjectivePoint as EcPoint;
use k256::Scalar as Sc;
use ff::{PrimeField, Field};
use group::{Group, GroupEncoding};
use sha2::{Sha256, Digest};

pub const N_CARDS: usize = 52;

pub type ECPoint = EcPoint;
pub type Scalar = Sc;
pub type Plaintext = EcPoint;

pub fn hash_to_scalar(digest: &[u8]) -> Scalar {
    let mut bytes = [0u8; 32];
    let len = 32.min(digest.len());
    bytes[..len].copy_from_slice(&digest[..len]);
    match Option::<Scalar>::from(Scalar::from_repr(bytes.into())) {
        Some(s) if s != Scalar::ZERO => s,
        _ => {
            let mut h = Sha256::new();
            h.update(b"hts_retry:");
            h.update(&bytes);
            let retry = h.finalize();
            let mut rb = [0u8; 32];
            rb.copy_from_slice(&retry);
            Option::<Scalar>::from(Scalar::from_repr(rb.into())).unwrap_or(Scalar::ONE)
        }
    }
}

fn get_base_g() -> EcPoint { EcPoint::GENERATOR }

fn get_base_h() -> EcPoint {
    let mut h = Sha256::new();
    h.update(b"crypto_independent_base_H_2024");
    let digest = h.finalize();
    let hash_bytes: [u8; 32] = digest.into();
    let prefix = if hash_bytes[0] % 2 == 0 { 0x02u8 } else { 0x03u8 };
    let mut bytes = [0u8; 33];
    bytes[0] = prefix;
    bytes[1..].copy_from_slice(&hash_bytes);
    loop {
        if let Some(point) = Option::<EcPoint>::from(EcPoint::from_bytes((&bytes).into())) {
            if !bool::from(point.is_identity()) { return point; }
        }
        bytes[31] = bytes[31].wrapping_add(1);
        if bytes[31] == 0 { bytes[30] = bytes[30].wrapping_add(1); }
    }
}

lazy_static::lazy_static! {
    pub static ref BASE_G: EcPoint = get_base_g();
    pub static ref BASE_H: EcPoint = get_base_h();
}
