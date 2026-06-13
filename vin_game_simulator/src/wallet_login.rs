use sui_crypto::secp256k1::Secp256k1PrivateKey;
use sui_crypto::secp256k1::Secp256k1Verifier;
use sui_crypto::{SuiSigner, SuiVerifier};
use sui_sdk_types::PersonalMessage;
use sui_sdk_types::{UserSignature, SimpleSignature, Secp256k1PublicKey};
use poker_protocol::crypto::curve::{Curve, CurvePoint, RistrettoCurve};
use poker_protocol::z_poker::convert::curve_point_to_hex;
use blake2b_simd::Params;
use std::path::Path;

pub fn pubkey_to_curve_point<C: Curve>(pubkey_bytes: &[u8]) -> Result<C::Point, String> {
    C::Point::from_compressed(pubkey_bytes)
        .ok_or_else(|| "Invalid EC point".to_string())
}

/// Type alias for Ristretto255-based WalletLogin (backward compatibility).
pub type RistrettoWalletLogin = WalletLogin<RistrettoCurve>;
/// Type alias for Ristretto255-based KeyStore (backward compatibility).
pub type RistrettoKeyStore = KeyStore<RistrettoCurve>;

pub fn pubkey_to_sui_address(pubkey_bytes: &[u8], scheme_flag: u8) -> String {
    let mut hasher = Params::new().hash_length(32).to_state();
    hasher.update(&[scheme_flag]);
    hasher.update(pubkey_bytes);
    let hash = hasher.finalize();
    format!("0x{}", hex::encode(hash.as_bytes()))
}

#[derive(Debug, Clone)]
pub struct WalletLogin<C: Curve> {
    private_key: Secp256k1PrivateKey,
    _phantom: std::marker::PhantomData<C>,
}

impl<C: Curve> WalletLogin<C> {
    pub fn generate() -> Self {
        Self {
            private_key: Secp256k1PrivateKey::generate(&mut rand::thread_rng()),
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn from_private_key(private_key: Secp256k1PrivateKey) -> Self {
        Self { private_key, _phantom: std::marker::PhantomData }
    }

    pub fn from_pem(pem_str: &str) -> Result<Self, String> {
        let private_key = Secp256k1PrivateKey::from_pem(pem_str)
            .map_err(|e| format!("Invalid PEM: {}", e))?;
        Ok(Self { private_key, _phantom: std::marker::PhantomData })
    }

    pub fn private_key_pem(&self) -> String {
        self.private_key.to_pem()
            .expect("PEM export should not fail")
    }

    pub fn public_key(&self) -> Secp256k1PublicKey {
        self.private_key.public_key()
    }

    pub fn address(&self) -> String {
        pubkey_to_sui_address(self.public_key().as_bytes(), 0x01)
    }

    pub fn ecpoint(&self) -> Result<C::Point, String> {
        pubkey_to_curve_point::<C>(self.public_key().as_bytes())
    }

    pub fn sign_login_message(&self, message: &str) -> Result<UserSignature, String> {
        let personal_msg = PersonalMessage(message.as_bytes().into());
        self.private_key
            .sign_personal_message(&personal_msg)
            .map_err(|e| format!("Sign error: {}", e))
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct KeyStoreData {
    keys: Vec<String>,
}

pub struct KeyStore<C: Curve> {
    wallets: Vec<WalletLogin<C>>,
}

impl<C: Curve> KeyStore<C> {
    pub fn generate(count: usize) -> Self {
        let wallets: Vec<WalletLogin<C>> = (0..count)
            .map(|_| WalletLogin::generate())
            .collect();
        Self { wallets }
    }

    pub fn load_or_create(path: &str, count: usize) -> Result<Self, String> {
        if Path::new(path).exists() {
            Self::load(path)
        } else {
            let store = Self::generate(count);
            store.save(path)?;
            println!("Generated {} new keys, saved to {}", count, path);
            Ok(store)
        }
    }

    pub fn load(path: &str) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read key file: {}", e))?;
        let data: KeyStoreData = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse key file: {}", e))?;
        let wallets: Vec<WalletLogin<C>> = data.keys.iter()
            .map(|pem| WalletLogin::from_pem(pem))
            .collect::<Result<Vec<_>, _>>()?;
        println!("Loaded {} keys from {}", wallets.len(), path);
        Ok(Self { wallets })
    }

    pub fn save(&self, path: &str) -> Result<(), String> {
        let data = KeyStoreData {
            keys: self.wallets.iter()
                .map(|w| w.private_key_pem())
                .collect(),
        };
        let content = serde_json::to_string_pretty(&data)
            .map_err(|e| format!("Failed to serialize keys: {}", e))?;
        std::fs::write(path, content)
            .map_err(|e| format!("Failed to write key file: {}", e))?;
        Ok(())
    }

    pub fn get(&self, index: usize) -> Option<&WalletLogin<C>> {
        self.wallets.get(index)
    }

    pub fn len(&self) -> usize {
        self.wallets.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &WalletLogin<C>> {
        self.wallets.iter()
    }

    pub fn login(&self, index: usize, message: &str) -> Result<(String, UserSignature), String> {
        let wallet = self.get(index)
            .ok_or_else(|| format!("Key index {} out of range (0-{})", index, self.len() - 1))?;
        let address = wallet.address();
        let signature = wallet.sign_login_message(message)?;
        Ok((address, signature))
    }

    pub fn print_info(&self) {
        println!("\n{:=<70}", "");
        println!("  KeyStore - {} wallets", self.len());
        println!("{:=<70}", "");
        for (i, wallet) in self.wallets.iter().enumerate() {
            let address = wallet.address();
            let pk = wallet.public_key();
            let ecpoint = wallet.ecpoint()
                .map(|p| curve_point_to_hex::<C>(&p))
                .unwrap_or_else(|e| format!("Error: {}", e));
            println!("  [{}] Address: {}", i, address);
            println!("       PK:      {:?}", pk);
            println!("       EcPoint: {}...", &ecpoint[..16]);
        }
        println!("{:=<70}", "");
    }
}

pub struct LoginVerifier;

impl LoginVerifier {
    pub fn verify_login(
        message: &str,
        signature: &UserSignature,
        expected_address: &str,
    ) -> Result<String, String> {
        let personal_msg = PersonalMessage(message.as_bytes().into());
        let verifier = Secp256k1Verifier::default();
        verifier
            .verify_personal_message(&personal_msg, signature)
            .map_err(|e| format!("Signature verification failed: {}", e))?;

        let pk_bytes = match signature {
            UserSignature::Simple(SimpleSignature::Secp256k1 { public_key, .. }) => {
                public_key.as_bytes()
            }
            _ => return Err("Unsupported signature scheme".to_string()),
        };

        let derived_address = pubkey_to_sui_address(pk_bytes, 0x01);
        if derived_address != expected_address {
            return Err(format!(
                "Address mismatch: derived {} but expected {}",
                derived_address, expected_address
            ));
        }

        Ok(derived_address)
    }
}

 mod tests{
    use super::*;
    use poker_protocol::crypto::curve::RistrettoCurve;

    #[test]
    pub fn test_wallet_login_full_flow(){
        let wallet: WalletLogin<RistrettoCurve> = WalletLogin::generate();
        let address = wallet.address();
        let pk = wallet.public_key();
        let ecpoint = wallet.ecpoint().unwrap();

        println!("\n=== 1. 钱包信息 ===");
        println!("SUI Address: {}", address);
        println!("Public Key:  {:?}", pk);
        println!("EcPoint:     {}", curve_point_to_hex::<RistrettoCurve>(&ecpoint));

        let login_message = "login:secret-poker:1700000000";
        println!("\n=== 2. 签名登录消息 ===");
        println!("Message: {}", login_message);

        let signature = wallet.sign_login_message(login_message).unwrap();
        println!("Signature (base64): {}", signature.to_base64());

        println!("\n=== 3. 服务端验证 ===");
        let result = LoginVerifier::verify_login(login_message, &signature, &address);
        assert!(result.is_ok(), "Login verification should succeed");
        println!("Verified address: {}", result.unwrap());

        let wrong_address = "0x0000000000000000000000000000000000000000000000000000000000000000";
        let wrong_result = LoginVerifier::verify_login(login_message, &signature, wrong_address);
        assert!(wrong_result.is_err(), "Wrong address should fail");
        println!("Wrong address rejected: {}", wrong_result.unwrap_err());

        let wrong_message = "login:secret-poker:1699999999";
        let wrong_msg_result = LoginVerifier::verify_login(wrong_message, &signature, &address);
        assert!(wrong_msg_result.is_err(), "Wrong message should fail");
        println!("Wrong message rejected: {}", wrong_msg_result.unwrap_err());
    }

    #[test]
    pub fn test_login_with_existing_key(){
        let private_key = Secp256k1PrivateKey::generate(&mut rand::thread_rng());
        let wallet: WalletLogin<RistrettoCurve> = WalletLogin::from_private_key(private_key);
        let address = wallet.address();

        let message = "login:secret-poker:1700000000";
        let signature = wallet.sign_login_message(message).unwrap();

        let result = LoginVerifier::verify_login(message, &signature, &address);
        assert!(result.is_ok());
        println!("\nLogin with existing key verified: {}", result.unwrap());
    }

    #[test]
    pub fn test_keystore_save_load(){
        let dir = std::env::temp_dir().join("test_keystore");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("keys.json").to_str().unwrap().to_string();

        let store: KeyStore<RistrettoCurve> = KeyStore::generate(3);
        store.save(&path).unwrap();

        let loaded: KeyStore<RistrettoCurve> = KeyStore::load(&path).unwrap();
        assert_eq!(store.len(), loaded.len());

        for i in 0..store.len() {
            assert_eq!(store.get(i).unwrap().address(), loaded.get(i).unwrap().address());
        }

        let _ = std::fs::remove_file(&path);
        println!("\nKeyStore save/load test passed!");
    }

    #[test]
    pub fn test_keystore_login(){
        let store: KeyStore<RistrettoCurve> = KeyStore::generate(3);
        let message = "login:secret-poker:1700000000";

        let (address, signature) = store.login(0, message).unwrap();
        let result = LoginVerifier::verify_login(message, &signature, &address);
        assert!(result.is_ok());
        println!("\nKeyStore login test passed! Address: {}", result.unwrap());
    }

    #[test]
    pub fn test_conv(){
        let wallet: WalletLogin<RistrettoCurve> = WalletLogin::generate();
        let ecpoint = wallet.ecpoint().unwrap();
        println!("EcPoint: {:?}", curve_point_to_hex::<RistrettoCurve>(&ecpoint));
    }
}
