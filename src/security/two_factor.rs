use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use sha2::{Digest, Sha256};
use totp_rs::{Builder, Secret};
use uuid::Uuid;

const SECRET_AAD: &[u8] = b"EcoVision administrator TOTP secret v1";

#[derive(Debug)]
pub enum TwoFactorError {
    TotpGeneration,
    InvalidKey,
    EncryptionFailed,
    DecryptionFailed,
}

impl std::fmt::Display for TwoFactorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TotpGeneration => write!(f, "falha ao gerar configuração TOTP"),
            Self::InvalidKey => write!(f, "chave de criptografia inválida"),
            Self::EncryptionFailed => write!(f, "falha ao criptografar segredo"),
            Self::DecryptionFailed => write!(f, "falha ao descriptografar segredo"),
        }
    }
}

impl std::error::Error for TwoFactorError {}

pub fn new_totp_setup(email: &str) -> Result<(String, String), TwoFactorError> {
    let totp = Builder::new()
        .with_secret(Secret::generate())
        .with_issuer(Some("Eco Vision".to_owned()))
        .with_account_name(email.to_owned())
        .build()
        .map_err(|_| TwoFactorError::TotpGeneration)?;
    let secret = totp.secret().to_base32();
    let uri = totp.to_url().map_err(|_| TwoFactorError::TotpGeneration)?;
    Ok((secret, uri))
}

pub fn verify_totp(email: &str, secret_base32: &str, code: &str) -> bool {
    let Ok(secret) = Secret::try_from_base32(secret_base32) else {
        return false;
    };
    let Ok(totp) = Builder::new()
        .with_secret(secret)
        .with_issuer(Some("Eco Vision".to_owned()))
        .with_account_name(email.to_owned())
        .build()
    else {
        return false;
    };
    totp.check_current(code.trim()).is_some()
}

pub fn encrypt_secret(secret: &str, key_hex: &str) -> Result<String, TwoFactorError> {
    let key = decode_key(key_hex).map_err(|_| TwoFactorError::InvalidKey)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| TwoFactorError::InvalidKey)?;
    let first_nonce = Uuid::new_v4();
    let second_nonce = Uuid::new_v4();
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[..6].copy_from_slice(&first_nonce.as_bytes()[..6]);
    nonce_bytes[6..].copy_from_slice(&second_nonce.as_bytes()[..6]);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: secret.as_bytes(),
                aad: SECRET_AAD,
            },
        )
        .map_err(|_| TwoFactorError::EncryptionFailed)?;
    let mut sealed = nonce_bytes.to_vec();
    sealed.extend_from_slice(&ciphertext);
    Ok(encode_hex(&sealed))
}

pub fn decrypt_secret(encrypted_hex: &str, key_hex: &str) -> Result<String, TwoFactorError> {
    let key = decode_key(key_hex).map_err(|_| TwoFactorError::InvalidKey)?;
    let sealed = decode_hex(encrypted_hex).map_err(|_| TwoFactorError::DecryptionFailed)?;
    if sealed.len() <= 12 {
        return Err(TwoFactorError::DecryptionFailed);
    }
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| TwoFactorError::InvalidKey)?;
    let nonce = Nonce::from_slice(&sealed[..12]);
    let plaintext = cipher
        .decrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: &sealed[12..],
                aad: SECRET_AAD,
            },
        )
        .map_err(|_| TwoFactorError::DecryptionFailed)?;
    String::from_utf8(plaintext).map_err(|_| TwoFactorError::DecryptionFailed)
}

pub fn create_recovery_codes() -> Vec<String> {
    (0..10)
        .map(|_| {
            let random = Uuid::new_v4().simple().to_string().to_uppercase();
            format!("{}-{}", &random[..8], &random[8..])
        })
        .collect()
}

pub fn hash_recovery_code(code: &str) -> String {
    let normalized: String = code
        .chars()
        .filter(|character| *character != '-')
        .flat_map(char::to_uppercase)
        .collect();
    format!("{:x}", Sha256::digest(normalized.as_bytes()))
}

fn decode_key(value: &str) -> Result<[u8; 32], ()> {
    let bytes = decode_hex(value)?;
    bytes.try_into().map_err(|_| ())
}

fn decode_hex(value: &str) -> Result<Vec<u8>, ()> {
    if !value.len().is_multiple_of(2) {
        return Err(());
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = hex_digit(pair[0]).ok_or(())?;
            let low = hex_digit(pair[1]).ok_or(())?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0f) as usize] as char);
    }
    result
}
