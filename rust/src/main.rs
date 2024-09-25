use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    AeadCore, Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use hex;
use pbkdf2::pbkdf2_hmac_array;
use rand::RngCore;
use sha2::Sha256;

const SALT_SIZE: usize = 16;
const BLOCK_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const ROUNDS: u32 = 4096;

fn main() -> Result<()> {
    let passphrase = "passphrase";
    let plaintext = "plaintext";

    println!("passphrase: {}", passphrase);
    println!("plaintext: {}", plaintext);

    let encrypted = encrypt(passphrase, plaintext)?;
    println!("encrypted: {}", encrypted);

    let decrypted = decrypt(passphrase, &encrypted)?;
    println!("decrypted: {}", decrypted);

    Ok(())
}

fn encrypt(passphrase: &str, plaintext: &str) -> Result<String> {
    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);

    let key = pbkdf2_hmac_array::<Sha256, BLOCK_SIZE>(passphrase.as_bytes(), &salt, ROUNDS);
    let cipher = Aes256Gcm::new(&key.into());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|err| anyhow!("encrypt failed: {}", err))?;

    let mut result = Vec::with_capacity(SALT_SIZE + nonce.len() + ciphertext.len());
    result.extend_from_slice(&salt);
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);

    Ok(hex::encode(result))
}

fn decrypt(passphrase: &str, encoded_text: &str) -> Result<String> {
    let result = hex::decode(encoded_text)?;
    if result.len() < SALT_SIZE + NONCE_SIZE {
        return Err(anyhow!("ciphertext shorter than salt + nonce"));
    }

    let (salt, rest) = result.split_at(SALT_SIZE);
    let (nonce, ciphertext) = rest.split_at(NONCE_SIZE);

    let key = pbkdf2_hmac_array::<Sha256, BLOCK_SIZE>(passphrase.as_bytes(), &salt, ROUNDS);
    let cipher = Aes256Gcm::new(&key.into());
    let nonce = Nonce::from_slice(nonce);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|err| anyhow!("decrypt failed: {}", err))?;

    String::from_utf8(plaintext).map_err(|err| anyhow!("invalid utf-8: {}", err))
}
