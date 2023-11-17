use super::{derive_static_secret, ValidationErr};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305,
};
use js_sys::Error;
use rand_core::OsRng;
use schnorrkel::SecretKey;
use serde::{Deserialize, Serialize};
use serde_json::to_string;
use sp_core::{sr25519, Bytes};
use wasm_bindgen::prelude::*;
use x25519_dalek::PublicKey;
use zeroize::Zeroize;

#[wasm_bindgen(js_name = encryptOnly)]
/// Encrypts, signs, and serializes a SignedMessage to JSON.
pub fn encrypt_only(sk: Vec<u8>, msg: Vec<u8>, pk: Vec<u8>) -> Result<String, Error> {
    let mut _raw_pk: [u8; 32] = [0; 32];
    _raw_pk.copy_from_slice(&pk[0..32]);
    let _pk = PublicKey::from(_raw_pk);
    let _msg = Bytes(msg);

    let mut sk_buff: [u8; 64] = [0; 64];
    sk_buff.copy_from_slice(&sk[0..64]);
    if sk.len() != 64 {
        return Err(Error::new("Secret key must be 64 bytes"));
    }

    let sec_key =
        SecretKey::from_ed25519_bytes(sk.as_slice()).map_err(|err| Error::new(&err.to_string()))?;
    let pair = sr25519::Pair::from(sec_key);
    let encrypted_message =
        EncryptedMessage::new(&pair, &_msg, &_pk).map_err(|err| Error::new(&err.to_string()))?;
    Ok(encrypted_message
        .to_json()
        .map_err(|err| Error::new(&err.to_string()))?)
}

#[wasm_bindgen (js_name = decryptOnly)]
/// Deserializes and decrypts a json encoded `EncryptedMessage`.
/// Returns the plaintext.
pub fn decrypt_only(sk: Vec<u8>, msg: String) -> Result<Vec<u8>, Error> {
    let sm: EncryptedMessage =
        serde_json::from_str(msg.as_str()).map_err(|err| Error::new(&err.to_string()))?;

    let sec_key =
        SecretKey::from_ed25519_bytes(sk.as_slice()).map_err(|err| Error::new(&err.to_string()))?;
    let pair = sr25519::Pair::from(sec_key);
    Ok(sm
        .decrypt(&pair)
        .map_err(|err| Error::new(&err.to_string()))?)
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct EncryptedMessage {
    /// The encrypted message.
    pub msg: Bytes,
    /// The intended recipients public key to be included in the signature.
    recip: [u8; 32],
    /// The signers public parameter used in diffie-hellman.
    a: [u8; 32],
    /// The message nonce used in ChaCha20Poly1305.
    nonce: [u8; 12],
}

impl EncryptedMessage {
    /// Encrypts and signs msg.
    /// sk is the sr25519 key used for signing and deriving a symmetric shared key
    /// via Diffie-Hellman for encryption.
    /// msg is the plaintext message to encrypt and sign
    /// recip is the public Diffie-Hellman parameter of the recipient.
    pub fn new(
        sk: &sr25519::Pair,
        msg: &Bytes,
        recip: &PublicKey,
    ) -> Result<EncryptedMessage, ValidationErr> {
        let mut s = derive_static_secret(sk);
        let a = x25519_dalek::PublicKey::from(&s);
        let shared_secret = s.diffie_hellman(recip);
        s.zeroize();

        let msg_nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bits; unique per message
        let cipher = ChaCha20Poly1305::new_from_slice(shared_secret.as_bytes())
            .map_err(|e| ValidationErr::Conversion(e.to_string()))?;
        let ciphertext = cipher
            .encrypt(&msg_nonce, msg.0.as_slice())
            .map_err(|e| ValidationErr::Encryption(e.to_string()))?;
        let mut static_nonce: [u8; 12] = [0; 12];
        static_nonce.copy_from_slice(&msg_nonce);

        Ok(EncryptedMessage {
            msg: sp_core::Bytes(ciphertext),
            recip: recip.to_bytes(),
            a: *a.as_bytes(),
            nonce: static_nonce,
        })
    }

    /// Decrypts the message and returns the plaintext.
    pub fn decrypt(&self, sk: &sr25519::Pair) -> Result<Vec<u8>, ValidationErr> {
        let mut static_secret = derive_static_secret(sk);
        let shared_secret = static_secret.diffie_hellman(&PublicKey::from(self.a));
        static_secret.zeroize();
        let cipher = ChaCha20Poly1305::new_from_slice(shared_secret.as_bytes())
            .map_err(|e| ValidationErr::Conversion(e.to_string()))?
            .decrypt(
                &generic_array::GenericArray::from(self.nonce),
                self.msg.0.as_slice(),
            )
            .map_err(|e| ValidationErr::Decryption(e.to_string()))?;
        Ok(cipher)
    }

    /// Returns the public DH parameter of the message sender.
    pub fn sender(&self) -> x25519_dalek::PublicKey {
        x25519_dalek::PublicKey::from(self.a)
    }

    /// Returns the public DH key of the message recipient.
    pub fn recipient(&self) -> PublicKey {
        PublicKey::from(self.recip)
    }

    /// Returns a serialized json string of self.
    pub fn to_json(&self) -> Result<String, ValidationErr> {
        Ok(to_string(self)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{mnemonic_to_pair, new_mnemonic};

    #[test]
    fn test_encrypt() {
        let plaintext = Bytes(vec![69, 42, 0]);

        let alice = mnemonic_to_pair(&new_mnemonic()).unwrap();

        let bob = mnemonic_to_pair(&new_mnemonic()).unwrap();
        let bob_secret = derive_static_secret(&bob);
        let bob_public_key = PublicKey::from(&bob_secret);

        // Test encryption
        let encrypted_message = EncryptedMessage::new(&alice, &plaintext, &bob_public_key).unwrap();

        // Test decryption
        let decrypted_message = encrypted_message.decrypt(&bob).unwrap();

        // Check the decrypted message equals the plaintext.
        assert_eq!(Bytes(decrypted_message), plaintext);

        // Check the encrypted message != the plaintext.
        assert_ne!(encrypted_message.msg, plaintext);
    }

    #[test]
    fn test_decryption_fails_with_wrong_keypair() {
        let plaintext = Bytes(vec![69, 42, 0]);

        let alice = mnemonic_to_pair(&new_mnemonic()).unwrap();

        let bob = mnemonic_to_pair(&new_mnemonic()).unwrap();
        let bob_secret = derive_static_secret(&bob);
        let bob_public_key = PublicKey::from(&bob_secret);

        let charlie = mnemonic_to_pair(&new_mnemonic()).unwrap();

        // Test encryption
        let encrypted_message = EncryptedMessage::new(&alice, &plaintext, &bob_public_key).unwrap();

        // Test decryption
        assert!(encrypted_message.decrypt(&charlie).is_err());
    }
}
