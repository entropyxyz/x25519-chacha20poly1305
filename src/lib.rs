use bip39::Mnemonic;
use blake2::{Blake2s256, Digest};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305,
};
use hex;
use js_sys::Error;
use rand_core::OsRng;
use schnorrkel::{MiniSecretKey, SecretKey};
use serde::{Deserialize, Serialize};
use serde_json::to_string;
use sp_core::{crypto::AccountId32, sr25519, sr25519::Signature, Bytes, Pair};
use thiserror::Error;
use wasm_bindgen::prelude::*;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

const HEX_PREFIX: [u8; 2] = [48, 120];

/// Convert a Vec<u8> to a hex encoded string
#[wasm_bindgen]
pub fn to_hex(v: Vec<u8>) -> String {
    hex::encode(v)
}

/// Convert a hex string to a Vec<u8>, ignoring 0x prefix
#[wasm_bindgen]
pub fn from_hex(v: String) -> Result<Vec<u8>, Error> {
    let mut to_decode: String = v;
    if to_decode.len() >= 2 {
        let prefix = to_decode[0..2].as_bytes();
        if (prefix[0] == HEX_PREFIX[0]) && (prefix[1] == HEX_PREFIX[1]) {
            to_decode = to_decode[2..].to_string();
        }
    }
    Ok(hex::decode(to_decode).map_err(|err| Error::new(&err.to_string()))?)
}

#[wasm_bindgen]
/// Derives a public DH key from a static DH secret.
/// sk must be 64 bytes in length or an error will be returned.
pub fn public_key_from_secret(sk: Vec<u8>) -> Result<Vec<u8>, Error> {
    if sk.len() != 64 {
        return Err(Error::new("Secret key must be 64 bytes"));
    }
    let sec_key =
        SecretKey::from_ed25519_bytes(sk.as_slice()).map_err(|err| Error::new(&err.to_string()))?;
    let pair = sr25519::Pair::from(sec_key);
    let ss = derive_static_secret(&pair);
    Ok(PublicKey::from(&ss).as_bytes().to_vec())
}

// TODO i don't think this is needed as nonce generation is done internally
/// Generate a 12 byte random nonce
pub fn gen_msg_nonce() -> Result<Vec<u8>, Error> {
    let mut vec: Vec<u8> = vec![0; 12];
    getrandom::getrandom(&mut vec).map_err(|err| Error::new(&err.to_string()))?;
    return Ok(vec);
}

#[wasm_bindgen]
/// Generates a Ristretto Schnorr secret key.
/// This method is used for testing, applications that implement this
/// library should rely on user provided keys generated from substrate.
pub fn gen_signing_key() -> Result<Vec<u8>, Error> {
    let mini_secret_key = MiniSecretKey::generate();
    let secret_key: SecretKey = mini_secret_key.expand(MiniSecretKey::ED25519_MODE);
    let _sk: [u8; 64] = secret_key.to_bytes();
    let sk = SecretKey::from_bytes(&_sk).map_err(|err| Error::new(&err.to_string()))?;
    Ok(sk.to_bytes().to_vec())
}

#[wasm_bindgen]
/// Encrypts, signs, and serializes a SignedMessage to JSON.
pub fn encrypt_and_sign(sk: Vec<u8>, msg: Vec<u8>, pk: Vec<u8>) -> Result<String, Error> {
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
    let signed_message =
        SignedMessage::new(&pair, &_msg, &_pk).map_err(|err| Error::new(&err.to_string()))?;
    Ok(signed_message
        .to_json()
        .map_err(|err| Error::new(&err.to_string()))?)
}

#[wasm_bindgen]
/// Deserializes, verifies and decrypts a json encoded `SignedMessage`.
/// Returns the plaintext.
pub fn decrypt_and_verify(sk: Vec<u8>, msg: String) -> Result<Vec<u8>, Error> {
    let sm: SignedMessage =
        serde_json::from_str(msg.as_str()).map_err(|err| Error::new(&err.to_string()))?;

    if !sm.verify() {
        return Err(Error::new("Failed to verify signature"));
    }

    let sec_key =
        SecretKey::from_ed25519_bytes(sk.as_slice()).map_err(|err| Error::new(&err.to_string()))?;
    let pair = sr25519::Pair::from(sec_key);
    Ok(sm
        .decrypt(&pair)
        .map_err(|err| Error::new(&err.to_string()))?)
}

/// Constant time not-equal compare for two equal sized byte vectors.
/// Returns 0 if a == b, else 1.
fn constant_time_ne(a: &Vec<u8>, b: &Vec<u8>) -> u8 {
    assert!(a.len() == b.len());
    let mut tmp = 0;
    for i in 0..a.len() {
        tmp |= a[i] ^ b[i];
    }
    tmp
}

#[wasm_bindgen]
/// Checks the equality of two equal sized byte vectors in constant time.
pub fn constant_time_eq(a: Vec<u8>, b: Vec<u8>) -> bool {
    a.len() == b.len() && constant_time_ne(&a, &b) == 0
}

/// Given a sr25519 secret signing key, generate an x25519 secret encryption key
pub fn derive_static_secret(sk: &sr25519::Pair) -> StaticSecret {
    let mut buffer: [u8; 32] = [0; 32];
    let mut hasher = Blake2s256::new();
    hasher.update(&sk.to_raw_vec());
    let hash = hasher.finalize().to_vec();
    buffer.copy_from_slice(&hash);
    let result = StaticSecret::from(buffer);
    buffer.zeroize();
    result
}

/// Used for signing, encrypting and often sending arbitrary Bytes.
/// sr25519 is the signature scheme.
/// Use SignedMessage::new(secret_key, message) to construct
/// a new signed message.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SignedMessage {
    /// The encrypted message.
    pub msg: Bytes,
    /// The signature of the message hash.
    pub sig: Signature,
    /// The public key of the message signer.
    pk: [u8; 32],
    /// The intended recipients public key to be included in the signature.
    recip: [u8; 32],
    /// The signers public parameter used in diffie-hellman.
    a: [u8; 32],
    /// The message nonce used in ChaCha20Poly1305.
    nonce: [u8; 12],
}

impl SignedMessage {
    /// Encrypts and signs msg.
    /// sk is the sr25519 key used for signing and deriving a symmetric shared key
    /// via Diffie-Hellman for encryption.
    /// msg is the plaintext message to encrypt and sign
    /// recip is the public Diffie-Hellman parameter of the recipient.
    pub fn new(
        sk: &sr25519::Pair,
        msg: &Bytes,
        recip: &PublicKey,
    ) -> Result<SignedMessage, ValidationErr> {
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

        let mut hasher = Blake2s256::new();
        hasher.update(&ciphertext);
        hasher.update(recip.as_bytes());
        let hash = hasher.finalize().to_vec();
        Ok(SignedMessage {
            pk: sk.public().0,
            a: *a.as_bytes(),
            msg: sp_core::Bytes(ciphertext),
            nonce: static_nonce,
            sig: sk.sign(&hash),
            recip: recip.to_bytes(),
        })
    }

    /// Creates a `SignedMessage` without needing any types from sp-core
    // This is useful for environments using newer versions of sp-core
    pub fn new_with_keypair_seed(
        sr25519_keypair_seed: &[u8; 32],
        msg: Vec<u8>,
        recip: &PublicKey,
    ) -> Result<Self, ValidationErr> {
        let pair = sr25519::Pair::from_seed(sr25519_keypair_seed);
        Self::new(&pair, &Bytes(msg), recip)
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

    /// Returns the AccountId32 of the message signer.
    pub fn account_id(&self) -> AccountId32 {
        AccountId32::new(self.pk)
    }

    /// Returns the public DH parameter of the message sender.
    pub fn sender(&self) -> x25519_dalek::PublicKey {
        x25519_dalek::PublicKey::from(self.a)
    }

    /// Returns the sr25519 public key of the message signer.
    pub fn pk(&self) -> sr25519::Public {
        sr25519::Public::from_raw(self.pk)
    }

    /// Returns the public DH key of the message recipient.
    pub fn recipient(&self) -> PublicKey {
        PublicKey::from(self.recip)
    }

    /// Verifies the signature of the hash of self.msg stored in self.sig
    /// with the public key self.pk.
    pub fn verify(&self) -> bool {
        let mut hasher = Blake2s256::new();
        hasher.update(&self.msg.0);
        hasher.update(self.recip);
        let hash = hasher.finalize().to_vec();
        <sr25519::Pair as Pair>::verify(&self.sig, &hash, &sr25519::Public(self.pk))
    }

    /// Returns a serialized json string of self.
    pub fn to_json(&self) -> Result<String, ValidationErr> {
        Ok(to_string(self)?)
    }
}

/// Creates a new random Mnemonic.
pub fn new_mnemonic() -> Mnemonic {
    Mnemonic::new(bip39::MnemonicType::Words24, bip39::Language::English)
}

/// Derives a sr25519::Pair from a Mnemonic
pub fn mnemonic_to_pair(m: &Mnemonic) -> Result<sr25519::Pair, ValidationErr> {
    Ok(<sr25519::Pair as Pair>::from_phrase(m.phrase(), None)
        .map_err(|_| ValidationErr::SecretString("Secret String Error"))?
        .0)
}

#[derive(Debug, Error)]
pub enum ValidationErr {
    #[error("ChaCha20 decryption error: {0}")]
    Decryption(String),
    #[error("ChaCha20 Encryption error: {0}")]
    Encryption(String),
    #[error("ChaCha20 Conversion error: {0}")]
    Conversion(String),
    #[error("Secret String failure: {0:?}")]
    SecretString(&'static str),
    #[error("Message is too old")]
    StaleMessage,
    #[error("Time subtraction error: {0}")]
    SystemTime(#[from] std::time::SystemTimeError),
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bad_signatures_fails() {
        let plaintext = Bytes(vec![69, 42, 0]);

        let alice = mnemonic_to_pair(&new_mnemonic()).unwrap();
        let alice_secret = derive_static_secret(&alice);
        let alice_public_key = PublicKey::from(&alice_secret);

        let bob = mnemonic_to_pair(&new_mnemonic()).unwrap();
        let bob_secret = derive_static_secret(&bob);
        let bob_public_key = PublicKey::from(&bob_secret);

        let alice_to_alice = SignedMessage::new(&alice, &plaintext, &alice_public_key).unwrap();
        let mut alice_to_bob = SignedMessage::new(&alice, &plaintext, &bob_public_key).unwrap();

        // Test that replacing the public key fails to verify the signature.
        alice_to_bob.sig = alice_to_alice.sig;
        assert!(!alice_to_bob.verify());

        // Test that decrypting with the wrong private key throws an error.
        let res = alice_to_bob.decrypt(&alice);
        assert!(res.is_err());
    }

    #[test]
    fn test_sign_and_encrypt() {
        let plaintext = Bytes(vec![69, 42, 0]);

        let alice = mnemonic_to_pair(&new_mnemonic()).unwrap();
        let _alice_secret = derive_static_secret(&alice);

        let bob = mnemonic_to_pair(&new_mnemonic()).unwrap();
        let bob_secret = derive_static_secret(&bob);
        let bob_public_key = PublicKey::from(&bob_secret);

        // Test encryption & signing.
        let encrypt_result = SignedMessage::new(&alice, &plaintext, &bob_public_key);
        // Assert no error received in encryption.
        assert!(encrypt_result.is_ok());
        let encrypted_message = encrypt_result.unwrap();

        // Test signature validity
        assert!(encrypted_message.verify());

        // Test decryption
        let decrypt_result = encrypted_message.decrypt(&bob);
        // Assert no error received in decryption.
        assert!(decrypt_result.is_ok());
        let decrypted_result = decrypt_result.unwrap();

        // Check the decrypted message equals the plaintext.
        assert_eq!(Bytes(decrypted_result), plaintext);

        // Check the encrypted message != the plaintext.
        assert_ne!(encrypted_message.msg, plaintext);
    }

    #[test]
    fn test_new_with_seed() {
        let plaintext = vec![69, 42, 0];

        let mnemonic = new_mnemonic();
        let (_pair, alice_seed) =
            <sr25519::Pair as Pair>::from_phrase(mnemonic.phrase(), None).unwrap();

        let bob = mnemonic_to_pair(&new_mnemonic()).unwrap();
        let bob_secret = derive_static_secret(&bob);
        let bob_public_key = PublicKey::from(&bob_secret);

        // Test encryption & signing.
        let encrypt_result =
            SignedMessage::new_with_keypair_seed(&alice_seed, plaintext.clone(), &bob_public_key);
        // Assert no error received in encryption.
        assert!(encrypt_result.is_ok());
        let encrypted_message = encrypt_result.unwrap();

        // Test signature validity
        assert!(encrypted_message.verify());

        // Test decryption
        let decrypt_result = encrypted_message.decrypt(&bob);
        // Assert no error received in decryption.
        assert!(decrypt_result.is_ok());
        let decrypted_result = decrypt_result.unwrap();

        // Check the decrypted message equals the plaintext.
        assert_eq!(decrypted_result, plaintext);

        // Check the encrypted message != the plaintext.
        assert_ne!(encrypted_message.msg, Bytes(plaintext));
    }
}
