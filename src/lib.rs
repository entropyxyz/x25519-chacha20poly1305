use serde_json::to_string;
use serde::{Deserialize, Serialize};
use sp_core::{crypto::AccountId32, sr25519, sr25519::Signature, Bytes, Pair};
use blake2::{Blake2s256, Digest};
use chacha20poly1305::{
    aead::{Aead, Error, KeyInit},
    ChaCha20Poly1305,
};
use x25519_dalek::{StaticSecret, PublicKey};
use generic_array::GenericArray;
use schnorrkel::{MiniSecretKey, SecretKey};
use wasm_bindgen::prelude::*;
use hex;

#[wasm_bindgen]
pub fn to_hex(v: Vec<u8>) -> String {
    hex::encode(v)
}

#[wasm_bindgen]
pub fn from_hex(v: String) -> Vec<u8> {
    hex::decode(v).unwrap()
}

#[wasm_bindgen]
// Derives a public DH key from a static DH secret.
// sk must be 64 bytes in length or an empty array will be returned. 
// TODO: find better interface in WASM for throwing errors from rust to wasm.
pub fn public_key_from_secret(sk: Vec<u8>) -> Vec<u8> {
    if sk.len() != 64 {
        return Vec::<u8>::new();
    }
    let sec_key = SecretKey::from_ed25519_bytes(sk.as_slice()).unwrap();
    let pair = sr25519::Pair::from(sec_key);
    let ss = derive_static_secret(&pair);
    PublicKey::from(&ss).as_bytes().to_vec()
}

pub fn gen_msg_nonce() -> Vec<u8> {
  let mut vec: Vec<u8> = vec![0; 12];
  getrandom::getrandom(&mut vec).unwrap();
  return vec;
}

#[wasm_bindgen]
/// Generates a Ristretto Schnorr secret key.
/// This method is used for testing, applications that implement this
/// library should rely on user provided keys generated from substrate.
pub fn gen_signing_key() -> Vec<u8> {
    let mini_secret_key = MiniSecretKey::generate();
    let secret_key: SecretKey = mini_secret_key.expand(MiniSecretKey::ED25519_MODE); 
    let _sk: [u8; 64] = secret_key.to_bytes();
    let sk = SecretKey::from_bytes(&_sk).unwrap();
    sk.to_bytes().to_vec()
}

#[wasm_bindgen]
/// Encrypts, signs, and serializes a SignedMessage to JSON.
pub fn encrypt_and_sign(sk: Vec<u8>, msg: Vec<u8>, pk: Vec<u8> ) -> String {
    let mut _raw_pk: [u8; 32] = [0; 32];
    _raw_pk.copy_from_slice(&pk[0..32]);
    let _pk = PublicKey::from(_raw_pk);
    let _msg = Bytes(msg);

    let mut sk_buff: [u8; 64] = [0; 64];
    sk_buff.copy_from_slice(&sk[0..64]);
    if sk.len() != 64 {
        return "bad key length".to_string();
    }

    let sec_key = SecretKey::from_ed25519_bytes(sk.as_slice());
    match sec_key {
        Err(v) => {
            return v.to_string();
        },
        Ok(v) => {
            let pair = sr25519::Pair::from(v);
            let sm = SignedMessage::new(&pair, &_msg, &_pk).unwrap();
            return sm.to_json();
        },
    }
}

#[wasm_bindgen]
/// Deserializes, verifies and decrypts a json encoded `SignedMessage`.
/// Returns the plaintext.
pub fn decrypt_and_verify(sk: Vec<u8>, msg: String) -> Vec<u8> {

    let _sm = serde_json::from_str(msg.as_str());
    if _sm.is_err() {
        return "error deserializing".to_string().as_bytes().to_vec();
    }

    let sm: SignedMessage = _sm.unwrap();

    if !sm.verify() {
        return "failed to verify signature".to_string().as_bytes().to_vec();
    }

    let sec_key = SecretKey::from_ed25519_bytes(sk.as_slice());
    match sec_key {
        Err(v) => {
            return v.to_string().as_bytes().to_vec();
        },
        Ok(v) => {
            let pair = sr25519::Pair::from(v);
            let res = sm.decrypt(&pair);
            match res {
                Err(v) => {
                    return "failed".to_string().as_bytes().to_vec();
                },
                Ok(v) => {
                    return v.clone();
                }
            }
        },
    }
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

pub fn derive_static_secret(sk: &sr25519::Pair) -> StaticSecret {
    let mut buffer: [u8; 32] = [0; 32];
    let mut hasher = Blake2s256::new();
    hasher.update(&sk.to_raw_vec());
    let hash = hasher.finalize().to_vec();
    buffer.copy_from_slice(&hash);
    let result = StaticSecret::from(buffer);
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
    ) -> Result<SignedMessage, Error> {
        let s = derive_static_secret(sk);
        let a = PublicKey::from(&s);
        let shared_secret = s.diffie_hellman(recip);
        let mut static_nonce: [u8; 12] = [0; 12];
        getrandom::getrandom(&mut static_nonce).unwrap();
        let nonce = GenericArray::from_slice(&static_nonce);
        let cipher = ChaCha20Poly1305::new_from_slice(shared_secret.as_bytes()).unwrap();
        let ciphertext = cipher.encrypt(nonce, msg.0.as_slice())?;

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

    /// Decrypts the message and returns the plaintext.
    pub fn decrypt(&self, sk: &sr25519::Pair) -> Result<Vec<u8>, Error> {
        if !self.verify() {
            return Err(Error);
        }
        let static_secret = derive_static_secret(sk);
        let shared_secret = static_secret.diffie_hellman(&PublicKey::from(self.a));
        let cipher = ChaCha20Poly1305::new_from_slice(shared_secret.as_bytes()).unwrap();
        cipher.decrypt(&generic_array::GenericArray::from(self.nonce), self.msg.0.as_slice())
    }

    /// Returns the AccountId32 of the message signer.
    pub fn account_id(&self) -> AccountId32 { AccountId32::new(self.pk) }

    /// Returns the public key of the message signer.
    pub fn pk(&self) -> sr25519::Public { sr25519::Public::from_raw(self.pk) }

    /// Returns the public DH key of the message recipient.
    pub fn recipient(&self) -> PublicKey { PublicKey::from(self.recip) }

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
    pub fn to_json(&self) -> String { to_string(self).unwrap() }
}

