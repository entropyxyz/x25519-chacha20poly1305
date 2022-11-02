
import {from_hex, to_hex, decrypt_and_verify, gen_signing_key, encrypt_and_sign, public_key_from_secret, constant_time_eq } from "x25519-chacha20poly1305";

let empty = new Uint8Array(32);
let hempty = to_hex(empty);
let dempty = from_hex(hempty);

// Alice keygen.
let alice_sk = gen_signing_key();

// Bob keygen.
let bob_sk = gen_signing_key();
let bob_pk = public_key_from_secret(bob_sk);

// Create a random message.
let plaintext = new Uint8Array(32);
console.log(plaintext);

// Alice encrypts and signs the message to bob.
let encrypted_and_signed_msg = encrypt_and_sign(alice_sk, plaintext, bob_pk);
console.log(encrypted_and_signed_msg);

// Bob decrypts the message.
let decrypted_plaintext = decrypt_and_verify(bob_sk, encrypted_and_signed_msg);

console.log(decrypted_plaintext);
// Check the original plaintext equals the decrypted plaintext.
let is_equal = constant_time_eq(decrypted_plaintext, plaintext);
console.log("alice encrypted plaintext is equal to bob decrypted ciphertext: ", is_equal);

