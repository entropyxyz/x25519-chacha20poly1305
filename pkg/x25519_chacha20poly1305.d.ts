/* tslint:disable */
/* eslint-disable */
/**
* Convert a Vec<u8> to a hex encoded string
* @param {Uint8Array} v
* @returns {string}
*/
export function to_hex(v: Uint8Array): string;
/**
* Convert a hex string to a Vec<u8>, ignoring 0x prefix
* @param {string} v
* @returns {Uint8Array}
*/
export function from_hex(v: string): Uint8Array;
/**
* Derives a public DH key from a static DH secret.
* sk must be 64 bytes in length or an error will be returned.
* @param {Uint8Array} sk
* @returns {Uint8Array}
*/
export function public_key_from_secret(sk: Uint8Array): Uint8Array;
/**
* Generates a Ristretto Schnorr secret key.
* This method is used for testing, applications that implement this
* library should rely on user provided keys generated from substrate.
* @returns {Uint8Array}
*/
export function gen_signing_key(): Uint8Array;
/**
* Encrypts, signs, and serializes a SignedMessage to JSON.
* @param {Uint8Array} sk
* @param {Uint8Array} msg
* @param {Uint8Array} pk
* @returns {string}
*/
export function encrypt_and_sign(sk: Uint8Array, msg: Uint8Array, pk: Uint8Array): string;
/**
* Deserializes, verifies and decrypts a json encoded `SignedMessage`.
* Returns the plaintext.
* @param {Uint8Array} sk
* @param {string} msg
* @returns {Uint8Array}
*/
export function decrypt_and_verify(sk: Uint8Array, msg: string): Uint8Array;
/**
* Checks the equality of two equal sized byte vectors in constant time.
* @param {Uint8Array} a
* @param {Uint8Array} b
* @returns {boolean}
*/
export function constant_time_eq(a: Uint8Array, b: Uint8Array): boolean;
