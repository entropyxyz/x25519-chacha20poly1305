/* tslint:disable */
/* eslint-disable */
/**
* @param {Uint8Array} v
* @returns {string}
*/
export function to_hex(v: Uint8Array): string;
/**
* @param {string} v
* @returns {Uint8Array}
*/
export function from_hex(v: string): Uint8Array;
/**
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

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly to_hex: (a: number, b: number, c: number) => void;
  readonly from_hex: (a: number, b: number, c: number) => void;
  readonly public_key_from_secret: (a: number, b: number, c: number) => void;
  readonly gen_signing_key: (a: number) => void;
  readonly encrypt_and_sign: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
  readonly decrypt_and_verify: (a: number, b: number, c: number, d: number, e: number) => void;
  readonly constant_time_eq: (a: number, b: number, c: number, d: number) => number;
  readonly rustsecp256k1_v0_4_1_context_create: (a: number) => number;
  readonly rustsecp256k1_v0_4_1_context_destroy: (a: number) => void;
  readonly rustsecp256k1_v0_4_1_default_illegal_callback_fn: (a: number, b: number) => void;
  readonly rustsecp256k1_v0_4_1_default_error_callback_fn: (a: number, b: number) => void;
  readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
  readonly __wbindgen_malloc: (a: number) => number;
  readonly __wbindgen_free: (a: number, b: number) => void;
  readonly __wbindgen_realloc: (a: number, b: number, c: number) => number;
  readonly __wbindgen_exn_store: (a: number) => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {SyncInitInput} module
*
* @returns {InitOutput}
*/
export function initSync(module: SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {InitInput | Promise<InitInput>} module_or_path
*
* @returns {Promise<InitOutput>}
*/
export default function init (module_or_path?: InitInput | Promise<InitInput>): Promise<InitOutput>;
