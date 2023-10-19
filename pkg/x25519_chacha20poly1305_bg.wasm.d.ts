/* tslint:disable */
/* eslint-disable */
export const memory: WebAssembly.Memory;
export function to_hex(a: number, b: number, c: number): void;
export function from_hex(a: number, b: number, c: number): void;
export function public_key_from_secret(a: number, b: number, c: number): void;
export function gen_signing_key(a: number): void;
export function encrypt_and_sign(a: number, b: number, c: number, d: number, e: number, f: number, g: number): void;
export function decrypt_and_verify(a: number, b: number, c: number, d: number, e: number): void;
export function constant_time_eq(a: number, b: number, c: number, d: number): number;
export function rustsecp256k1_v0_4_1_context_create(a: number): number;
export function rustsecp256k1_v0_4_1_context_destroy(a: number): void;
export function rustsecp256k1_v0_4_1_default_illegal_callback_fn(a: number, b: number): void;
export function rustsecp256k1_v0_4_1_default_error_callback_fn(a: number, b: number): void;
export function __wbindgen_add_to_stack_pointer(a: number): number;
export function __wbindgen_malloc(a: number, b: number): number;
export function __wbindgen_free(a: number, b: number, c: number): void;
export function __wbindgen_realloc(a: number, b: number, c: number, d: number): number;
export function __wbindgen_exn_store(a: number): void;
