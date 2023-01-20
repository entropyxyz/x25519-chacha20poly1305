### x25519-chacha20poly1305

---
**WARNING: This code has not been audited and is not yet suitable for production. Use at your own risk.**

---

Nodejs package for x25519 key exchange and chacha20poly1305 encryption, written in Rust compiled to WASM.

## Development process

### Install dependencies

See `example/ci-test.sh` for example of how to install both rust and javascript dependencies.

### Compile

Compile a nodejs/wasm library from the Rust source.

```sh
make
```

### Link 

Link the nodejs/wasm library locally.

```sh
make link
```

### Test

After compiling and linking, run:

```sh
ts-node example/test.ts
```

