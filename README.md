### x25519-chacha20poly1305

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

### NPM

link to package on npm: https://www.npmjs.com/package/x25519
