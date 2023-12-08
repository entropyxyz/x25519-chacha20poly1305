### x25519-chacha20poly1305

---
**WARNING: This code has not been audited and is not yet suitable for production. Use at your own risk.**

---

x25519 key exchange and chacha20poly1305 encryption, written in Rust compiled to WASM.

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

links to packages on npm: 
- [`x25519`](https://www.npmjs.com/package/x25519)
- [`x25519-chacha20poly1305-nodejs`](https://www.npmjs.com/package/@entropyxyz/x25519-chacha20poly1305-nodejs)
- [`x25519-chacha20poly1305-web`](https://www.npmjs.com/package/@entropyxyz/x25519-chacha20poly1305-web)
- [`x25519-chacha20poly1305-bundler`](https://www.npmjs.com/package/@entropyxyz/x25519-chacha20poly1305-bundler)

## Publishing instructions

- Bump version in Cargo.toml
- Rebuild for eg: NodeJs with `make build-nodejs`
- Manually change the package name in `./pkg/package.json` for the desired platform `-nodejs` and add the `@entropyxyz` org name, eg:
```
  "name": "@entropyxyz/x25519-chacha20poly1305-nodejs"
```
- publish with `npm publish`
- Rebuild for `web` and `bundler` with eg: `make build-web` and then change the package names again in package.json before re-publishing. 
