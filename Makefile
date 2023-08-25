CRATE_NAME := x25519-chacha20poly1305

default :: build-nodejs

# Builds a JS Module for nodejs with glue for the compiled WASM.
build-nodejs ::
	wasm-pack build --target nodejs


# Builds a JS Module for web with glue for the compiled WASM.
build-web ::
	wasm-pack build --target web

# Links the local wasm/js library with npm for testing locally.
link-local :: build-nodejs
	cd pkg && npm link

# Links the example frontend project with the locally built wasm/js package.
link :: link-local
	cd example && npm link $(CRATE_NAME) 

# Another build option for compiling to webpack, builds a typescript library around the WASM for use
# with npm.
build-bundler ::
	wasm-pack build --target bundler

test ::
	cd example && ts-node test.ts

# Cleans out build artifacts.
clean ::
	rm -rf target/ pkg/ example/node_modules/

# ---- Building API docs for Vercel ----

# Vercel sets the `HOME` env var weirdly, so we define a few extra
# things to make sure it installs okay.
.PHONY: vercel-rustup
vercel-rustup:
		curl --proto '=https' --tlsv1.2 \
			--silent --show-error --fail https://sh.rustup.rs \
			| RUSTUP_HOME=/vercel/.rustup HOME=/root sh -s -- -y
		cp -R /root/.cargo /vercel/.cargo

# Installs `rustup` in a typical case.
.PHONY: rustup
rustup:
		curl --proto '=https' --tlsv1.2 \
			--silent --show-error --fail https://sh.rustup.rs \
			| sh -s -- -y

.PHONY: rust
rust:
		export PATH="${PATH}:${HOME}/.cargo/bin" rustup default stable \
		&& rustup update nightly \
		&& rustup update stable \
		&& rustup target add wasm32-unknown-unknown --toolchain nightly

# This target is specifically for generating API documentation from
# within a Vercel.com Project. It is used as the Projects `installCommand`.
vercel-install-api-docs :: vercel-rustup rust
		git config --global url."https://github.com".insteadOf ssh://git@github.com

# The Vercel Project's `buildCommand` is defined here.
vercel-build-api-docs ::
		export PATH="${PATH}:${HOME}/.cargo/bin" \
			&& cargo doc --release --no-deps
