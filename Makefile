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
