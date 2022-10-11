CRATE_NAME := x25519-chacha20poly1305-wasm
HOST_IP := 127.0.0.1

default :: link-project

# Builds a JS Module for nodejs with glue for the compiled WASM.
build-nodejs ::
	wasm-pack build --target nodejs


# Builds a JS Module for web with glue for the compiled WASM.
build-web ::
	wasm-pack build --target web

# Links the local wasm/js library with npm for testing locally.
link-local :: build-nodejs
	cd pkg && sudo npm link

# Links the example frontend project with the locally built wasm/js package.
link-project :: link-local
	cd example && sudo npm link $(CRATE_NAME) 

# Another build option for compiling to webpack, builds a typescript library around the WASM for use
# with npm.
build-bundler ::
	wasm-pack build --target bundler

run ::
	cd example && ts-node test.ts

# Runs the example with a http server
serve ::
	cd example && ./server.sh $(HOST_IP)

# Cleans out build artifacts.
clean ::
	rm -rf target/ pkg/ example/node_modules/
