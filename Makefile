CRATE_NAME := x25519-chacha20poly1305-wasm
HOST_IP := 127.0.0.1

default :: link-project

# Builds a JS Module with glue for the compiled WASM.
build-web ::
	wasm-pack build --target web

# Links the local wasm/js library with npm for testing locally.
link-local :: build-web
	cd pkg && npm link

# Links the example frontend project with the locally built wasm/js package.
link-project :: link-local
	cd example && npm link $(CRATE_NAME) 

# Another build option for compiling to webpack, builds a typescript library around the WASM for use
# with npm.
build-bundler ::
	wasm-pack build --target bundler

# Runs the example with a http server
run ::
	cd example && ./server.sh $(HOST_IP)

# Cleans out build artifacts.
clean ::
	rm -rf target/ pkg/ example/node_modules/
