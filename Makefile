CRATE_NAME := x25519-chacha20poly1305
SCOPE_NAME := @entropyxyz
default :: build-nodejs


# Builds a JS Module for bundler with glue for the compiled WASM.
build-bundler ::
	wasm-pack build --target bundler --out-dir pkg/bundler --out-name $(CRATE_NAME)-bundler --scope $(SCOPE_NAME)

# Builds a JS Module for nodejs with glue for the compiled WASM.
build-nodejs ::
	wasm-pack build --target nodejs --out-dir pkg/nodejs --out-name $(CRATE_NAME)-nodejs --scope $(SCOPE_NAME)

# Builds a JS Module for web with glue for the compiled WASM.
build-web ::
	wasm-pack build --target web --out-dir pkg/web --out-name $(CRATE_NAME)-web --scope $(SCOPE_NAME)



# Links the local bundler wasm/js library with npm for testing locally.
link-local-bundler:: build-bundler
	cd pkg/bundler && npm link

# Links the local nodejs wasm/js library with npm for testing locally.
link-local-nodejs :: build-nodejs
	cd pkg/nodejs && npm link

# Links the local web wasm/js library with npm for testing locally.
link-local-web :: build-web
	cd pkg/web && npm link

# Links the example frontend project with the locally built wasm/js package.
link-example-bundler :: link-local-bundler
	cd example && npm link $(SCOPE_NAME)/$(CRATE_NAME)-bundler

# Links the example frontend project with the locally built wasm/js package.
link-example-nodejs :: link-local-nodejs
	cd example && npm link $(SCOPE_NAME)/$(CRATE_NAME)-nodejs

# Lists all linked npm packages.
list-linked ::
	npm list --linked
# Links the example frontend project with the locally built wasm/js package.
link-example-web :: link-local-web
	cd example && npm link $(SCOPE_NAME)/$(CRATE_NAME)-web

test ::
	cd example && ts-node test.ts

link :: link-local
	cd example && npm link $(SCOPE_NAME)/$(CRATE_NAME)-nodejs
													@entropyxyz/x25519-chacha20poly1305-nodejs
																			x25519-chacha20poly1305

# Cleans out build artifacts.
clean ::
	rm -rf target/ pkg/web/ pkg/nodejs/ pkg/bundler/ example/node_modules/
