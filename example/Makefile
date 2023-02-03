
CRATE_NAME := x25519-chacha20poly1305
SCOPE_NAME := entropyxyz
default :: build-nodejs

build-nodejs ::
	wasm-pack build --target nodejs --out-dir pkg/nodejs --out-name $(CRATE_NAME)-nodejs --scope $(SCOPE_NAME)

link-local-nodejs :: build-nodejs
	cd ../pkg/nodejs && npm link

link-example-nodejs :: link-local-nodejs
	cd example && npm link $(SCOPE_NAME)/$(CRATE_NAME)-nodejs

list-linked ::
	npm list --linked
