.PHONY: build build-plugins run clean

PLUGIN_DIR = ../cpex-wasm-plugin
WASM_DIR = wasm
PLUGINS = identity_checker.wasm audit_logger.wasm header_injector.wasm

build-plugins:
	$(MAKE) -C $(PLUGIN_DIR) build
	@mkdir -p $(WASM_DIR)
	@for f in $(PLUGINS); do \
		cp $(PLUGIN_DIR)/$$f $(WASM_DIR)/$$f; \
	done
	@echo "Copied plugins to $(WASM_DIR)/"

build: build-plugins
	cargo build --release

run: build
	cargo run --release

clean:
	cargo clean
	rm -f $(WASM_DIR)/*.wasm
