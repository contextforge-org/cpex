.PHONY: build build-plugin run clean

PLUGIN_DIR = ../cpex-wasm-plugin
WASM_DIR = wasm

build-plugin:
	$(MAKE) -C $(PLUGIN_DIR) build

build: build-plugin
	cargo build --release

run: build
	cargo run --release

clean:
	cargo clean
	rm -f $(WASM_DIR)/plugin.wasm
