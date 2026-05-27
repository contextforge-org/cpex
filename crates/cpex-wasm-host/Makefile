.PHONY: build run clean

PLUGIN_PATH = ../cpex-wasm-plugin/plugin.wasm

build:
	cargo build --release

run: build
	@if [ ! -f $(PLUGIN_PATH) ]; then \
		echo "Error: plugin.wasm not found. Build it first with:"; \
		echo "  cd ../cpex-wasm-plugin && make build"; \
		exit 1; \
	fi
	cp $(PLUGIN_PATH) plugin.wasm
	cargo run --release

clean:
	cargo clean
	rm -f plugin.wasm
