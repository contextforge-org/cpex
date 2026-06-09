.PHONY: build validate inspect clean

TARGET = wasm32-wasip2
WORKSPACE_TARGET_DIR = target
WASM_HOST_DIR = ../cpex-wasm-host/wasm

build:
	cargo build --target $(TARGET) --release
	cp $(WORKSPACE_TARGET_DIR)/$(TARGET)/release/cpex_wasm_plugin.wasm plugin.wasm
	cp plugin.wasm $(WASM_HOST_DIR)/

validate: plugin.wasm
	wasm-tools validate plugin.wasm
	@echo "plugin.wasm is valid"

inspect: plugin.wasm
	wasm-tools component wit plugin.wasm

clean:
	cargo clean
	rm -f plugin.wasm
