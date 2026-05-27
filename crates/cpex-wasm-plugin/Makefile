.PHONY: build clean

TARGET = wasm32-wasip2
OUTPUT = plugin.wasm
WORKSPACE_TARGET_DIR = ../../target

build:
	cargo build --target $(TARGET) --release
	cp $(WORKSPACE_TARGET_DIR)/$(TARGET)/release/cpex_wasm_plugin.wasm $(OUTPUT)

clean:
	cargo clean
	rm -f $(OUTPUT)

