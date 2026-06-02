.PHONY: build build-identity build-audit build-headers clean

TARGET = wasm32-wasip2
WORKSPACE_TARGET_DIR = ../../target

build: build-identity build-audit build-headers

build-identity:
	cargo build --target $(TARGET) --release --features identity-checker
	cp $(WORKSPACE_TARGET_DIR)/$(TARGET)/release/cpex_wasm_plugin.wasm identity_checker.wasm

build-audit:
	cargo build --target $(TARGET) --release --features audit-logger
	cp $(WORKSPACE_TARGET_DIR)/$(TARGET)/release/cpex_wasm_plugin.wasm audit_logger.wasm

build-headers:
	cargo build --target $(TARGET) --release --features header-injector
	cp $(WORKSPACE_TARGET_DIR)/$(TARGET)/release/cpex_wasm_plugin.wasm header_injector.wasm

clean:
	cargo clean
	rm -f identity_checker.wasm audit_logger.wasm header_injector.wasm
