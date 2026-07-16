.PHONY: all build build-plugin build-all-plugins build-test-plugins test run-demos run-cmf-demo run-identity-demo run-generic-demo run-capabilities-demo clean clean-all help

PLUGIN_DIR := ../cpex-wasm-plugin
WASM_DIR   := wasm

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

all: build ## Build default plugin + host (default)

build-plugin: ## Build the default WASM plugin and stage it
	$(MAKE) -C $(PLUGIN_DIR) all

build-all-plugins: ## Build all WASM plugin binaries (identity-checker, header-injector, audit-logger)
	$(MAKE) -C $(PLUGIN_DIR) build-all

build: build-plugin ## Build everything (default plugin + host examples)
	cargo build --examples

# ---------------------------------------------------------------------------
# Run demos
# ---------------------------------------------------------------------------

run-demos: build ## Run all three WASM plugin demos
	@echo "\n========== CMF MessagePayload Demo ==========\n"
	cargo run --example wasm_plugin_demo
	@echo "\n========== Identity Resolve Demo ==========\n"
	cargo run --example wasm_identity_resolve_demo
	@echo "\n========== Generic Payload Demo ==========\n"
	cargo run --example wasm_generic_payload_demo
	@echo "\n========== All demos passed ==========\n"

run-cmf-demo: build ## Run only the CMF MessagePayload demo
	cargo run --example wasm_plugin_demo

run-identity-demo: build ## Run only the identity resolve demo
	cargo run --example wasm_identity_resolve_demo

run-generic-demo: build ## Run only the generic payload demo
	cargo run --example wasm_generic_payload_demo

run-capabilities-demo: build-all-plugins ## Build all plugins and run the capabilities demo
	cargo build --examples
	cargo run --example wasm_capabilities_demo

# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

PLUGIN_TARGET := $(PLUGIN_DIR)/target/wasm32-wasip2/release/cpex_wasm_plugin.wasm
TEST_PLUGINS  := fs-test net-test env-test noop

build-test-plugins: ## Build all test WASM plugins (fs-test, net-test, env-test, noop)
	@for plugin in $(TEST_PLUGINS); do \
		echo "Building $$plugin..."; \
		cargo build --manifest-path $(PLUGIN_DIR)/Cargo.toml \
			--target wasm32-wasip2 --release \
			--features $$plugin --no-default-features; \
		cp $(PLUGIN_TARGET) $(WASM_DIR)/$$plugin.wasm; \
	done
	@echo "All test plugins built and staged."

test: clean-all build-all-plugins build-test-plugins ## Clean all, rebuild all plugins, run all tests
	@echo "\n========== Running host tests (46 tests) ==========\n"
	cargo test
	@echo "\n========== Running plugin unit tests ==========\n"
	cargo test --manifest-path $(PLUGIN_DIR)/Cargo.toml --features identity-checker --no-default-features
	cargo test --manifest-path $(PLUGIN_DIR)/Cargo.toml --features header-injector --no-default-features
	cargo test --manifest-path $(PLUGIN_DIR)/Cargo.toml --features audit-logger --no-default-features
	cargo test --manifest-path $(PLUGIN_DIR)/Cargo.toml --features token-attenuator --no-default-features
	@echo "\n========== All tests passed ==========\n"

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

clean: ## Remove host build artifacts and default plugin.wasm
	cargo clean
	rm -f $(WASM_DIR)/plugin.wasm

clean-all: ## Remove host + plugin build artifacts and ALL .wasm files
	cargo clean
	cargo clean --manifest-path $(PLUGIN_DIR)/Cargo.toml
	cargo clean --manifest-path $(PLUGIN_DIR)/Cargo.toml --target wasm32-wasip2
	rm -f $(WASM_DIR)/*.wasm

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
