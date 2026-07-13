.PHONY: all build build-plugin build-all-plugins run-demos run-cmf-demo run-identity-demo run-generic-demo run-capabilities-demo clean help

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
# Cleanup
# ---------------------------------------------------------------------------

clean: ## Remove build artifacts
	cargo clean
	rm -f $(WASM_DIR)/plugin.wasm

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
