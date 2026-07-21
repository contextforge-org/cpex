.PHONY: all build build-debug release stage validate inspect clean check fmt clippy run-demo run-all-demos help

TARGET        := wasm32-wasip2
TARGET_DIR    := target
HOST_WASM_DIR := ../cpex-wasm-host/wasm
PLUGIN_NAME   := cpex_wasm_plugin
STAGED        := $(HOST_WASM_DIR)/plugin.wasm

# Default profile for `make build` — override with PROFILE=debug
PROFILE       := release
ARTIFACT       = $(TARGET_DIR)/$(TARGET)/$(PROFILE)/$(PLUGIN_NAME).wasm

# Plugin features (one binary per feature)
PLUGINS       := identity-checker header-injector audit-logger tool-invoke-checker pii-guard audit-logger-custom remote-authz

# ---------------------------------------------------------------------------
# Build targets
# ---------------------------------------------------------------------------

all: build stage ## Build (release) and stage the default plugin (identity-checker)

build: ## Build the default plugin (release by default, override: make build PROFILE=debug)
	cargo build --target $(TARGET) $(if $(filter release,$(PROFILE)),--release,)
	@echo "Built: $(ARTIFACT) ($$(du -h $(ARTIFACT) | cut -f1))"

build-debug: ## Build the default plugin (debug, faster compile)
	$(MAKE) build PROFILE=debug

release: ## Build the default plugin (release, optimized)
	$(MAKE) build PROFILE=release

build-all: ## Build all plugin binaries and stage to host wasm/ directory
	@mkdir -p $(HOST_WASM_DIR)
	@for plugin in $(PLUGINS); do \
		echo "Building $$plugin..."; \
		cargo build --target $(TARGET) --release --features $$plugin --no-default-features && \
		cp $(TARGET_DIR)/$(TARGET)/release/$(PLUGIN_NAME).wasm $(HOST_WASM_DIR)/$$plugin.wasm && \
		echo "  Staged: $(HOST_WASM_DIR)/$$plugin.wasm ($$(du -h $(HOST_WASM_DIR)/$$plugin.wasm | cut -f1))"; \
	done
	@echo "All plugins built and staged."

# ---------------------------------------------------------------------------
# Stage — copy to host wasm/ directory
# ---------------------------------------------------------------------------

stage: $(ARTIFACT) ## Copy built .wasm to the host's wasm/ directory
	@mkdir -p $(HOST_WASM_DIR)
	cp $(ARTIFACT) $(STAGED)
	@echo "Staged: $(STAGED) ($$(du -h $(STAGED) | cut -f1))"

# Local copy for validate/inspect
plugin.wasm: $(ARTIFACT)
	cp $(ARTIFACT) plugin.wasm

# ---------------------------------------------------------------------------
# Validation and inspection (requires: cargo install wasm-tools)
# ---------------------------------------------------------------------------

validate: plugin.wasm ## Validate the component binary
	wasm-tools validate plugin.wasm
	@echo "plugin.wasm is valid"

inspect: plugin.wasm ## Print the WIT interface embedded in the binary
	wasm-tools component wit plugin.wasm

# ---------------------------------------------------------------------------
# Development
# ---------------------------------------------------------------------------

check: ## Type-check without producing a binary (fast feedback)
	cargo check --target $(TARGET)

fmt: ## Format source code
	cargo fmt

clippy: ## Run clippy lints for the wasm target
	cargo clippy --target $(TARGET) -- -D warnings

# ---------------------------------------------------------------------------
# Run demos (from workspace root via the host crate)
# ---------------------------------------------------------------------------

run-demo: all ## Build, stage, and run the plugin demo
	cd ../.. && cargo run -p cpex-wasm-host --example wasm_plugin_demo

run-all-demos: build-all ## Build all plugins and run both demos
	cd ../.. && cargo run -p cpex-wasm-host --example wasm_plugin_demo
	cd ../.. && cargo run -p cpex-wasm-host --example wasm_capabilities_demo

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

clean: ## Remove all build artifacts and staged binary
	cargo clean
	rm -f plugin.wasm
	rm -f $(STAGED)

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'
