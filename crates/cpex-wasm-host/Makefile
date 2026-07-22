.PHONY: all build build-plugin build-all-plugins build-test-plugins build-bench-plugins bench-all test run-demos run-plugin-demo run-capabilities-demo clean clean-all help

PLUGIN_DIR := ../cpex-wasm-plugin
WASM_DIR   := wasm

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

all: build ## Build default plugin + host (default)

build-plugin: ## Build the default WASM plugin and stage it
	$(MAKE) -C $(PLUGIN_DIR) all

DEMO_PLUGINS  := tool-invoke-checker pii-guard audit-logger-custom remote-authz
BENCH_PLUGINS := compute-bench

build-all-plugins: ## Build all WASM plugin binaries (capabilities + custom-payload demo)
	$(MAKE) -C $(PLUGIN_DIR) build-all
	@for plugin in $(DEMO_PLUGINS); do \
		echo "Building $$plugin..."; \
		cargo build --manifest-path $(PLUGIN_DIR)/Cargo.toml \
			--target wasm32-wasip2 --release \
			--features $$plugin --no-default-features; \
		cp $(PLUGIN_TARGET) $(WASM_DIR)/$$plugin.wasm; \
	done
	@echo "All demo plugins built and staged."

build: build-plugin ## Build everything (default plugin + host examples)
	cargo build --examples

# ---------------------------------------------------------------------------
# Run demos
# ---------------------------------------------------------------------------

run-demos: build-all-plugins ## Build all plugins and run all demos
	cargo build --examples
	@echo "\n========== Plugin Demo (custom payload, pre/post invoke) ==========\n"
	cargo run --example wasm_plugin_demo
	@echo "\n========== Capabilities Demo (3 plugins, capability isolation) ==========\n"
	cargo run --example wasm_capabilities_demo
	@echo "\n========== All demos passed ==========\n"

run-plugin-demo: build-all-plugins ## Build tool-invoke-checker plugin and run the custom-payload demo
	cargo build --examples
	cargo run --example wasm_plugin_demo

run-capabilities-demo: build-all-plugins ## Build all plugins and run the capabilities demo
	cargo build --examples
	cargo run --example wasm_capabilities_demo

# ---------------------------------------------------------------------------
# Benchmarks
# ---------------------------------------------------------------------------

build-bench-plugins: ## Build benchmark WASM plugins (compute-bench, noop)
	@for plugin in $(BENCH_PLUGINS); do \
		echo "Building $$plugin..."; \
		cargo build --manifest-path $(PLUGIN_DIR)/Cargo.toml \
			--target wasm32-wasip2 --release \
			--features $$plugin --no-default-features; \
		cp $(PLUGIN_TARGET) $(WASM_DIR)/$$plugin.wasm; \
	done
	@echo "Benchmark plugins built and staged."

bench-all: build-all-plugins build-bench-plugins build-test-plugins ## Build all plugins and run all benchmarks + generate chart
	cargo bench
	@echo "\n========== Generating performance chart ==========\n"
	cd benchmarking && python3 plot_results.py
	@echo "\n========== Benchmarks complete ==========\n"

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
	cargo test --manifest-path $(PLUGIN_DIR)/Cargo.toml --features tool-invoke-checker --no-default-features
	cargo test --manifest-path $(PLUGIN_DIR)/Cargo.toml --features pii-guard --no-default-features
	cargo test --manifest-path $(PLUGIN_DIR)/Cargo.toml --features audit-logger-custom --no-default-features
	cargo test --manifest-path $(PLUGIN_DIR)/Cargo.toml --features remote-authz --no-default-features
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
