.PHONY: all build-examples build-all-plugins build-test-plugins build-bench-plugins \
        run-all-demos run-plugin-demo run-capabilities-demo run-sandbox-demo run-env-demo \
        run-token-attenuator-demo run-network-policy-demo run-resource-limits-demo setup-sandbox-demo-data \
        bench-all test unit-tests integration-tests plugin-tests clippy \
        clean clean-all sync-wit check-wit help

PLUGIN_DIR    := ../cpex-wasm-plugin
WASM_DIR      := wasm
PLUGIN_TARGET := $(PLUGIN_DIR)/target/wasm32-wasip2/release/cpex_wasm_plugin.wasm

# Plugin lists — single source of truth for what gets built and staged to wasm/.
DEMO_PLUGINS  := identity-checker header-injector audit-logger token-attenuator \
                 tool-invoke-checker pii-guard audit-logger-custom remote-authz
TEST_PLUGINS  := fs-test net-test env-test noop fs-sandbox-demo env-sandbox-demo \
                 resource-test net-http-test
BENCH_PLUGINS := compute-bench

# ---------------------------------------------------------------------------
# Internal helper — build a list of plugins and stage each to wasm/.
# ---------------------------------------------------------------------------
define build-plugins
	@mkdir -p $(WASM_DIR)
	@for plugin in $(1); do \
		echo "Building $$plugin..."; \
		cargo build --manifest-path $(PLUGIN_DIR)/Cargo.toml \
			--target wasm32-wasip2 --release \
			--features $$plugin --no-default-features; \
		cp $(PLUGIN_TARGET) $(WASM_DIR)/$$plugin.wasm; \
	done
	@echo "Done: $(2)"
endef

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

all: build-all-plugins build-test-plugins build-examples ## Build all plugins and host examples (default)

build-examples: ## Compile all host example binaries
	cargo build --examples

build-all-plugins: ## Build demo WASM plugins and stage to wasm/
	$(call build-plugins,$(DEMO_PLUGINS),All demo plugins built and staged.)

build-test-plugins: ## Build test WASM plugins and stage to wasm/
	$(call build-plugins,$(TEST_PLUGINS),All test plugins built and staged.)

build-bench-plugins: ## Build benchmark WASM plugins and stage to wasm/
	$(call build-plugins,$(BENCH_PLUGINS),Benchmark plugins built and staged.)

# ---------------------------------------------------------------------------
# Run demos
# ---------------------------------------------------------------------------

run-all-demos: build-all-plugins build-test-plugins setup-sandbox-demo-data build-examples ## Build all plugins and run ALL demos end-to-end
	@echo "\n========== Plugin Demo ==========\n"
	cargo run --example wasm_plugin_demo
	@echo "\n========== Capabilities Demo ==========\n"
	cargo run --example wasm_capabilities_demo
	@echo "\n========== Filesystem Sandbox Demo ==========\n"
	cargo run --example wasm_fs_sandbox_demo
	@echo "\n========== Env Sandbox Demo ==========\n"
	cargo run --example wasm_env_sandbox_demo
	@echo "\n========== Token Attenuator Demo ==========\n"
	cargo run --example wasm_token_attenuator_demo
	@echo "\n========== Network Policy Demo ==========\n"
	cargo run --example wasm_network_policy_demo
	@echo "\n========== Resource Limits Demo ==========\n"
	cargo run --example wasm_resource_limits_demo
	@echo "\n========== All demos passed ==========\n"

run-plugin-demo: build-all-plugins build-examples ## Run the custom-payload plugin demo
	cargo run --example wasm_plugin_demo

run-capabilities-demo: build-all-plugins build-examples ## Run the capabilities isolation demo
	cargo run --example wasm_capabilities_demo

setup-sandbox-demo-data: ## Create examples/data subdirs and seed files for the fs sandbox demo
	@mkdir -p examples/data examples/data/rules examples/data/cache examples/data/audit \
		examples/data/counters examples/data/plugins examples/data/scratch
	@echo 'allow_tool: "*"' > examples/data/rules/policy.yaml
	@echo '0' > examples/data/counters/rate.txt
	@touch examples/data/plugins/fs-sandbox-demo.wasm
	@rm -rf examples/data/audit/events examples/data/scratch/work examples/data/counters/new
	@echo "Sandbox demo data ready under examples/data/"

run-sandbox-demo: build-test-plugins setup-sandbox-demo-data build-examples ## Run the filesystem sandbox permissions demo
	cargo run --example wasm_fs_sandbox_demo

run-env-demo: build-test-plugins build-examples ## Run the env variable sandbox permissions demo
	cargo run --example wasm_env_sandbox_demo

run-token-attenuator-demo: build-all-plugins build-examples ## Run the token delegation demo
	cargo run --example wasm_token_attenuator_demo

run-network-policy-demo: build-test-plugins build-examples ## Run the network policy sandbox demo
	cargo run --example wasm_network_policy_demo

run-resource-limits-demo: build-test-plugins build-examples ## Run the resource limits sandbox demo
	cargo run --example wasm_resource_limits_demo

# ---------------------------------------------------------------------------
# Benchmarks
# ---------------------------------------------------------------------------

bench-all: build-all-plugins build-bench-plugins build-test-plugins ## Build all plugins and run benchmarks + generate chart
	cargo bench
	@echo "\n========== Generating performance chart ==========\n"
	cd benchmarking && python3 plot_results.py
	@echo "\n========== Benchmarks complete ==========\n"

# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

test: clean-all build-all-plugins build-test-plugins ## Clean, rebuild all plugins, run all tests
	@echo "\n========== Running host unit tests ==========\n"
	cargo test
	@echo "\n========== Running host integration tests ==========\n"
	cargo test --tests -- --ignored
	@echo "\n========== Running plugin unit tests ==========\n"
	@for plugin in $(DEMO_PLUGINS) $(TEST_PLUGINS); do \
		echo "Testing $$plugin..."; \
		cargo test --manifest-path $(PLUGIN_DIR)/Cargo.toml \
			--features $$plugin --no-default-features || exit 1; \
	done
	@echo "\n========== All tests passed ==========\n"

unit-tests: ## Run host unit tests (no WASM plugins needed)
	cargo test

integration-tests: build-all-plugins build-test-plugins ## Run host integration tests (builds plugins first)
	cargo test --tests -- --ignored

plugin-tests: ## Run plugin crate unit tests (all demos)
	cargo test --manifest-path $(PLUGIN_DIR)/Cargo.toml --features test-demos

clippy: ## Run clippy on both host and plugin crates
	cargo clippy -- -D warnings
	cargo clippy --manifest-path $(PLUGIN_DIR)/Cargo.toml --target wasm32-wasip2 -- -D warnings

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

clean: ## Remove host build artifacts and wasm/ binaries
	cargo clean
	rm -f $(WASM_DIR)/*.wasm

clean-all: ## Remove host + plugin build artifacts and ALL .wasm files
	cargo clean
	cargo clean --manifest-path $(PLUGIN_DIR)/Cargo.toml
	cargo clean --manifest-path $(PLUGIN_DIR)/Cargo.toml --target wasm32-wasip2
	rm -f $(WASM_DIR)/*.wasm

# ---------------------------------------------------------------------------
# WIT sync — cpex-wasm-plugin is the source of truth
# ---------------------------------------------------------------------------

sync-wit: ## Copy wit/world.wit from cpex-wasm-plugin (updating the location comment)
	@sed '1s|cpex-wasm-plugin|cpex-wasm-host|' $(PLUGIN_DIR)/wit/world.wit > wit/world.wit
	@echo "wit/world.wit synced from cpex-wasm-plugin"

check-wit: ## Fail if wit/world.wit has drifted from cpex-wasm-plugin
	@sed '1s|cpex-wasm-plugin|cpex-wasm-host|' $(PLUGIN_DIR)/wit/world.wit | diff - wit/world.wit \
		|| { echo "ERROR: wit/world.wit is out of sync — run 'make sync-wit'"; exit 1; }
	@echo "wit/world.wit is in sync"

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-24s\033[0m %s\n", $$1, $$2}'
