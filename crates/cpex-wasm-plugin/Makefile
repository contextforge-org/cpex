.PHONY: build build-debug build-demo build-demos validate validate-demos \
        inspect inspect-demo inspect-demos check check-demos test test-demos \
        test-all fmt fmt-check clippy clippy-demos ci clean help

TARGET        := wasm32-wasip2
TARGET_DIR    := target
PLUGIN_NAME   := cpex_wasm_plugin

# Default profile — override with PROFILE=debug
PROFILE       := release
ARTIFACT       = $(TARGET_DIR)/$(TARGET)/$(PROFILE)/$(PLUGIN_NAME).wasm

# Demo plugin list — one binary is compiled per feature flag.
DEMOS         := identity-checker header-injector audit-logger token-attenuator \
                 tool-invoke-checker pii-guard audit-logger-custom remote-authz \
                 noop fs-test net-test env-test compute-bench fs-sandbox-demo \
                 env-sandbox-demo resource-test net-http-test

# ---------------------------------------------------------------------------
# Build your plugin
# ---------------------------------------------------------------------------

# build: optimized + smaller binary (~3s) — use for deployment
# build-debug: unoptimized + faster compile (~1-2s) — use for iteration

build: ## Build your plugin (release, optimized — for deployment)
	cargo build --target $(TARGET) --release
	@echo "Built: $(ARTIFACT) ($$(du -h $(ARTIFACT) | cut -f1))"

build-debug: ## Build your plugin (debug, fast compile — for iteration)
	cargo build --target $(TARGET)
	@echo "Built: $(TARGET_DIR)/$(TARGET)/debug/$(PLUGIN_NAME).wasm"

# ---------------------------------------------------------------------------
# Build demos (src/examples/)
# ---------------------------------------------------------------------------

build-demo: ## Build a single demo: make build-demo DEMO=noop
ifndef DEMO
	$(error Usage: make build-demo DEMO=<name>  (available: $(DEMOS)))
endif
	cargo build --target $(TARGET) --release --features $(DEMO) --no-default-features
	@mkdir -p wasm
	@cp $(ARTIFACT) wasm/$(DEMO).wasm
	@echo "Built: wasm/$(DEMO).wasm ($$(du -h wasm/$(DEMO).wasm | cut -f1))"

build-demos: ## Build all demo plugins to wasm/ directory
	@mkdir -p wasm
	@for demo in $(DEMOS); do \
		echo "Building $$demo..."; \
		cargo build --target $(TARGET) --release --features $$demo --no-default-features && \
		cp $(ARTIFACT) wasm/$$demo.wasm && \
		echo "  wasm/$$demo.wasm ($$(du -h wasm/$$demo.wasm | cut -f1))"; \
	done
	@echo "All demos built. Output: wasm/"

# ---------------------------------------------------------------------------
# Validation and inspection (requires: cargo install wasm-tools)
# ---------------------------------------------------------------------------

validate: ## Validate the built .wasm component binary
	wasm-tools validate $(ARTIFACT)
	@echo "$(ARTIFACT) is valid"

validate-demos: ## Validate all demo .wasm files in wasm/ directory
	@if [ ! -d wasm ]; then \
		echo "No wasm/ directory — run 'make build-demos' first"; exit 1; \
	fi
	@for f in wasm/*.wasm; do \
		wasm-tools validate "$$f" && echo "  $$f valid"; \
	done
	@echo "All demos valid."

inspect: ## Print the WIT interface embedded in your plugin binary
	wasm-tools component wit $(ARTIFACT)

inspect-demo: ## Print the WIT interface of a demo: make inspect-demo DEMO=noop
ifndef DEMO
	$(error Usage: make inspect-demo DEMO=<name>)
endif
	@if [ ! -f wasm/$(DEMO).wasm ]; then \
		echo "wasm/$(DEMO).wasm not found — run 'make build-demo DEMO=$(DEMO)' first"; exit 1; \
	fi
	wasm-tools component wit wasm/$(DEMO).wasm

inspect-demos: ## Print the WIT interface of all demo .wasm files
	@if [ ! -d wasm ]; then \
		echo "No wasm/ directory — run 'make build-demos' first"; exit 1; \
	fi
	@for f in wasm/*.wasm; do \
		echo "── $$(basename $$f) ──"; \
		wasm-tools component wit "$$f"; \
		echo ""; \
	done

# ---------------------------------------------------------------------------
# Testing
# ---------------------------------------------------------------------------

test: ## Run tests for your plugin (src/plugin.rs)
	cargo test --lib plugin::tests

test-demos: ## Run inline tests for all demo plugins (src/examples/)
	cargo test --features test-demos --lib

test-all: ## Run all tests (plugin + demos + conversions + integration)
	cargo test --features test-demos

# ---------------------------------------------------------------------------
# Code quality
# ---------------------------------------------------------------------------

check: ## Type-check your plugin (fast feedback)
	cargo check --target $(TARGET)

check-demos: ## Type-check all demo plugins
	@for demo in $(DEMOS); do \
		echo "Checking $$demo..."; \
		cargo check --target $(TARGET) --features $$demo --no-default-features || exit 1; \
	done
	@echo "All demos type-check passed."

fmt: ## Format source code
	cargo fmt

fmt-check: ## Check formatting without modifying files
	cargo fmt -- --check

clippy: ## Run clippy lints on your plugin
	cargo clippy --target $(TARGET) -- -D warnings

clippy-demos: ## Run clippy lints on all demo plugins
	@for demo in $(DEMOS); do \
		echo "Clippy $$demo..."; \
		cargo clippy --target $(TARGET) --features $$demo --no-default-features -- -D warnings || exit 1; \
	done
	@echo "All demos clippy passed."

# ---------------------------------------------------------------------------
# CI (run everything: format check, lint, test, build, validate)
# ---------------------------------------------------------------------------

ci: ## Run full CI pipeline (fmt check + clippy + test + build + validate)
	@echo "── Format check ──"
	cargo fmt -- --check
	@echo "── Clippy ──"
	cargo clippy --target $(TARGET) -- -D warnings
	@echo "── Tests (all) ──"
	cargo test --features test-demos
	@echo "── Build (plugin) ──"
	cargo build --target $(TARGET) --release
	@echo "── Validate ──"
	wasm-tools validate $(ARTIFACT)
	@echo ""
	@echo "CI passed."

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

clean: ## Remove all build artifacts
	cargo clean
	rm -rf wasm

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'
