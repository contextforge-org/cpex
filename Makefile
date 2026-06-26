# CPEX — Rust workspace Makefile
# =============================================================================
# Targets mirror CI (.github/workflows/) so a green `make ci` locally means a
# green pipeline. The CPEX Python package now lives on the `0.1.x` branch.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

CARGO ?= cargo
GO    ?= go

GO_DIR          = go/cpex
GO_EXAMPLES_DIR = examples/go-demo

HUGO      ?= hugo
DOCS_DIR   = docs
DOCS_PORT ?= 1313

GOLANGCI_LINT ?= golangci-lint

# =============================================================================
# Help
# =============================================================================

.PHONY: help
help:
	@echo "CPEX (Rust) — Makefile"
	@echo ""
	@echo "Build:"
	@echo "  build             Build the workspace (debug)"
	@echo "  build-release     Build the workspace (release, size-optimized)"
	@echo "  check             cargo check the workspace"
	@echo "  clean             Remove the target/ directory"
	@echo ""
	@echo "Lint & format:"
	@echo "  fmt               Format Rust code (cargo fmt --all)"
	@echo "  lint              CI lint gate: fmt --check + clippy -D warnings"
	@echo "  clippy            Run clippy on the workspace (-D warnings)"
	@echo "  lint-fix          Auto-fix: cargo fmt + clippy --fix"
	@echo "  machete           Report unused dependencies (advisory)"
	@echo ""
	@echo "Test:"
	@echo "  test              Run all workspace tests"
	@echo "  test-ffi          Run only the cpex-ffi crate tests"
	@echo "  test-all          Rust tests + Go tests (with -race)"
	@echo ""
	@echo "Supply chain & coverage:"
	@echo "  audit             cargo deny check (advisories, licenses, bans, sources)"
	@echo "  coverage          Line/region coverage summary (cargo-llvm-cov; report only)"
	@echo ""
	@echo "Docs:"
	@echo "  doc               Build API docs (rustdoc, -D warnings)"
	@echo "  docs              Build the Hugo documentation site"
	@echo "  docs-serve        Hugo dev server with live reload"
	@echo "  docs-clean        Remove generated documentation artifacts"
	@echo ""
	@echo "Go bindings (go/cpex):"
	@echo "  go-build go-test go-test-race go-fmt go-vet go-lint-check go-lint-fix"
	@echo ""
	@echo "Examples:"
	@echo "  examples-build    Build all Rust + Go examples (catches stale APIs)"
	@echo "  examples-run      Run all examples end-to-end"
	@echo ""
	@echo "End-to-end:"
	@echo "  ci                Lint + tests + examples-build (CI gate)"
	@echo ""
	@echo "Release (version bump + tag locally; CI publishes on tag push):"
	@echo "  release-dry       Preview the release (no changes)"
	@echo "  release-version   Set the version everywhere (no commit/tag)"
	@echo "  release           Bump + commit + tag (then: git push origin vX.Y.Z)"
	@echo "  publish-dry       Local packaging dry-run (mirrors CI dry-run)"
	@echo "                    Pass LEVEL=alpha|patch|minor|major|rc|release or VERSION=X.Y.Z"

# =============================================================================
# Build
# =============================================================================

.PHONY: build
build:
	@$(CARGO) build --workspace

.PHONY: build-release
build-release:
	@$(CARGO) build --release --workspace

.PHONY: check
check:
	@$(CARGO) check --workspace

.PHONY: clean
clean:
	@$(CARGO) clean

# =============================================================================
# Lint & format
# =============================================================================

.PHONY: fmt
fmt:
	@$(CARGO) fmt --all

.PHONY: clippy
clippy:
	@$(CARGO) clippy --workspace --all-targets -- -D warnings

# CI-safe gate: read-only fmt check + clippy. Lint levels come from the
# [workspace.lints] wall in Cargo.toml.
.PHONY: lint
lint:
	@echo "🦀 fmt --check + clippy -D warnings ..."
	@$(CARGO) fmt --all -- --check
	@$(CARGO) clippy --workspace --all-targets -- -D warnings
	@echo "✅  lint passed"

# Developer convenience: format, then apply clippy's machine-applicable fixes.
.PHONY: lint-fix
lint-fix:
	@$(CARGO) fmt --all
	@$(CARGO) clippy --workspace --all-targets --fix --allow-dirty --allow-staged -- -D warnings

# Advisory: cargo-machete static analysis false-positives on macro/derive-only
# crates, so this is not part of the blocking `lint` gate.
.PHONY: machete
machete:
	@command -v cargo-machete >/dev/null 2>&1 || $(CARGO) install cargo-machete --locked
	@cargo machete || true

# =============================================================================
# Test
# =============================================================================

.PHONY: test
test:
	@$(CARGO) test --workspace

.PHONY: test-ffi
test-ffi:
	@$(CARGO) test -p cpex-ffi --lib

# Rust workspace tests + Go tests under the race detector.
.PHONY: test-all
test-all: test go-test-race

# =============================================================================
# Supply chain & coverage
# =============================================================================

# Single supply-chain gate (advisories + licenses + bans + sources). Policy
# lives in deny.toml.
.PHONY: audit
audit:
	@command -v cargo-deny >/dev/null 2>&1 || $(CARGO) install cargo-deny --locked
	@cargo deny check

# Report-only: prints a coverage summary, does NOT enforce a threshold.
# Add `--fail-under-lines N` here and in coverage.yaml to turn on a gate.
.PHONY: coverage
coverage:
	@command -v cargo-llvm-cov >/dev/null 2>&1 || $(CARGO) install cargo-llvm-cov --locked
	@cargo llvm-cov --workspace --summary-only

# =============================================================================
# Docs
# =============================================================================

.PHONY: doc
doc:
	@RUSTDOCFLAGS="-D warnings" $(CARGO) doc --workspace --no-deps

.PHONY: docs
docs:
	@command -v $(HUGO) >/dev/null 2>&1 || { echo "❌ Hugo not found. Install with: brew install hugo"; exit 1; }
	@cd $(DOCS_DIR) && $(HUGO)

.PHONY: docs-serve
docs-serve:
	@command -v $(HUGO) >/dev/null 2>&1 || { echo "❌ Hugo not found. Install with: brew install hugo"; exit 1; }
	@cd $(DOCS_DIR) && $(HUGO) server --buildDrafts --port $(DOCS_PORT)

.PHONY: docs-clean
docs-clean:
	@rm -rf $(DOCS_DIR)/public $(DOCS_DIR)/resources

# =============================================================================
# Go bindings (go/cpex)
# =============================================================================
#
# go/cpex links against the cpex-ffi cdylib at target/release. Go targets
# ensure the release build is current first — Go's linker errors on a missing
# libcpex_ffi are easy to misread.

.PHONY: go-build
go-build: build-release
	@cd $(GO_DIR) && $(GO) build ./...

.PHONY: go-test
go-test: build-release
	@cd $(GO_DIR) && $(GO) test -count=1 ./...

.PHONY: go-test-race
go-test-race: build-release
	@cd $(GO_DIR) && $(GO) test -count=1 -race ./...

.PHONY: go-vet
go-vet: build-release
	@cd $(GO_DIR) && $(GO) vet ./...

.PHONY: go-fmt
go-fmt:
	@cd $(GO_DIR) && $(GO) fmt ./...

.PHONY: go-lint-fix
go-lint-fix: build-release
	@command -v $(GOLANGCI_LINT) >/dev/null 2>&1 || { \
		echo "❌ golangci-lint not found (brew install golangci-lint)"; exit 1; }
	@cd $(GO_DIR) && $(GO) fmt ./... && $(GO) vet ./... && $(GOLANGCI_LINT) run --fix ./...

.PHONY: go-lint-check
go-lint-check: build-release
	@command -v $(GOLANGCI_LINT) >/dev/null 2>&1 || { \
		echo "❌ golangci-lint not found (brew install golangci-lint)"; exit 1; }
	@cd $(GO_DIR) && unformatted=$$(gofmt -l .); \
		if [ -n "$$unformatted" ]; then echo "❌ Files need formatting:"; echo "$$unformatted"; exit 1; fi
	@cd $(GO_DIR) && $(GO) vet ./... && $(GOLANGCI_LINT) run ./...

# =============================================================================
# Examples
# =============================================================================
#
# Building examples is the cheapest way to catch stale public-API usage: cargo
# test / go test only build code reachable from tests, so an example using a
# renamed function compiles fine in isolation but breaks at example-build time.

.PHONY: rust-examples-build
rust-examples-build:
	@$(CARGO) build --examples --workspace

.PHONY: go-examples-build
go-examples-build: build-release
	@cd $(GO_EXAMPLES_DIR) && $(GO) build ./...

.PHONY: examples-build
examples-build: rust-examples-build go-examples-build
	@echo "✅  All examples built"

.PHONY: examples-run
examples-run: examples-build
	@$(CARGO) run --example plugin_demo -p cpex-core --quiet >/dev/null
	@$(CARGO) run --example cmf_capabilities_demo -p cpex-core --quiet >/dev/null
	@cd $(GO_EXAMPLES_DIR) && $(GO) run . >/dev/null
	@cd $(GO_EXAMPLES_DIR) && $(GO) run ./cmd/cmf-demo >/dev/null
	@echo "✅  All examples ran successfully"

# =============================================================================
# CI gate
# =============================================================================
#
# Canonical local gate: read-only lint, full test suite, example builds. If
# this passes locally, the same checks pass in CI.
.PHONY: ci
ci: lint test examples-build
	@echo "✅  CI gate passed (lint + tests + examples)"

# =============================================================================
# Release
# =============================================================================
#
# This workspace versions and releases every publishable crate together. The
# version lives in ONE place — `[workspace.package] version` plus the
# `[workspace.dependencies]` table in the root Cargo.toml — and cargo-release
# keeps both in sync. Config (shared-version, tag name, publish=false) lives in
# release.toml; the actual crates.io publish runs in CI on the pushed tag.
#
# Bump level (LEVEL) or explicit VERSION:
#   make release-dry                 # preview, no changes (default LEVEL=alpha)
#   make release LEVEL=patch         # 0.2.0 -> 0.2.1
#   make release VERSION=0.2.0       # drop the pre-release suffix
#   git push origin "v$(...)"        # push the tag to let CI publish

LEVEL   ?= alpha
VERSION ?=
# Explicit VERSION wins over LEVEL when set.
RELEASE_ARG = $(if $(VERSION),$(VERSION),$(LEVEL))

.PHONY: release-tool
release-tool:
	@command -v cargo-release >/dev/null 2>&1 || $(CARGO) install cargo-release --locked

# Preview only — cargo-release makes NO changes without --execute.
.PHONY: release-dry
release-dry: release-tool
	@$(CARGO) release $(RELEASE_ARG) --workspace

# Rewrite the version in [workspace.package] + [workspace.dependencies] only;
# no commit, no tag. Useful for a manual, reviewed bump.
.PHONY: release-version
release-version: release-tool
	@$(CARGO) release version $(RELEASE_ARG) --workspace --execute --no-confirm

# Bump + commit + tag, then stop. --no-publish/--no-push enforce the
# "CI publishes on tag push" model at the CLI level too (release.toml already
# sets publish=false/push=false; this makes the guarantee not depend on config
# parsing). Afterwards: `git push origin vX.Y.Z` to trigger the CI publish.
.PHONY: release
release: release-tool
	@$(CARGO) release $(RELEASE_ARG) --workspace --no-publish --no-push --execute

# Build + verify a .crate for every crates.io-published member without
# uploading — the same check the release workflow's dry-run runs. The two
# `publish = false` FFI crates are excluded (cpex-ffi ships as signed prebuilt
# artifacts; cpex-demo-ffi is an example). CI runs this on a clean checkout;
# --allow-dirty lets you run it locally with work in progress.
.PHONY: publish-dry
publish-dry:
	@$(CARGO) package --workspace --locked --allow-dirty --exclude cpex-ffi --exclude cpex-demo-ffi
