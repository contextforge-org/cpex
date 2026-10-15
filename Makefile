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
	@echo "  test-python-e2e   Python host e2e (#[ignore]d); needs CPEX_PYTHON_SOURCE."
	@echo "                    Skips FAIL here — this lane must really run."
	@echo "  parity            Replay the 0.2.3 snapshots (cpex-parity-harness)."
	@echo "                    Set PARITY_VALKEY_URL to include Valkey; skips then fail."
	@echo "  test-acceptance   Python bindings + Go acceptance suites"
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
	@echo "  ffi-release       Build the cpex-ffi release library the Go package links"
	@echo "  go-build go-test go-test-race go-fmt go-vet go-lint-check go-lint-fix"
	@echo "  go-test-acceptance  Go acceptance tests (TestAcceptance*), with -race"
	@echo "                    GO_STATIC=1 removes the shared library first, so Go"
	@echo "                    links libcpex_ffi.a as release consumers do (CI sets it)"
	@echo ""
	@echo "Python bindings (bindings/python — requires maturin):"
	@echo "  bindings-python-build          Build and install Python bindings (debug)"
	@echo "  bindings-python-build-release  Build Python bindings wheel (release)"
	@echo "  bindings-python-test           Build + run Python binding tests"
	@echo "  bindings-python-smoke          Build the wheel, install it in a fresh venv, run a policy"
	@echo "  bindings-python-acceptance     Build + run the Python acceptance tests"
	@echo ""
	@echo "Examples:"
	@echo "  examples-build    Build all Rust + Go examples (catches stale APIs)"
	@echo "  examples-run      Run the tutorial (no-IdP) checks and the Go demos"
	@echo ""
	@echo "End-to-end:"
	@echo "  ci                Lint + tests + examples-build (CI gate)"
	@echo ""
	@echo "Release (version bump + tag locally; CI publishes on tag push):"
	@echo "  release-dry       Preview the release (no changes)"
	@echo "  release-version   Set the version everywhere (no commit/tag)"
	@echo "  release           Bump + commit + tag (then: git push origin vX.Y.Z)"
	@echo "  publish-dry       Local packaging dry-run (mirrors CI dry-run)"
	@echo "  release-check     Check versions, publishable crates, PPE pins and ABI"
	@echo "  ffi-package       Package a host FFI tarball + checksum in dist/"
	@echo "  ffi-verify        Package, verify and race-test Go against that archive"
	@echo "  release-verify    Rust lint/tests/packages + FFI verification + examples"
	@echo "                    Pass LEVEL=alpha|patch|minor|major|rc|release or VERSION=X.Y.Z"
	@echo "  tag               Tag + push all 3 release tags: make tag VERSION=X.Y.Z"

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
	@$(CARGO) clippy -p cpex --all-targets --all-features -- -D warnings
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
	@$(CARGO) test -p cpex --features python-host

.PHONY: test-ffi
test-ffi:
	@$(CARGO) test -p cpex-ffi --lib

# The Python host's end-to-end tests. They are `#[ignore]`d because they need a
# python3 and a checkout of the cpex Python side, so `make test` reports them as
# ignored rather than passing a body that never ran.
#
# CPEX_REQUIRE_PYTHON_E2E=1 turns every in-test skip into a panic: this target
# is the lane that is supposed to have the environment, so a skip here is a
# broken lane, not an absent dependency. That is what stops the suite reporting
# safety it has not verified.
#
# CPEX_PYTHON_SOURCE must point at a cpex Python checkout carrying
# cpex/framework/isolated/worker.py (PyPI's is behind this branch).
# config_e2e is left out: it needs cpex-test-plugin installed under plugins/.
PYTHON_E2E_TESTS ?= credential_e2e isolated_venv_e2e extensions_merge_e2e acceptance_e2e

.PHONY: test-python-e2e
test-python-e2e:
	@command -v python3 >/dev/null 2>&1 || { \
		echo "❌ python3 not found — the Python host e2e tests need an interpreter"; exit 1; }
	@test -n "$(CPEX_PYTHON_SOURCE)" || { \
		echo "❌ CPEX_PYTHON_SOURCE is unset. Point it at a cpex Python checkout containing"; \
		echo "   cpex/framework/isolated/worker.py, e.g.:"; \
		echo "   make test-python-e2e CPEX_PYTHON_SOURCE=../cpex-python"; exit 1; }
	@test -f "$(CPEX_PYTHON_SOURCE)/cpex/framework/isolated/worker.py" || { \
		echo "❌ $(CPEX_PYTHON_SOURCE) has no cpex/framework/isolated/worker.py"; exit 1; }
	@echo "🐍 Python host e2e (skips fail here) ..."
	@for t in $(PYTHON_E2E_TESTS); do \
		echo "→ $$t"; \
		CPEX_REQUIRE_PYTHON_E2E=1 CPEX_PYTHON_SOURCE="$(CPEX_PYTHON_SOURCE)" \
			$(CARGO) test -p cpex-hosts-python --test $$t \
			-- --ignored --nocapture || exit 1; \
	done
	@echo "✅  Python host e2e passed (no skips)"

# Rust workspace tests + Go tests under the race detector.
.PHONY: test-all
test-all: test go-test-race

# Parity with the 0.2.3 baseline: replays every recorded scenario through the
# current engine and diffs it against tests/parity/snapshots. See
# tests/parity/README.md.
#
# Valkey scenarios and the stored-label read-back need a throwaway Valkey (the
# harness runs FLUSHDB on it):
#   docker run -d --rm -p 127.0.0.1:6391:6379 valkey/valkey:8-alpine
#   make parity PARITY_VALKEY_URL=redis://127.0.0.1:6391/0
# Without PARITY_VALKEY_URL those scenarios are skipped. With it set, any
# skip fails the target, so a lane that is meant to have Valkey cannot pass
# without it.
PARITY_LOG = target/parity-test.log

.PHONY: parity
parity:
	@mkdir -p target
	@echo "🔁 parity against the 0.2.3 snapshots ..."
	@PARITY_VALKEY_URL="$(PARITY_VALKEY_URL)" \
		$(CARGO) test -p cpex-parity-harness -- --nocapture 2>&1 | tee $(PARITY_LOG)
	@if [ -n "$(PARITY_VALKEY_URL)" ] && grep -q 'SKIPPED' $(PARITY_LOG); then \
		echo "❌ PARITY_VALKEY_URL is set but some parity checks were skipped:"; \
		grep 'SKIPPED' $(PARITY_LOG); exit 1; fi
	@echo "✅  parity passed"

# Acceptance suites that live beside each surface's own tests: the Python
# bindings (tests/test_acceptance.py) and the Go package (TestAcceptance*).
# The Python host's acceptance coverage runs in test-python-e2e.
.PHONY: test-acceptance
test-acceptance: bindings-python-acceptance go-test-acceptance

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
# Python bindings (bindings/python)
# =============================================================================
#
# cpex-python is built via maturin, not plain cargo. The targets below
# require maturin to be installed (`pip install maturin`). The crate is
# excluded from the pure-Rust `rust-build` / `rust-test` targets so those
# paths stay libpython-independent (KD3).

PYTHON_BINDINGS_DIR = bindings/python
VENV_BIN = .venv/bin
MATURIN ?= maturin

.PHONY: bindings-python-build
bindings-python-build:
	@echo "🐍 Building Python bindings (debug)..."
	@cd $(PYTHON_BINDINGS_DIR) && python -m venv .venv && source .venv/bin/activate && pip install maturin pytest pytest-asyncio && $(MATURIN) develop
	@echo "✅  Python bindings built (debug)"

.PHONY: bindings-python-build-release
bindings-python-build-release:
	@echo "🐍 Building Python bindings (release)..."
	@cd $(PYTHON_BINDINGS_DIR) && python -m venv .venv && source .venv/bin/activate && pip install maturin pytest pytest-asyncio && $(MATURIN) build --release
	@echo "✅  Python bindings built (release)"

.PHONY: bindings-python-test
bindings-python-test: bindings-python-build
	@echo "🧪 Running Python binding tests..."
	@cd $(PYTHON_BINDINGS_DIR) && $(VENV_BIN)/pytest tests/ -v
	@echo "✅  Python binding tests passed"

.PHONY: bindings-python-acceptance
bindings-python-acceptance: bindings-python-build
	@echo "🧪 Running Python binding acceptance tests..."
	@cd $(PYTHON_BINDINGS_DIR) && $(VENV_BIN)/pytest tests/test_acceptance.py -v
	@echo "✅  Python binding acceptance tests passed"

# Builds a release wheel, installs it into a fresh venv and runs a policy from
# outside the source tree. Needs only python3; the script installs maturin into
# a throwaway venv when it is not on PATH.
PYTHON ?= python3

.PHONY: bindings-python-smoke
bindings-python-smoke:
	@echo "🐍 Python wheel smoke test..."
	@$(PYTHON) $(PYTHON_BINDINGS_DIR)/tests/smoke_wheel.py

# =============================================================================
# Go bindings (go/cpex)
# =============================================================================
#
# go/cpex links -lcpex_ffi from target/release. Go targets build cpex-ffi in
# release mode first, since Go's linker errors on a missing libcpex_ffi are
# easy to misread.
#
# cpex-ffi builds both a shared and a static library, and the linker prefers
# the shared one when both are present. GO_STATIC=1 deletes the shared library
# after the build so Go links libcpex_ffi.a, the way consumers of the release
# artifacts do. That also checks the native link flags in go/cpex/ffi.go. CI
# sets it; locally the default keeps the shared library.
GO_STATIC ?=
FFI_LIB_DIR = target/release

.PHONY: ffi-release
ffi-release:
	@$(CARGO) build --release --locked -p cpex-ffi
	@if [ "$(GO_STATIC)" = "1" ]; then \
		rm -f $(FFI_LIB_DIR)/libcpex_ffi.so $(FFI_LIB_DIR)/libcpex_ffi.dylib; \
		echo "→ GO_STATIC=1: Go links $(FFI_LIB_DIR)/libcpex_ffi.a"; fi

.PHONY: go-build
go-build: ffi-release
	@cd $(GO_DIR) && $(GO) build ./...

.PHONY: go-test
go-test: ffi-release
	@cd $(GO_DIR) && $(GO) test -count=1 ./...

.PHONY: go-test-race
go-test-race: ffi-release
	@cd $(GO_DIR) && $(GO) test -count=1 -race ./...

# Go acceptance tests follow the TestAcceptance* naming. go-test and
# go-test-race already run them along with the rest of the package.
.PHONY: go-test-acceptance
go-test-acceptance: ffi-release
	@cd $(GO_DIR) && $(GO) test -count=1 -race -run '^TestAcceptance' -v ./...

.PHONY: go-vet
go-vet: ffi-release
	@cd $(GO_DIR) && $(GO) vet ./...

.PHONY: go-fmt
go-fmt:
	@cd $(GO_DIR) && $(GO) fmt ./...

.PHONY: go-lint-fix
go-lint-fix: ffi-release
	@command -v $(GOLANGCI_LINT) >/dev/null 2>&1 || { \
		echo "❌ golangci-lint not found (brew install golangci-lint)"; exit 1; }
	@cd $(GO_DIR) && $(GO) fmt ./... && $(GO) vet ./... && $(GOLANGCI_LINT) run --fix ./...

.PHONY: go-lint-check
go-lint-check: ffi-release
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

# The Go demo links both its factory staticlib and the CPEX Go SDK's FFI library.
.PHONY: go-examples-ffi
go-examples-ffi: ffi-release
	@$(CARGO) build --release -p cpex-demo-ffi

.PHONY: go-examples-build
go-examples-build: go-examples-ffi
	@cd $(GO_EXAMPLES_DIR) && $(GO) build ./...

.PHONY: examples-build
examples-build: rust-examples-build go-examples-build
	@echo "✅  All examples built"

# The tutorial modules are the Rust examples; tutorial-check-local runs the
# ones that need no IdP.
.PHONY: examples-run
examples-run: examples-build tutorial-check-local
	@cd $(GO_EXAMPLES_DIR) && $(GO) run . >/dev/null
	@cd $(GO_EXAMPLES_DIR) && $(GO) run ./cmd/cmf-demo >/dev/null
	@echo "✅  All examples ran successfully"

# =============================================================================
# Tutorial (examples/tutorial)
# =============================================================================
#
# The tutorial ships one runnable binary per module, each with a `--check`
# mode that asserts its scripted scenario. `tutorial-check-local` runs the
# modules that need no infrastructure; `tutorial-check` additionally brings
# up the tutorial Keycloak (docker compose) and runs the IdP-backed modules,
# tearing the stack down afterward. CI runs `tutorial-check`.
#
# Module 16 needs the SPIRE overlay and a one-time Keycloak setup on top of
# the base stack, so it has its own opt-in target (`tutorial-check-spire`).

TUTORIAL_IDP_COMPOSE = examples/tutorial/idp/docker-compose.yml
TUTORIAL_SPIRE_COMPOSE = examples/tutorial/idp/docker-compose.spire.yml
TUTORIAL_NOIDP_MODULES = m01_hello m03_shaping m04_effects m09_custom_plugin m10_testing
TUTORIAL_IDP_MODULES = m02_identity m05_pdp m06_delegation m07_tainting m08_elicitation \
                       m11_groups m12_subjects m13_client m14_passthrough m15_dual_principal \
                       m17_federation m18_attributes capstone

.PHONY: tutorial-check-local
tutorial-check-local:
	@for m in $(TUTORIAL_NOIDP_MODULES); do \
		echo "→ tutorial $$m --check"; \
		$(CARGO) run -q -p cpex-tutorial --example $$m -- --check >/dev/null || exit 1; \
	done
	@echo "✅  Tutorial (no-IdP) checks passed"

.PHONY: tutorial-check
tutorial-check: tutorial-check-local
	@echo "→ starting tutorial IdP"
	@docker compose -f $(TUTORIAL_IDP_COMPOSE) up -d
	@echo "→ waiting for Keycloak realm to be ready"
	@$(CARGO) run -q -p cpex-tutorial --example wait_for_idp || { \
		docker compose -f $(TUTORIAL_IDP_COMPOSE) down; exit 1; }
	@for m in $(TUTORIAL_IDP_MODULES); do \
		echo "→ tutorial $$m --check"; \
		$(CARGO) run -q -p cpex-tutorial --example $$m -- --check || { \
			docker compose -f $(TUTORIAL_IDP_COMPOSE) down; exit 1; }; \
	done
	@docker compose -f $(TUTORIAL_IDP_COMPOSE) down
	@echo "✅  Tutorial checks passed (incl. IdP-backed modules)"

# Module 16 only. Brings up the SPIRE overlay, trusts SPIRE in Keycloak, and
# runs the workload-identity module. Not part of the CI gate: it needs two
# extra containers and a Keycloak that speaks SPIFFE.
.PHONY: tutorial-check-spire
tutorial-check-spire:
	@echo "→ starting tutorial IdP + SPIRE"
	@docker compose -f $(TUTORIAL_IDP_COMPOSE) -f $(TUTORIAL_SPIRE_COMPOSE) up -d
	@echo "→ waiting for Keycloak realm to be ready"
	@$(CARGO) run -q -p cpex-tutorial --example wait_for_idp || { \
		docker compose -f $(TUTORIAL_IDP_COMPOSE) -f $(TUTORIAL_SPIRE_COMPOSE) down; exit 1; }
	@examples/tutorial/idp/spire/setup-spiffe.sh || { \
		docker compose -f $(TUTORIAL_IDP_COMPOSE) -f $(TUTORIAL_SPIRE_COMPOSE) down; exit 1; }
	@echo "→ tutorial m16_workload --check"
	@$(CARGO) run -q -p cpex-tutorial --example m16_workload -- --check || { \
		docker compose -f $(TUTORIAL_IDP_COMPOSE) -f $(TUTORIAL_SPIRE_COMPOSE) down; exit 1; }
	@docker compose -f $(TUTORIAL_IDP_COMPOSE) -f $(TUTORIAL_SPIRE_COMPOSE) down
	@echo "✅  Tutorial SPIRE check passed (module 16)"

.PHONY: tutorial-recordings
tutorial-recordings:
	@examples/tutorial/recordings/record.sh
	@echo "Upload each cast to asciinema.org, then embed per examples/tutorial/recordings/README.md"

# =============================================================================
# CI gate
# =============================================================================
#
# Canonical local gate: read-only lint, full test suite, example builds. If
# this passes locally, the same checks pass in CI.
.PHONY: ci
ci: lint test examples-build bindings-python-build-release bindings-python-test
	@echo "✅  CI gate passed (lint + tests + examples + bindings/python)"

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
#   make release-dry VERSION=0.3.0   # preview, no changes
#   make release LEVEL=patch         # next patch release
#   make release VERSION=0.3.0       # explicit release version
#   git push origin "v$(...)"        # push the tag to let CI publish

LEVEL   ?= release
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

# Build + verify a .crate for every crates.io-published member (cpex,
# cpex-hosts-python, cpex-plugin-delegator-biscuit, cpex-python) without
# uploading — the same check the release workflow's dry-run runs. The four
# `publish = false` crates are excluded (cpex-ffi ships as signed prebuilt
# artifacts; cpex-demo-ffi and cpex-tutorial are examples; cpex-parity-harness
# is a test harness). CI runs this on a clean checkout; --allow-dirty lets you
# run it locally with work in progress.
.PHONY: publish-dry
publish-dry: release-check
	@$(CARGO) package --workspace --locked --allow-dirty --exclude cpex-ffi --exclude cpex-demo-ffi --exclude cpex-tutorial --exclude cpex-parity-harness

.PHONY: release-check
release-check:
	@$(PYTHON) scripts/release/check-release.py $(if $(VERSION),--version "$(VERSION)")

# Local artifacts use the same builder as the CI target matrix. Verification
# uses a fresh Go module copy so cgo cannot find a workspace shared library.
FFI_TARGET ?= $(shell rustc -vV | sed -n 's/^host: //p')
DIST_DIR ?= dist

.PHONY: ffi-package
ffi-package: release-check
	@TARGET="$(FFI_TARGET)" VERSION="$(VERSION)" DIST_DIR="$(DIST_DIR)" bash scripts/release/build-artifact.sh

.PHONY: ffi-verify
ffi-verify: ffi-package
	@TARGET="$(FFI_TARGET)" VERSION="$(VERSION)" DIST_DIR="$(DIST_DIR)" GO="$(GO)" bash scripts/release/verify-artifact.sh

# Keep these sequential even under make -j: Go example builds and GO_STATIC
# alter library files, while ffi-verify must consume only the packaged archive.
.PHONY: release-verify
release-verify: release-check
	@$(MAKE) lint test
	@$(MAKE) publish-dry
	@$(MAKE) ffi-verify
	@$(MAKE) examples-run GO_STATIC=1

# Tag the current commit across the three namespaces the project releases on,
# then push all three. The `v<version>` tag is what the CI release workflow
# triggers on; `go/cpex/v<version>` is the Go module tag; the bare `<version>`
# is the crates.io-style tag. VERSION must be semver (e.g. 0.3.0 or
# 0.3.0-rc.1), with no leading `v`.
#   make tag VERSION=0.3.0
.PHONY: tag
tag: release-check
	@test -n "$(VERSION)" || { echo "usage: make tag VERSION=X.Y.Z[-prerelease]"; exit 1; }
	@echo "$(VERSION)" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$$' \
		|| { echo "error: VERSION '$(VERSION)' is not semver (e.g. 0.3.0 or 0.3.0-rc.1; no leading 'v')"; exit 1; }
	git tag v$(VERSION)
	git tag go/cpex/v$(VERSION)
	git tag $(VERSION)
	git push origin v$(VERSION)
	git push origin go/cpex/v$(VERSION)
	git push origin $(VERSION)
