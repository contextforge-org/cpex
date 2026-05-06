# Cpex Plugin Framework Makefile
# =============================================================================

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

# Project variables
PACKAGE_NAME = cpex
PROJECT_NAME = cpex
SRC_DIR = cpex
TEST_DIR = tests
TARGET ?= $(SRC_DIR)

# Virtual-environment variables
VENV_DIR  ?= $(HOME)/.venv/$(PROJECT_NAME)
VENV_BIN  = $(VENV_DIR)/bin

# Python
PYTHON = python3
PYTEST_ARGS ?=

# =============================================================================
# Help
# =============================================================================

.PHONY: help
help:
	@echo "ContextForge Plugin Framework - Makefile"
	@echo ""
	@echo "Environment Setup:"
	@echo "  venv              Create a new virtual environment"
	@echo "  install           Install package from sources"
	@echo "  install-dev       Install package in editable mode with dev deps"
	@echo "  install-docs      Install package in editable mode with docs deps"
	@echo "  install-all       Install package in editable mode all optional deps"
	@echo ""
	@echo "Development:"
	@echo "  lint              Run all linters (black, ruff)"
	@echo "  lint-fix          Auto-fix linting issues"
	@echo "  lint-check        Check for linting issues without fixing"
	@echo "  format            Format code with black and ruff"
	@echo "  type-check        Run mypy type checking"
	@echo ""
	@echo "Testing:"
	@echo "  test              Run all tests with pytest"
	@echo "  test-cov          Run tests with coverage report"
	@echo "  test-verbose      Run tests in verbose mode"
	@echo "  test-file FILE=path/to/test.py  Run specific test file"
	@echo ""
	@echo "Documentation (requires Hugo: brew install hugo):"
	@echo "  docs              Build the documentation site"
	@echo "  docs-serve        Start local Hugo dev server with live reload"
	@echo "  docs-clean        Remove generated documentation artifacts"
	@echo ""
	@echo "Building & Distribution:"
	@echo "  dist              Build wheel + sdist into ./dist"
	@echo "  wheel             Build wheel only"
	@echo "  sdist             Build source distribution only"
	@echo "  verify            Build and verify package with twine"
	@echo ""
	@echo "Rust (cpex-core / cpex-ffi / cpex-sdk):"
	@echo "  rust-build        Build the Rust workspace (debug)"
	@echo "  rust-build-release  Build the Rust workspace (release)"
	@echo "  rust-test         Run all Rust workspace tests"
	@echo "  rust-test-ffi     Run only the cpex-ffi crate tests"
	@echo "  rust-fmt          Format Rust code with rustfmt"
	@echo "  rust-clippy       Run clippy on the Rust workspace"
	@echo "  rust-lint         Auto-fix style + clippy issues (alias for rust-lint-fix)"
	@echo "  rust-lint-fix     Same as rust-lint — mutating fmt + clippy --fix"
	@echo "  rust-lint-check   Read-only fmt --check + clippy (CI-safe)"
	@echo "  rust-clean        Remove the Rust target/ directory"
	@echo ""
	@echo "Go (go/cpex):"
	@echo "  go-build          Build the Go cpex package (requires libcpex_ffi)"
	@echo "  go-test           Run Go tests"
	@echo "  go-test-race      Run Go tests with the race detector"
	@echo "  go-fmt            Format Go code with gofmt"
	@echo "  go-vet            Run go vet"
	@echo "  go-lint           Auto-fix style + lint issues (alias for go-lint-fix)"
	@echo "  go-lint-fix       Same as go-lint — gofmt -w + vet + golangci-lint --fix"
	@echo "  go-lint-check     Read-only gofmt -l + vet + golangci-lint (CI-safe)"
	@echo ""
	@echo "Examples:"
	@echo "  examples-build    Build all Rust + Go examples (catches stale APIs)"
	@echo "  examples-run      Run all examples end-to-end"
	@echo ""
	@echo "End-to-end:"
	@echo "  test-all          Run Rust workspace tests + Go tests w/ -race"
	@echo "  ci                Lint-check + tests + examples-build (CI gate)"
	@echo ""
	@echo "Utilities:"
	@echo "  clean             Remove all artifacts and builds"
	@echo "  clean-all         Remove artifacts, builds, and venv"
	@echo "  run-main          Run main.py with PYTHONPATH set"
	@echo "  uninstall         Uninstall package"
	@echo "  grpc-proto        Generate gRPC stubs for external plugin transport"

# =============================================================================
# Virtual Environment
# =============================================================================

.PHONY: venv
venv:
	@echo "🔧 Creating virtual environment..."
	@rm -rf "$(VENV_DIR)"
	@test -d "$(VENV_DIR)" || mkdir -p "$(VENV_DIR)"
	@$(PYTHON) -m venv "$(VENV_DIR)"
	@$(VENV_BIN)/python -m pip install --upgrade pip setuptools wheel
	@echo "✅  Virtual env created at: $(VENV_DIR)"
	@echo "💡  Activate it with:"
	@echo "    source $(VENV_DIR)/bin/activate"

.PHONY: install
install: venv
	@echo "📦 Installing package..."
	@$(VENV_BIN)/pip install .
	@echo "✅  Package installed"

.PHONY: install-dev
install-dev: venv
	@echo "📦 Installing package with dev dependencies..."
	@$(VENV_BIN)/pip install -e ".[dev,all]"
	@echo "✅  Package installed in editable mode with dev dependencies"

.PHONY: install-docs
install-docs: venv
	@echo "📦 Installing package with docs dependencies..."
	@$(VENV_BIN)/pip install -e ".[docs]"
	@echo "✅  Package installed in editable mode with docs dependencies"

.PHONY: install-all
install-all: venv
	@echo "📦 Installing package with all optional dependencies..."
	@$(VENV_BIN)/pip install -e ".[dev,docs,all]"
	@echo "✅  Package installed in editable mode with all optional dependencies"

.PHONY: uninstall
uninstall:
	@echo "🗑️  Uninstalling package..."
	@$(VENV_BIN)/pip uninstall -y $(PACKAGE_NAME) 2>/dev/null || true
	@echo "✅  Package uninstalled"

# =============================================================================
# Linting & Formatting
# =============================================================================

.PHONY: vulture
vulture:
	@echo "⚡ Running vulture on $(TARGET)..."
	@$(VENV_BIN)/vulture $(TARGET)

.PHONY: interrogate
interrogate:
	@echo "⚡ Running interrogate on $(TARGET)..."
	@$(VENV_BIN)/interrogate $(TARGET)

.PHONY: interrogate-verbose
interrogate-verbose:
	@echo "⚡ Running interrogate on $(TARGET)..."
	@$(VENV_BIN)/interrogate -vv $(TARGET)

.PHONY: radon
radon:
	@echo "⚡ Running radon on $(TARGET)..."
	@$(VENV_BIN)/radon cc $(TARGET) --min C --show-complexity

.PHONY: ruff
ruff:
	@echo "⚡ Running ruff on $(TARGET)..."
	@$(VENV_BIN)/ruff check $(TARGET) --fix
	@$(VENV_BIN)/ruff format $(TARGET)

.PHONY: ruff-check
ruff-check:
	@echo "⚡ Checking ruff on $(TARGET)..."
	@$(VENV_BIN)/ruff check $(TARGET)

.PHONY: ruff-fix
ruff-fix:
	@echo "⚡ Fixing ruff issues in $(TARGET)..."
	@$(VENV_BIN)/ruff check --fix $(TARGET)

.PHONY: ruff-format
ruff-format:
	@echo "⚡ Formatting with ruff on $(TARGET)..."
	@$(VENV_BIN)/ruff format $(TARGET)

.PHONY: ruff-format-check
ruff-format-check:
	@echo "⚡ Checking formatting with ruff on $(TARGET)..."
	@$(VENV_BIN)/ruff format --check $(TARGET)

.PHONY: format
format: ruff-format
	@echo "✅  Code formatted"

.PHONY: lint
lint: lint-fix

.PHONY: lint-fix
lint-fix:
	@# Handle file arguments
	@target_file="$(word 2,$(MAKECMDGOALS))"; \
	if [ -n "$$target_file" ] && [ "$$target_file" != "" ]; then \
		actual_target="$$target_file"; \
	else \
		actual_target="$(TARGET)"; \
	fi; \
	for target in $$(echo $$actual_target); do \
		if [ ! -e "$$target" ]; then \
			echo "❌ File/directory not found: $$target"; \
			exit 1; \
		fi; \
	done; \
	echo "🔧 Fixing lint issues in $$actual_target..."; \
	$(MAKE) --no-print-directory ruff-fix TARGET="$$actual_target"; \
	$(MAKE) --no-print-directory ruff-format TARGET="$$actual_target"; \
	echo "✅  Lint issues fixed"

.PHONY: lint-check
lint-check:
	@# Handle file arguments
	@target_file="$(word 2,$(MAKECMDGOALS))"; \
	if [ -n "$$target_file" ] && [ "$$target_file" != "" ]; then \
		actual_target="$$target_file"; \
	else \
		actual_target="$(TARGET)"; \
	fi; \
	echo "🔍 Checking for lint issues..."; \
	$(MAKE) --no-print-directory ruff-check TARGET="$$actual_target"; \
	$(MAKE) --no-print-directory ruff-format-check TARGET="$$actual_target"; \
	echo "✅  Lint check complete"

.PHONY: type-check
type-check:
	@echo "🔍 Running mypy type checking..."
	@$(VENV_BIN)/mypy $(SRC_DIR) --ignore-missing-imports
	@echo "✅  Type checking complete"

# =============================================================================
# Testing
# =============================================================================

.PHONY: test
test:
	@echo "🧪 Running tests..."
	@PYTHONPATH="$(SRC_DIR)" $(VENV_BIN)/pytest -n auto $(TEST_DIR) $(PYTEST_ARGS)

.PHONY: test-cov
test-cov:
	@echo "🧪 Running tests with coverage..."
	@PYTHONPATH="$(SRC_DIR)" $(VENV_BIN)/pytest -n auto $(TEST_DIR) \
		--cov=$(SRC_DIR) \
		--cov-report=html \
		--cov-report=term-missing \
		$(PYTEST_ARGS)
	@echo "📊 Coverage report generated in htmlcov/"

.PHONY: test-verbose
test-verbose:
	@$(MAKE) test PYTEST_ARGS="-vv"

.PHONY: test-file
test-file:
	@if [ -z "$(FILE)" ]; then \
		echo "❌ Please specify FILE=path/to/test.py"; \
		exit 1; \
	fi
	@echo "🧪 Running test file: $(FILE)..."
	@PYTHONPATH="$(SRC_DIR)" $(VENV_BIN)/pytest $(FILE) $(PYTEST_ARGS)

doctest:
	@echo "🧪 Running doctest on all modules..."
	@PYTHONPATH="$(SRC_DIR)" $(VENV_BIN)/pytest --doctest-modules cpex/ --ignore=cpex/templates --tb=short --no-cov --disable-warnings

# =============================================================================
# Documentation (Hugo Book theme — no Python deps required)
# =============================================================================

HUGO ?= hugo
DOCS_DIR = docs
DOCS_PORT ?= 1313

.PHONY: docs
docs:
	@command -v $(HUGO) >/dev/null 2>&1 || { echo "❌ Hugo not found. Install with: brew install hugo"; exit 1; }
	@echo "📖 Building documentation site..."
	@cd $(DOCS_DIR) && $(HUGO)
	@echo "✅  Site built in $(DOCS_DIR)/public/"

.PHONY: docs-serve
docs-serve:
	@command -v $(HUGO) >/dev/null 2>&1 || { echo "❌ Hugo not found. Install with: brew install hugo"; exit 1; }
	@echo "📖 Starting Hugo dev server on http://localhost:$(DOCS_PORT)/ ..."
	@cd $(DOCS_DIR) && $(HUGO) server --buildDrafts --port $(DOCS_PORT)

.PHONY: docs-clean
docs-clean:
	@echo "🧹 Cleaning documentation build artifacts..."
	@rm -rf $(DOCS_DIR)/public $(DOCS_DIR)/resources
	@echo "✅  Documentation artifacts cleaned"

# =============================================================================
# Building & Distribution
# =============================================================================

.PHONY: check-manifest
check-manifest:
	@echo "📦  Verifying MANIFEST.in completeness..."
	@$(VENV_BIN)/check-manifest

.PHONY: dist
dist: clean
	@echo "📦 Building distribution packages..."
	@test -d "$(VENV_DIR)" || $(MAKE) --no-print-directory venv
	@$(VENV_BIN)/python -m pip install --quiet --upgrade pip build
	@$(VENV_BIN)/python -m build
	@echo "✅  Wheel & sdist written to ./dist"

.PHONY: wheel
wheel:
	@echo "📦 Building wheel..."
	@test -d "$(VENV_DIR)" || $(MAKE) --no-print-directory venv
	@$(VENV_BIN)/python -m pip install --quiet --upgrade pip build
	@$(VENV_BIN)/python -m build -w
	@echo "✅  Wheel written to ./dist"

.PHONY: sdist
sdist:
	@echo "📦 Building source distribution..."
	@test -d "$(VENV_DIR)" || $(MAKE) --no-print-directory venv
	@$(VENV_BIN)/python -m pip install --quiet --upgrade pip build
	@$(VENV_BIN)/python -m build -s
	@echo "✅  Source distribution written to ./dist"

.PHONY: verify
verify: dist check-manifest
	@echo "🔍 Verifying package..."
	@$(VENV_BIN)/twine check dist/*
	@echo "✅  Package verified - ready to publish"

.PHONY: publish-test
publish-test: verify
	@echo "📤 Publishing to TestPyPI..."
	@$(VENV_BIN)/twine upload --repository testpypi dist/*

.PHONY: publish
publish: verify
	@echo "📤 Publishing to PyPI..."
	@$(VENV_BIN)/twine upload dist/*

# =============================================================================
# Utilities
# =============================================================================

.PHONY: run-main
run-main:
	@echo "🚀 Running main.py..."
	@PYTHONPATH="$(SRC_DIR)" $(PYTHON) main.py

.PHONY: clean
clean:
	@echo "🧹 Cleaning build artifacts..."
	@find . -type f -name '*.py[co]' -delete
	@find . -type d -name __pycache__ -delete
	@rm -rf *.egg-info .pytest_cache tests/.pytest_cache build dist .ruff_cache .coverage htmlcov .mypy_cache docs/public docs/resources
	@echo "✅  Build artifacts cleaned"

.PHONY: clean-all
clean-all: clean
	@echo "🧹 Cleaning virtual environment..."
	@rm -rf "$(VENV_DIR)"
	@echo "✅  Everything cleaned"

.PHONY: show-venv
show-venv:
	@echo "Virtual environment: $(VENV_DIR)"
	@if [ -d "$(VENV_DIR)" ]; then \
		echo "Status: ✅ EXISTS"; \
		echo "Python: $$($(VENV_BIN)/python --version 2>&1)"; \
		echo "Pip: $$($(VENV_BIN)/pip --version 2>&1)"; \
	else \
		echo "Status: ❌ NOT FOUND"; \
		echo "Run 'make venv' to create it"; \
	fi

.PHONY: show-deps
show-deps:
	@echo "📋 Installed packages:"
	@$(VENV_BIN)/pip list


.PHONY: grpc-proto
grpc-proto:                          ## Generate gRPC stubs for external plugin transport
	@echo "🔧  Generating gRPC protocol buffer stubs..."
	@test -d "$(VENV_DIR)" || $(MAKE) venv
	@/bin/bash -c "source $(VENV_DIR)/bin/activate && \
		uv pip show grpcio-tools >/dev/null 2>&1 || \
		uv pip install -q grpcio-tools"
	@/bin/bash -c "source $(VENV_DIR)/bin/activate && \
		python -m grpc_tools.protoc \
			-I cpex/framework/external/grpc/proto \
			--python_out=cpex/framework/external/grpc/proto \
			--pyi_out=cpex/framework/external/grpc/proto \
			--grpc_python_out=cpex/framework/external/grpc/proto \
			cpex/framework/external/grpc/proto/plugin_service.proto"
	@echo "🔧  Fixing imports in generated files..."
	@if [ "$$(uname)" = "Darwin" ]; then \
		sed -i '' 's/^import plugin_service_pb2/from cpex.framework.external.grpc.proto import plugin_service_pb2/' \
			cpex/framework/external/grpc/proto/plugin_service_pb2_grpc.py; \
	else \
		sed -i 's/^import plugin_service_pb2/from cpex.framework.external.grpc.proto import plugin_service_pb2/' \
			cpex/framework/external/grpc/proto/plugin_service_pb2_grpc.py; \
	fi
	@echo "🔧  Adding noqa comments to generated files..."
	@if [ "$$(uname)" = "Darwin" ]; then \
		sed -i '' '1s/^/# noqa: D100, D101, D102, D103, D104, D107, D400, D415\n# ruff: noqa\n# type: ignore\n# pylint: skip-file\n# Generated by protoc - do not edit\n/' \
			cpex/framework/external/grpc/proto/plugin_service_pb2.py \
			cpex/framework/external/grpc/proto/plugin_service_pb2_grpc.py \
			cpex/framework/external/grpc/proto/plugin_service_pb2.pyi; \
	else \
		sed -i '1s/^/# noqa: D100, D101, D102, D103, D104, D107, D400, D415\n# ruff: noqa\n# type: ignore\n# pylint: skip-file\n# Generated by protoc - do not edit\n/' \
			cpex/framework/external/grpc/proto/plugin_service_pb2.py \
			cpex/framework/external/grpc/proto/plugin_service_pb2_grpc.py \
			cpexs/framework/external/grpc/proto/plugin_service_pb2.pyi; \
	fi
	@echo "✅  gRPC stubs generated in cpex/framework/external/grpc/proto/"

.PHONY: env-example
env-example:
	@test -d "$(VENV_DIR)" || $(MAKE) --no-print-directory venv
	@pip install settings-doc
	@settings-doc generate --class cpex.framework.settings.PluginsSettings --output-format dotenv > .env.template

# =============================================================================
# Rust workspace (cpex-core, cpex-ffi, cpex-sdk)
# =============================================================================

CARGO ?= cargo
GO    ?= go
GO_DIR = go/cpex

.PHONY: rust-build
rust-build:
	@echo "🦀 Building Rust workspace (debug)..."
	@$(CARGO) build --workspace
	@echo "✅  Rust workspace built"

.PHONY: rust-build-release
rust-build-release:
	@echo "🦀 Building Rust workspace (release)..."
	@$(CARGO) build --release --workspace
	@echo "✅  Rust workspace built (release)"

.PHONY: rust-test
rust-test:
	@echo "🧪 Running Rust workspace tests..."
	@$(CARGO) test --workspace
	@echo "✅  Rust tests passed"

.PHONY: rust-test-ffi
rust-test-ffi:
	@echo "🧪 Running cpex-ffi tests..."
	@$(CARGO) test -p cpex-ffi --lib
	@echo "✅  cpex-ffi tests passed"

.PHONY: rust-fmt
rust-fmt:
	@echo "🦀 Formatting Rust code..."
	@$(CARGO) fmt --all
	@echo "✅  Rust code formatted"

.PHONY: rust-clippy
rust-clippy:
	@echo "🦀 Running clippy..."
	@$(CARGO) clippy --workspace --all-targets -- -D warnings
	@echo "✅  Clippy clean"

# rust-lint is a developer convenience: format the code, then apply
# clippy's auto-fixes. --allow-dirty/--allow-staged let clippy run on
# in-progress edits rather than refusing on a non-clean tree.
.PHONY: rust-lint
rust-lint: rust-lint-fix

.PHONY: rust-lint-fix
rust-lint-fix:
	@echo "🦀 Formatting + auto-fixing Rust..."
	@$(CARGO) fmt --all
	@$(CARGO) clippy --workspace --all-targets --fix --allow-dirty --allow-staged -- -D warnings
	@echo "✅  Rust lint-fix complete"

# rust-lint-check is the CI-safe variant: no writes. Fails if formatting
# drifted (fmt --check) or clippy has any warning.
.PHONY: rust-lint-check
rust-lint-check:
	@echo "🦀 Checking Rust formatting + clippy (read-only)..."
	@$(CARGO) fmt --all -- --check
	@$(CARGO) clippy --workspace --all-targets -- -D warnings
	@echo "✅  Rust lint-check passed"

.PHONY: rust-clean
rust-clean:
	@echo "🧹 Removing Rust target directory..."
	@$(CARGO) clean
	@echo "✅  target/ removed"

# =============================================================================
# Go bindings (go/cpex)
# =============================================================================
#
# go/cpex links against the cpex-ffi cdylib at target/release. Targets
# below that touch Go ensure the release build is current first — Go's
# linker errors on missing libcpex_ffi.dylib are easy to misread.

.PHONY: go-build
go-build: rust-build-release
	@echo "🐹 Building Go cpex package..."
	@cd $(GO_DIR) && $(GO) build ./...
	@echo "✅  Go package built"

.PHONY: go-test
go-test: rust-build-release
	@echo "🧪 Running Go tests..."
	@cd $(GO_DIR) && $(GO) test -count=1 ./...
	@echo "✅  Go tests passed"

.PHONY: go-test-race
go-test-race: rust-build-release
	@echo "🧪 Running Go tests with race detector..."
	@cd $(GO_DIR) && $(GO) test -count=1 -race ./...
	@echo "✅  Go tests passed (with -race)"

.PHONY: go-vet
go-vet: rust-build-release
	@echo "🐹 Running go vet..."
	@cd $(GO_DIR) && $(GO) vet ./...
	@echo "✅  go vet clean"

# go-fmt rewrites .go files in place via gofmt. Read-only counterpart
# is `gofmt -l`, used inside go-lint-check.
.PHONY: go-fmt
go-fmt:
	@echo "🐹 Formatting Go code..."
	@cd $(GO_DIR) && $(GO) fmt ./...
	@echo "✅  Go code formatted"

# go-lint is a developer convenience: format, vet, then run
# golangci-lint with --fix. We require golangci-lint to be installed —
# print an install hint rather than silently skipping it (skipping
# would let style drift land unnoticed).
GOLANGCI_LINT ?= golangci-lint

.PHONY: go-lint
go-lint: go-lint-fix

.PHONY: go-lint-fix
go-lint-fix: rust-build-release
	@command -v $(GOLANGCI_LINT) >/dev/null 2>&1 || { \
		echo "❌ golangci-lint not found. Install:"; \
		echo "    brew install golangci-lint"; \
		echo "    # or: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
		exit 1; \
	}
	@echo "🐹 Formatting + auto-fixing Go..."
	@cd $(GO_DIR) && $(GO) fmt ./...
	@cd $(GO_DIR) && $(GO) vet ./...
	@cd $(GO_DIR) && $(GOLANGCI_LINT) run --fix ./...
	@echo "✅  Go lint-fix complete"

# go-lint-check is the CI-safe variant: read-only. `gofmt -l` lists
# files that would be reformatted and we fail if that list is non-empty.
.PHONY: go-lint-check
go-lint-check: rust-build-release
	@command -v $(GOLANGCI_LINT) >/dev/null 2>&1 || { \
		echo "❌ golangci-lint not found. Install:"; \
		echo "    brew install golangci-lint"; \
		echo "    # or: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
		exit 1; \
	}
	@echo "🐹 Checking Go formatting + vet + golangci-lint (read-only)..."
	@cd $(GO_DIR) && unformatted=$$(gofmt -l .); \
		if [ -n "$$unformatted" ]; then \
			echo "❌ Files need formatting:"; echo "$$unformatted"; \
			exit 1; \
		fi
	@cd $(GO_DIR) && $(GO) vet ./...
	@cd $(GO_DIR) && $(GOLANGCI_LINT) run ./...
	@echo "✅  Go lint-check passed"

# =============================================================================
# Examples
# =============================================================================
#
# Building examples is the cheapest way to catch stale public-API usage:
# cargo test / go test only build code reachable from tests, so an
# example file using a renamed function compiles fine in isolation but
# breaks at example-build time. Wire this into CI.

GO_EXAMPLES_DIR = examples/go-demo

.PHONY: rust-examples-build
rust-examples-build:
	@echo "🦀 Building Rust examples..."
	@$(CARGO) build --examples --workspace
	@echo "✅  Rust examples built"

.PHONY: go-examples-build
go-examples-build: rust-build-release
	@echo "🐹 Building Go examples..."
	@cd $(GO_EXAMPLES_DIR) && $(GO) build ./...
	@echo "✅  Go examples built"

.PHONY: examples-build
examples-build: rust-examples-build go-examples-build
	@echo "✅  All examples built"

# Running examples — useful for manual smoke-testing. Output goes to
# stdout and may be noisy. Each example is self-contained: prints
# scenario output and exits 0 on success.
.PHONY: examples-run
examples-run: examples-build
	@echo "🏃 Running cpex-core plugin_demo..."
	@$(CARGO) run --example plugin_demo -p cpex-core --quiet >/dev/null
	@echo "✅  plugin_demo OK"
	@echo "🏃 Running cpex-core cmf_capabilities_demo..."
	@$(CARGO) run --example cmf_capabilities_demo -p cpex-core --quiet >/dev/null
	@echo "✅  cmf_capabilities_demo OK"
	@echo "🏃 Running go-demo (generic payload)..."
	@cd $(GO_EXAMPLES_DIR) && $(GO) run . >/dev/null
	@echo "✅  go-demo OK"
	@echo "🏃 Running go-demo cmf-demo..."
	@cd $(GO_EXAMPLES_DIR) && $(GO) run ./cmd/cmf-demo >/dev/null
	@echo "✅  cmf-demo OK"
	@echo "✅  All examples ran successfully"

# =============================================================================
# End-to-end
# =============================================================================

# test-all bundles the Rust workspace tests and the Go tests under
# the race detector. Skips the Python pytest suite — use
# `make test rust-test go-test-race` if you want all three.
.PHONY: test-all
test-all: rust-test go-test-race
	@echo "✅  Rust + Go test suites passed"

# ci is the canonical CI gate: read-only lint checks, full test
# suites, and example builds. If this passes locally, the same checks
# will pass in CI.
.PHONY: ci
ci: rust-lint-check test-all examples-build
	@echo "✅  CI gate passed (lint + tests + examples)"

# =============================================================================
# Development shortcuts
# =============================================================================

.PHONY: dev-setup
dev-setup: install-dev
	@echo "✅  Development environment ready!"
	@echo ""
	@echo "Next steps:"
	@echo "  1. Activate venv: source $(VENV_DIR)/bin/activate"
	@echo "  2. Run tests: make test"
	@echo "  3. Run main: make run-main"

.PHONY: quick-test
quick-test:
	@echo "🚀 Quick test (no coverage)..."
	@PYTHONPATH="$(SRC_DIR)" $(VENV_BIN)/pytest $(TEST_DIR) -v --tb=short

.PHONY: watch-test
watch-test:
	@echo "👀 Watching for changes..."
	@while true; do \
		$(MAKE) quick-test; \
		echo ""; \
		echo "Waiting for changes... (Ctrl+C to stop)"; \
		sleep 2; \
	done

# Prevent make from treating additional arguments as targets
%:
	@:
