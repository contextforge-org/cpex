# =====================================================================
# sampleWasmPlugin — Build / Test / Publish
# =====================================================================
# Targets:
#   build         compile the .wasm Component Model artifact
#   manifest-sha  recompute the sha256 in plugin-manifest.yaml
#   sign          cosign-sign the artifact (optional, requires cosign)
#   test          run host-side integration tests
#   clean         remove build/ and target/
#   install-deps  fetch the toolchain (cargo-component, wasm-tools)
# =====================================================================

PLUGIN_SLUG := samplewasmplugin
WASM_TARGET := wasm32-wasip2
BUILD_DIR   := ./build
ARTIFACT    := $(BUILD_DIR)/$(PLUGIN_SLUG).wasm
MANIFEST    := ./plugin-manifest.yaml

.PHONY: build manifest-sha sign test clean install-deps verify all

all: build manifest-sha

# ---------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------
# Plain `cargo build` against wasm32-wasip2 produces a Component Model
# artifact directly — wit-bindgen emits the canonical-ABI exports from
# src/lib.rs and the wasip2 target encodes the result as a component.
# No `cargo component` and no `wasm-tools component new` wrapping needed.
build:
	@mkdir -p $(BUILD_DIR)
	cargo build --release --target $(WASM_TARGET)
	cp target/$(WASM_TARGET)/release/$(PLUGIN_SLUG).wasm $(ARTIFACT)
	@echo "Built $(ARTIFACT) ($$(wc -c < $(ARTIFACT)) bytes)"

# ---------------------------------------------------------------------
# Manifest SHA update
# ---------------------------------------------------------------------
# The host refuses to load if the on-disk wasm doesn't match the
# manifest's sha256. After every build, regenerate it.
manifest-sha: $(ARTIFACT)
	@SHA=$$(shasum -a 256 $(ARTIFACT) | awk '{print $$1}'); \
	  echo "Updating $(MANIFEST) sha256: $$SHA"; \
	  if [ "$$(uname)" = "Darwin" ]; then \
	    sed -i '' "s/^  sha256: \".*\"/  sha256: \"$$SHA\"/" $(MANIFEST); \
	  else \
	    sed -i "s/^  sha256: \".*\"/  sha256: \"$$SHA\"/" $(MANIFEST); \
	  fi

# ---------------------------------------------------------------------
# Optional signing
# ---------------------------------------------------------------------
sign: $(ARTIFACT)
	@command -v cosign >/dev/null || { echo "cosign not installed"; exit 1; }
	cosign sign-blob --yes --output-signature $(ARTIFACT).sig $(ARTIFACT)

# ---------------------------------------------------------------------
# Verify the Component Model contract is satisfied
# ---------------------------------------------------------------------
verify: $(ARTIFACT)
	@command -v wasm-tools >/dev/null || { echo "wasm-tools not installed"; exit 1; }
	wasm-tools component wit $(ARTIFACT) | head -40
	@echo "OK: $(ARTIFACT) is a valid component"

# ---------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------
# Runs the Python-side test harness that loads the artifact through
# cpex's WasmPlugin and exercises a real hook invocation.
test: build manifest-sha
	cd tests && python -m pytest -v test_plugin.py

# ---------------------------------------------------------------------
# Clean
# ---------------------------------------------------------------------
clean:
	rm -rf $(BUILD_DIR) target/

# ---------------------------------------------------------------------
# One-shot toolchain install
# ---------------------------------------------------------------------
install-deps:
	rustup target add wasm32-wasip2
	cargo install --locked wasm-tools
	pip install 'cpex' 'wasmtime>=20.0' pytest
