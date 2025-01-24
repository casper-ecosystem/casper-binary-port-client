# Makefile for casper-binary-port-client

# Specify the cargo target for wasm32
WASM_TARGET = wasm32-unknown-unknown

# Default target (build the project)
all: build

# Build the project
build:
	cargo build

build-for-release:
	cargo build --release

# Run the tests
test:
	cargo test --all-targets

# Run clippy (linter) on all targets
lint: lint-wasm
	cargo clippy --all-targets -- -D warnings

# Run clippy on wasm32-unknown-unknown target
lint-wasm:
	cd binary-port-access && cargo clippy --target $(WASM_TARGET) --all-targets -- -D warnings

# Format the codebase using rustfmt and check for correct formatting
fmt-check:
	cargo fmt --all -- --check

# Check for outdated dependencies
outdated:
	cargo outdated || cargo install cargo-outdated

# Run a full CI-style check (build, fmt, clippy, test)
ci-check: fmt-check lint lint-wasm test

# Clean build artifacts
clean:
	cargo clean

audit:
	cargo audit
