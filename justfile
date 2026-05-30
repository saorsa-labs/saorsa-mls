# saorsa-mls justfile
# Zero-tolerance: zero warnings, zero clippy violations, all tests pass.

# Show available recipes
default:
    @just --list

# Full validation: format check, lint, build, test, docs
check: fmt-check lint build test doc

# Quick validation: format check, lint, test
quick-check: fmt-check lint test

# Format code
fmt:
    cargo fmt --all

# Check formatting without modifying
fmt-check:
    cargo fmt --all -- --check

# Clippy with zero warnings across all features and targets
lint:
    cargo clippy --all-features --all-targets -- -D warnings

# Debug build (all features)
build:
    cargo build --all-features

# Release build
build-release:
    cargo build --release --all-features

# Run tests (fast, parallel)
test:
    cargo nextest run --all-features

# Run tests with output
test-verbose:
    cargo nextest run --all-features --no-capture

# Build documentation (deny warnings)
doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps

# Clean build artifacts
clean:
    cargo clean
