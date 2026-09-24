# himalaya-sherpa developer tasks. Run `make` (or `make help`) to list them.
#
# CI runs `make ci`, so what passes here passes there.

CARGO ?= cargo
MSRV := $(shell sed -n 's/^rust-version = "\(.*\)"/\1/p' Cargo.toml)

# himalaya release used by the end-to-end tests. The upstream release publishes no
# checksum, so the tarball is pinned here; update both together.
HIMALAYA_VERSION ?= 2.1.0
HIMALAYA_SHA256 ?= 683a2ab8e1534f01e6bda3a69e204d564c31fbfbe20511fc7bc60b67f2e85884
HIMALAYA_DIR := .cache/himalaya-$(HIMALAYA_VERSION)
HIMALAYA_URL := https://github.com/pimalaya/himalaya/releases/download/v$(HIMALAYA_VERSION)/himalaya.x86_64-linux.tgz

HIMALAYA_PINNED := $(abspath $(HIMALAYA_DIR)/himalaya)

# The end-to-end tests use $HIMALAYA_BIN if set, else the pinned release if it was
# downloaded (`make himalaya`), else a himalaya on PATH, and are skipped if none.
USE_PINNED := if [ -z "$$HIMALAYA_BIN" ] && [ -x $(HIMALAYA_PINNED) ]; then export HIMALAYA_BIN=$(HIMALAYA_PINNED); fi;

.DEFAULT_GOAL := help
.PHONY: help build release static image test test-unit test-e2e msrv fmt fmt-check lint doc deny \
        policy-check check ci himalaya clean

help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "; printf "Usage: make <target>\n\n"} \
	     /^[a-zA-Z0-9_-]+:.*## / {printf "  %-13s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@printf "\nVariables: HIMALAYA_BIN=<path> to test against another himalaya binary.\n"

build: ## Build debug binaries (sherpa client, sherpa-gate, sherpa-admin)
	$(CARGO) build --locked

release: ## Build release binaries in target/release
	$(CARGO) build --release --locked

STATIC_TARGET := x86_64-unknown-linux-musl
CONTAINER ?= $(shell command -v podman || command -v docker)

static: ## Build static binaries for containers (needs the musl target: rustup target add $(STATIC_TARGET))
	$(CARGO) build --release --locked --target $(STATIC_TARGET)
	@ls -l target/$(STATIC_TARGET)/release/sherpa target/$(STATIC_TARGET)/release/sherpa-gate

image: static himalaya ## Build the gate container image (himalaya-sherpa-gate)
	$(CONTAINER) build -f contrib/Containerfile -t himalaya-sherpa-gate .

test: ## Run all tests (end-to-end tests need himalaya: see `make himalaya`)
	@$(USE_PINNED) set -x; $(CARGO) test --locked

test-unit: ## Run unit tests only
	$(CARGO) test --locked --lib --bins

test-e2e: himalaya ## Run end-to-end tests against the pinned himalaya release
	HIMALAYA_BIN=$(HIMALAYA_PINNED) SHERPA_REQUIRE_HIMALAYA=1 $(CARGO) test --locked --test gate

msrv: ## Run the tests with the minimum supported Rust version (needs rustup)
	@$(USE_PINNED) set -x; $(CARGO) +$(MSRV) test --locked

fmt: ## Format the code
	$(CARGO) fmt --all

fmt-check: ## Check formatting
	$(CARGO) fmt --all --check

lint: ## Run clippy, warnings as errors
	$(CARGO) clippy --all-targets --locked -- -D warnings

doc: ## Build the API docs, warnings as errors
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc --no-deps --locked

deny: ## Check dependencies: advisories, licenses, sources (needs cargo-deny)
	$(CARGO) deny check

policy-check: build ## Check the shipped policy against its examples
	target/debug/sherpa-admin policy check etc/sherpa.toml

check: fmt-check lint doc test ## Everything that needs no extra tools (run before pushing)

ci: fmt-check lint doc test-e2e test deny ## What CI runs

himalaya: $(HIMALAYA_DIR)/himalaya ## Download the pinned himalaya release for the end-to-end tests

$(HIMALAYA_DIR)/himalaya:
	mkdir -p $(HIMALAYA_DIR)
	curl -sSfL -o $(HIMALAYA_DIR)/himalaya.tgz $(HIMALAYA_URL)
	echo "$(HIMALAYA_SHA256)  $(HIMALAYA_DIR)/himalaya.tgz" | sha256sum -c -
	tar -xzf $(HIMALAYA_DIR)/himalaya.tgz -C $(HIMALAYA_DIR) himalaya
	rm $(HIMALAYA_DIR)/himalaya.tgz
	$@ --version

clean: ## Remove build output and downloads
	$(CARGO) clean
	rm -rf .cache
