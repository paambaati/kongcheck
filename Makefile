.PHONY: all build test test-race lint lint-tools fmt clean

VERSION ?= $(shell git describe --tags --always 2>/dev/null | sed 's/^v//')
ifeq ($(VERSION),)
VERSION := 1.3.0
endif

# Pin the exact golangci-lint version used by CI so every machine lints the
# same way. Bump this together with GOLANGCI_LINT_VERSION in ci.yml.
GOLANGCI_LINT_VERSION := v2.13.0
GOLANGCI_LINT_PKG := github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
BIN_DIR := $(CURDIR)/bin
GOLANGCI_LINT := $(BIN_DIR)/golangci-lint-$(GOLANGCI_LINT_VERSION)

LDFLAGS := -s -w -X github.com/paambaati/kongcheck/internal/version.Version=$(VERSION)

all: fmt lint test build

build:
	@mkdir -p dist
	go build -trimpath -ldflags="$(LDFLAGS)" -o dist/kongcheck ./cmd/kongcheck

test:
	go test ./...

test-race:
	go test -race -count=1 ./...

lint: $(GOLANGCI_LINT)
	$(GOLANGCI_LINT) run ./...

$(GOLANGCI_LINT):
	@mkdir -p $(BIN_DIR)
	GOBIN=$(BIN_DIR) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	@# go install writes plain "golangci-lint"; rename so version bumps re-install.
	@if [ -f $(BIN_DIR)/golangci-lint ]; then mv -f $(BIN_DIR)/golangci-lint $(GOLANGCI_LINT); fi
	@# Tolerate a leftover path if install already targeted the versioned name.
	@test -x $(GOLANGCI_LINT)

lint-tools:
	@command -v goimports >/dev/null 2>&1 || go install golang.org/x/tools/cmd/goimports@latest

fmt: lint-tools
	gofmt -s -w cmd internal
	goimports -w cmd internal

clean:
	rm -rf dist/ bin/ coverage.out
