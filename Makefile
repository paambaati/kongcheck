.PHONY: all build test test-race lint fmt clean

VERSION ?= $(shell git describe --tags --always 2>/dev/null | sed 's/^v//')
ifeq ($(VERSION),)
VERSION := 1.3.0
endif

LDFLAGS := -s -w -X github.com/paambaati/kongcheck/internal/version.Version=$(VERSION)

all: fmt lint test build

build:
	@mkdir -p dist
	go build -trimpath -ldflags="$(LDFLAGS)" -o dist/kongcheck ./cmd/kongcheck

test:
	go test ./...

test-race:
	go test -race -count=1 ./...

lint:
	go vet ./...
	@if [ -x "$$(command -v golangci-lint 2>/dev/null)" ] || [ -x "$(shell go env GOPATH)/bin/golangci-lint" ]; then \
		LINT_BIN=$$(command -v golangci-lint 2>/dev/null || echo "$(shell go env GOPATH)/bin/golangci-lint"); \
		OUT=$$($$LINT_BIN run ./... 2>&1); \
		if [ $$? -eq 0 ]; then \
			[ -n "$$OUT" ] && echo "$$OUT"; \
		elif echo "$$OUT" | grep -q "export data version"; then \
			if [ -x "$(shell go env GOPATH)/bin/staticcheck" ]; then \
				$(shell go env GOPATH)/bin/staticcheck -checks="all,-ST1005" ./...; \
			fi; \
		else \
			echo "$$OUT"; exit 1; \
		fi; \
	elif [ -x "$(shell go env GOPATH)/bin/staticcheck" ]; then \
		$(shell go env GOPATH)/bin/staticcheck -checks="all,-ST1005" ./...; \
	fi

fmt:
	gofmt -s -w cmd internal
	@if command -v goimports >/dev/null 2>&1; then \
		goimports -w cmd internal; \
	elif [ -x "$(shell go env GOPATH)/bin/goimports" ]; then \
		$(shell go env GOPATH)/bin/goimports -w cmd internal; \
	fi

clean:
	rm -rf dist/ bin/ coverage.out
