BIN     := bin/alert-linter
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/mohammed-saaduddin-ansari/alert-linter/internal/cli.Version=$(VERSION)

.PHONY: all build test lint fmt golden demo sarif clean

all: lint test build

build: ## Build the binary into bin/
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/alert-linter

test: ## Unit and golden tests (offline, no credentials)
	go test -race ./...

lint: ## gofmt check, go vet and golangci-lint
	@test -z "$$(gofmt -l .)" || (gofmt -l . && echo "run make fmt" && exit 1)
	go vet ./...
	golangci-lint run

fmt:
	gofmt -w .

golden: ## Regenerate golden files after an intended output change
	go test ./internal/cli -update

demo: build ## Lint the bad and good sample files
	-$(BIN) examples/bad-rules.yaml
	$(BIN) examples/good-rules.yaml

sarif: build ## Write a SARIF report for the bad sample to bad-rules.sarif
	-$(BIN) --format sarif --output bad-rules.sarif examples/bad-rules.yaml

clean:
	rm -rf bin *.sarif coverage.out
