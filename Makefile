# Makefile for libgeneve-go

# Build parameters
BINARY_NAME=geneve-analyzer
BUILD_DIR=build
CMD_DIR=cmd/geneve-analyzer

# Version and build info
VERSION?=1.0.0
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.GitCommit=$(GIT_COMMIT) -X main.BuildTime=$(BUILD_TIME)"

# Default target
.PHONY: all
all: build analyzer

# Build the project libraries
.PHONY: build
build:
	go build ./...

# Build the command-line analyzer tool
.PHONY: analyzer
analyzer:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./$(CMD_DIR)
	@echo "Built $(BUILD_DIR)/$(BINARY_NAME)"

# Run tests
.PHONY: test
test:
	go test -v ./geneve

# Run tests with coverage
.PHONY: test-coverage
test-coverage:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Run benchmarks
.PHONY: bench
bench:
	go test -bench=. -benchmem ./...

# Run race condition tests
.PHONY: test-race
test-race:
	go test -race ./...

# Install dependencies
.PHONY: deps
deps:
	go mod download
	go mod verify

# Update dependencies
.PHONY: deps-update
deps-update:
	go get -u ./...
	go mod tidy

# Format code
.PHONY: fmt
fmt:
	go fmt ./...

# Vet code
.PHONY: vet
vet:
	go vet ./...

# Lint code (requires golangci-lint)
.PHONY: lint
lint:
	golangci-lint run

# Run all checks
.PHONY: check
check: fmt vet lint test

# Install the analyzer binary to system path
.PHONY: install
install: analyzer
	@echo "Installing $(BINARY_NAME) to /usr/local/bin/..."
	sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	sudo chmod +x /usr/local/bin/$(BINARY_NAME)
	@echo "Installed $(BINARY_NAME)"

# Uninstall the analyzer binary from system path
.PHONY: uninstall
uninstall:
	@echo "Uninstalling $(BINARY_NAME)..."
	sudo rm -f /usr/local/bin/$(BINARY_NAME)
	@echo "Uninstalled $(BINARY_NAME)"

# Clean build artifacts
.PHONY: clean
clean:
	go clean -cache -testcache -modcache
	rm -f coverage.out coverage.html
	rm -rf $(BUILD_DIR)

# Run example programs
.PHONY: example-basic
example-basic:
	go run examples/basic/main.go

.PHONY: example-hexdump
example-hexdump:
	go run examples/hexdump/main.go

# Show sample packet
.PHONY: example-sample
example-sample:
	go run examples/hexdump/main.go "000008001234560048656c6c6f2c2047454e45564521"

# Performance profiling
.PHONY: profile-cpu
profile-cpu:
	go test -cpuprofile=cpu.prof -bench=. ./geneve
	go tool pprof cpu.prof

.PHONY: profile-mem
profile-mem:
	go test -memprofile=mem.prof -bench=. ./geneve
	go tool pprof mem.prof

# Generate documentation
.PHONY: docs
docs:
	godoc -http=:6060

# Help target
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  all              - Build the project and analyzer"
	@echo "  build            - Build the project libraries"
	@echo "  analyzer         - Build the command-line analyzer tool"
	@echo "  install          - Install analyzer to /usr/local/bin"
	@echo "  uninstall        - Uninstall analyzer from system"
	@echo "  test             - Run tests"
	@echo "  test-coverage    - Run tests with coverage report"
	@echo "  bench            - Run benchmarks"
	@echo "  test-race        - Run race condition tests"
	@echo "  deps             - Install dependencies"
	@echo "  deps-update      - Update dependencies"
	@echo "  fmt              - Format code"
	@echo "  vet              - Vet code"
	@echo "  lint             - Lint code (requires golangci-lint)"
	@echo "  check            - Run all checks (fmt, vet, lint, test)"
	@echo "  clean            - Clean build artifacts"
	@echo "  example-basic    - Run basic example"
	@echo "  example-hexdump  - Run hexdump example"
	@echo "  example-sample   - Run sample packet parse"
	@echo "  profile-cpu      - CPU profiling"
	@echo "  profile-mem      - Memory profiling"
	@echo "  docs             - Generate documentation"
	@echo "  help             - Show this help"
	@echo ""
	@echo "Analyzer usage examples:"
	@echo "  $(BUILD_DIR)/$(BINARY_NAME) -i eth0"
	@echo "  $(BUILD_DIR)/$(BINARY_NAME) -f capture.pcap"
	@echo "  $(BUILD_DIR)/$(BINARY_NAME) -f capture.pcap -output json"