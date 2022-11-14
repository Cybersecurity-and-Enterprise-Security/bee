# Based on https://github.com/openHPI/poseidon/blob/main/Makefile

PROJECT_NAME := "bee"
PKG := "gitlab.cyber-threat-intelligence.com/software/alvarium/$(PROJECT_NAME)/cmd/$(PROJECT_NAME)"
UNIT_TESTS = $(shell go list ./... | grep -v /e2e)

DOCKER_TAG := "$(PROJECT_NAME):latest"
DOCKER_OPTS := -v $(shell pwd)/configuration.yaml:/configuration.yaml

default: help

.PHONY: all
all: build

.PHONY: deps
deps: ## Get the dependencies
	@go get -v -d ./...

.PHONY: upgrade-deps
upgrade-deps: ## Upgrade the dependencies
	@go get -u -v -d ./...

.PHONY: tidy-deps
tidy-deps: ## Remove unused dependencies
	@go mod tidy

.PHONY: build
build: deps ## Build the binary
	@go build -o $(PROJECT_NAME) -v $(PKG)

.PHONY: clean
clean: ## Remove previous build
	@rm -f $(PROJECT_NAME)

.PHONY: docker
docker:
	@CGO_ENABLED=0 make build
	@docker build -t $(DOCKER_TAG) -f build/Dockerfile .

.PHONY: golangci-lint
golangci-lint: ## Lint the source code using golangci-lint
	@golangci-lint run ./... --timeout=3m

.PHONY: lint
lint: golangci-lint ## Lint the source code using all linters

.PHONY: test
test: deps ## Run unit tests
	@go test -count=1 -short $(UNIT_TESTS)

.PHONY: race
race: deps ## Run data race detector
	@go test -race -count=1 -short $(UNIT_TESTS)

.PHONY: coverage
coverage: deps ## Generate code coverage report
	@go test $(UNIT_TESTS) -v -coverprofile coverage.cov
	@go tool cover -func=coverage.cov

.PHONY: coverhtml
coverhtml: coverage ## Generate HTML coverage report
	@go tool cover -html=coverage.cov -o coverage_unit.html

.PHONY: help
HELP_FORMAT="    \033[36m%-25s\033[0m %s\n"
help: ## Display this help screen
	@echo "Valid targets:"
	@grep -E '^[^ ]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		sort | \
		awk 'BEGIN {FS = ":.*?## "}; \
			{printf $(HELP_FORMAT), $$1, $$2}'
