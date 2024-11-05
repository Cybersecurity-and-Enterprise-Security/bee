# Based on https://github.com/openHPI/poseidon/blob/main/Makefile

PROJECT_NAME := "bee"
PKG := "github.com/Cybersecurity-and-Enterprise-Security/$(PROJECT_NAME)/cmd/$(PROJECT_NAME)"
DOCKER_TAG := $(PROJECT_NAME)

MIN_GO_MAJOR_VERSION := 1
MIN_GO_MINOR_VERSION := 23

default: help

.PHONY: all
all: build

.PHONY: check-go-version
check-go-version:
	@GO_MAJOR_VERSION=$$(go version | awk '{print substr($$3, 3)}' | cut -d. -f1); \
	GO_MINOR_VERSION=$$(go version | awk '{print substr($$3, 3)}' | cut -d. -f2); \
	if [ $$GO_MAJOR_VERSION -gt $(MIN_GO_MAJOR_VERSION) ]; then \
		exit 0 ;\
	elif [ $$GO_MAJOR_VERSION -lt $(MIN_GO_MAJOR_VERSION) ] || [ $$GO_MINOR_VERSION -lt $(MIN_GO_MINOR_VERSION) ] ; then \
		echo "ERROR: Go version ${MIN_GO_MAJOR_VERSION}.${MIN_GO_MINOR_VERSION} or higher is required, but found $$(go version)";\
		exit 1; \
	fi

.PHONY: deps
deps: check-go-version ## Get the dependencies
	@go get -v ./...

.PHONY: upgrade-deps
upgrade-deps: check-go-version ## Upgrade the dependencies
	@go get -u -v ./...

.PHONY: tidy-deps
tidy-deps: check-go-version ## Remove unused dependencies
	@go mod tidy

.PHONY: generate-deps
generate-deps: check-go-version
	go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@latest
	@if ! which oapi-codegen > /dev/null 2>&1; then \
		echo "ERROR: Installed oapi-codegen but it is not in your PATH."; \
		echo "       Make sure that your Go bin directory is part of your PATH, e.g. using \`export PATH=\$$PATH:~/go/bin\` and then run the command again."; \
		exit 1; \
	fi

.PHONY: generate
generate: generate-deps ## Generate Go code
	go generate ./...

.PHONY: build
build: deps generate ## Build the binary
	@if [ "$(TARGETARCH)" = "arm" ] && [ "$(TARGETVARIANT)" = "v7" ]; then \
		GOOS=linux GOARCH=arm CC=arm-linux-gnueabihf-gcc CGO_ENABLED=1 CGO_LDFLAGS="-L/usr/lib/arm-linux-gnueabihf/" go build -o $(PROJECT_NAME) -v $(PKG) ; \
	elif [ "$(TARGETARCH)" = "arm" ] && [ "$(TARGETVARIANT)" = "v6" ]; then \
		GOOS=linux GOARCH=arm CC=arm-linux-gnueabi-gcc CGO_ENABLED=1 CGO_LDFLAGS="-L/usr/lib/arm-linux-gnueabi/" go build -o $(PROJECT_NAME) -v $(PKG) ; \
	elif [ "$(TARGETARCH)" = "arm64" ]; then \
		GOOS=linux GOARCH=arm64 CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 CGO_LDFLAGS="-L/usr/lib/aarch64-linux-gnu/" go build -o $(PROJECT_NAME) -v $(PKG) ; \
	else \
		go build -o $(PROJECT_NAME) -v $(PKG); \
	fi;

.PHONY: clean
clean: ## Remove previous build and generated artifacts
	@rm -f $(PROJECT_NAME)
	@rm -f pkg/api/beekeeper.gen.go

.PHONY: docker
docker:
	@docker build -t $(DOCKER_TAG) -f build/Dockerfile .

.PHONY: check-golangci-lint-binary
check-golangci-lint-binary:
	@if ! which golangci-lint > /dev/null 2>&1; then \
		echo "ERROR: golangci-lint is not in your PATH."; \
		echo "       See https://golangci-lint.run/welcome/install/ on how to install it and then run the command again."; \
		exit 1; \
	fi

.PHONY: lint
lint: generate check-golangci-lint-binary ## Lint the source code
	@golangci-lint run ./... --timeout=3m

.PHONY: help
HELP_FORMAT := "    \033[36m%-25s\033[0m %s\n"
help: ## Display this help screen
	@echo "Valid targets:"
	@grep -E '^[^ ]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		sort | \
		awk 'BEGIN {FS = ":.*?## "}; \
			{printf $(HELP_FORMAT), $$1, $$2}'
