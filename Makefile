# Based on https://github.com/openHPI/poseidon/blob/main/Makefile

PROJECT_NAME := "bee"
PKG := "github.com/Cybersecurity-and-Enterprise-Security/$(PROJECT_NAME)/cmd/$(PROJECT_NAME)"
UNIT_TESTS = $(shell go list ./... | grep -v /e2e)

MIN_GO_MAJOR_VERSION := 1
MIN_GO_MINOR_VERSION := 23

default: help

.PHONY: all
all: build

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

.PHONY: libpcap
libpcap:  ## Build libpcap
	cd ${PCAP_SRC} && \
	if [ "$(ARCH)" = "arm" ]; then 
		CC=arm-linux-gnueabi-gcc ./configure --host=arm-linux --with-pcap=linux ; \
	elif [ "$(ARCH)" = "aarch64" ]; then \
		CC=aarch64-linux-gnu-gcc ./configure --host=aarch64-linux --with-pcap=linux ; \
	elif [ "$(ARCH)" = "amd64" ]; then \
		./configure --host=amd64-linux --with-pcap=linux ; \
	else \
		echo "Unsupported architecture: $(ARCH)" ; \
		exit 1 ; \
	fi; \
	make && make install

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
lint: generate golangci-lint ## Lint the source code using all linters

.PHONY: test
test: deps generate ## Run unit tests
	@go test -count=1 -short $(UNIT_TESTS)

.PHONY: race
race: deps generate ## Run data race detector
	@go test -race -count=1 -short $(UNIT_TESTS)

.PHONY: coverage
coverage: deps generate ## Generate code coverage report
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
