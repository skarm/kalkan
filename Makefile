KALKANCRYPT_LIBRARY ?=
KALKANCRYPT_SDK_ASSETS ?= $(CURDIR)/testdata
KALKAN_DOCKER_PLATFORM ?= linux/amd64
KALKAN_DOCKER_TAG ?= kalkan-test

.PHONY: fmt vet test test-race test-native docker-test lint check

fmt:
	go fmt ./...

test:
	go test ./...

vet:
	go vet ./...

test-race:
	go test -race ./...

test-native:
	@if [ -z "$(KALKANCRYPT_LIBRARY)" ]; then \
		echo "KALKANCRYPT_LIBRARY is required for make test-native"; \
		exit 2; \
	fi
	KALKANCRYPT_LIBRARY="$(KALKANCRYPT_LIBRARY)" \
	KALKANCRYPT_SDK_ASSETS="$(KALKANCRYPT_SDK_ASSETS)" \
	go test ./...

docker-test:
	docker build --build-arg KALKAN_DOCKER_PLATFORM="$(KALKAN_DOCKER_PLATFORM)" --target test -t "$(KALKAN_DOCKER_TAG)" .

lint:
	golangci-lint run -v --config .golangci.yml ./...

check: fmt vet test test-race
	@if command -v golangci-lint >/dev/null 2>&1; then \
		$(MAKE) lint; \
	else \
		echo "golangci-lint not found; skipping lint"; \
	fi
