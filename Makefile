KALKANCRYPT_LIBRARY ?=
KALKANCRYPT_SDK_ASSETS ?= $(CURDIR)/testdata
KALKANCRYPT_LIVE_TESTS ?= 0

# Together with linux/amd64+cgo, these cover every current go:build branch.
LINT_PLATFORMS := linux/amd64 windows/amd64 darwin/arm64 freebsd/amd64

.PHONY: fmt vet test test-race test-native docker-test docker-lint docker-lint-linux-cgo lint lint-linux-cgo check

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
	docker build --platform linux/amd64 --progress=plain --no-cache-filter test \
		--build-arg KALKANCRYPT_LIVE_TESTS="$(KALKANCRYPT_LIVE_TESTS)" .

docker-lint:
	docker run --rm --platform linux/amd64 \
		-v "$(CURDIR):/src:ro" \
		-w /src \
		golangci/golangci-lint:v2.15.0 \
		make lint

lint:
	golangci-lint config verify --config .golangci.yml
	@set -eu; \
	for platform in $(LINT_PLATFORMS); do \
		echo "Lint $$platform (CGO_ENABLED=0)"; \
		GOOS=$${platform%/*} GOARCH=$${platform#*/} CGO_ENABLED=0 \
			golangci-lint run -v --config .golangci.yml ./...; \
	done
	@if [ "$$(go env GOHOSTOS)/$$(go env GOHOSTARCH)" = "linux/amd64" ]; then \
		$(MAKE) lint-linux-cgo; \
	else \
		$(MAKE) docker-lint-linux-cgo; \
	fi

lint-linux-cgo:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=1 golangci-lint run -v --config .golangci.yml ./...

docker-lint-linux-cgo:
	docker run --rm --platform linux/amd64 \
		-v "$(CURDIR):/src:ro" \
		-w /src \
		golangci/golangci-lint:v2.15.0 \
		make lint-linux-cgo

check: fmt vet test test-race
	@if command -v golangci-lint >/dev/null 2>&1; then \
		$(MAKE) lint; \
	else \
		echo "golangci-lint not found; skipping lint"; \
	fi
