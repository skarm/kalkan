KALKANCRYPT_LIBRARY ?=
KALKANCRYPT_SDK_ASSETS ?= $(CURDIR)/testdata
JAVA_FORMAT ?= google-java-format

.PHONY: fmt fmt-java vet test test-race test-native docker-test docker-lint lint check

fmt:
	go fmt ./...

fmt-java:
	$(JAVA_FORMAT) --aosp --replace \
		internal/javakalkan/worker/src/Bootstrap.java \
		internal/javakalkan/worker/src/kalkan/worker/*.java \
		internal/javakalkan/testdata/*.java

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
	docker build --platform linux/amd64 .

docker-lint:
	docker run --rm \
		-v "$(CURDIR):/src:ro" \
		-w /src \
		golangci/golangci-lint:v2.13.2 \
		golangci-lint run -v --config .golangci.yml ./...

lint:
	golangci-lint run -v --config .golangci.yml ./...

check: fmt vet test test-race
	@if command -v golangci-lint >/dev/null 2>&1; then \
		$(MAKE) lint; \
	else \
		echo "golangci-lint not found; skipping lint"; \
	fi
