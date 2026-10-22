FROM golang:1.26-bookworm AS base

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        openssl \
        libltdl7 \
        libpcsclite1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

ENV LD_LIBRARY_PATH=/src/.local/kalkancrypt/lib/linux \
    KALKANCRYPT_LIBRARY=/src/.local/kalkancrypt/lib/linux/libkalkancryptwr-64.so \
    KALKANCRYPT_SDK_ASSETS=/src/testdata

COPY . .

FROM base AS test

ARG KALKANCRYPT_LIVE_TESTS=0

RUN set -eu; \
    case "$KALKANCRYPT_LIVE_TESTS" in \
        0|1) ;; \
        *) echo 'KALKANCRYPT_LIVE_TESTS must be 0 or 1' >&2; exit 2 ;; \
    esac; \
    if [ "$KALKANCRYPT_LIVE_TESTS" = 1 ]; then \
        for ca_name in root_rsa_test nca_rsa_test; do \
            curl --fail --silent --show-error --connect-timeout 5 --max-time 20 \
                "http://test.pki.gov.kz/cert/${ca_name}.cer" -o "/tmp/${ca_name}.cer"; \
            openssl x509 -inform DER -in "/tmp/${ca_name}.cer" \
                -out "/usr/local/share/ca-certificates/kalkan-${ca_name}.crt"; \
        done; \
        openssl verify -CAfile /usr/local/share/ca-certificates/kalkan-root_rsa_test.crt \
            /usr/local/share/ca-certificates/kalkan-nca_rsa_test.crt; \
        update-ca-certificates; \
    fi; \
    KALKANCRYPT_LIVE_TESTS="$KALKANCRYPT_LIVE_TESTS" \
        go test -race -shuffle=on -count=1 -timeout=5m -v ./...
