FROM golang:1.26-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libltdl7 \
        libpcsclite1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

ENV LD_LIBRARY_PATH=/src/.local/kalkancrypt/lib/linux \
    KALKANCRYPT_LIBRARY=/src/.local/kalkancrypt/lib/linux/libkalkancryptwr-64.so \
    KALKANCRYPT_SDK_ASSETS=/src/testdata

COPY . .

RUN go test ./...
