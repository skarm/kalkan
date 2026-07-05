ARG KALKAN_DOCKER_PLATFORM=linux/amd64
FROM --platform=${KALKAN_DOCKER_PLATFORM} golang:1.26-bookworm AS test

ENV CGO_ENABLED=1
ENV LD_LIBRARY_PATH=/usr/local/lib

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libltdl7 \
        libpcsclite1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY go.mod ./
RUN go mod download

COPY .local/kalkancrypt/lib/linux/ /usr/local/lib/
RUN ldconfig

ENV KALKANCRYPT_LIBRARY=/usr/local/lib/libkalkancryptwr-64.so
ENV KALKANCRYPT_SDK_ASSETS=/src/testdata

COPY . .

RUN go test ./...
