FROM golang:1.23 AS builder

# Automatically set GOARCH to the build-time architecture
ARG TARGETARCH
ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=${TARGETARCH:-amd64}

WORKDIR /build

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go build -o alpamon ./cmd/alpamon/main.go

FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    systemd \
    ca-certificates \
    sudo \
    vim \
    build-essential \
    libpam0g-dev \
    libjansson-dev

WORKDIR /usr/local/alpamon

COPY --from=builder /build/alpamon ./alpamon

COPY Dockerfiles/ubuntu/22.04/entrypoint.sh /usr/local/alpamon/entrypoint.sh

RUN chmod +x /usr/local/alpamon/entrypoint.sh

ENTRYPOINT ["/usr/local/alpamon/entrypoint.sh"]