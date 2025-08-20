FROM golang:1.23 AS builder

ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

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

RUN curl -sSf https://atlasgo.sh | sh

WORKDIR /usr/local/alpamon

COPY --from=builder /build/alpamon ./alpamon

RUN useradd -m -s /bin/bash user && echo "user:123" | chpasswd
RUN usermod -aG sudo user

COPY Dockerfiles/ubuntu/22.04/entrypoint.sh /usr/local/alpamon/entrypoint.sh

RUN chmod +x /usr/local/alpamon/entrypoint.sh

ENTRYPOINT ["/usr/local/alpamon/entrypoint.sh"]