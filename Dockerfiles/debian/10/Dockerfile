FROM golang:1.26.11@sha256:7af425da11f4fc1a9308eb704369e3f6d1c44e35bac0f874a59ade3f20fdc07e AS builder

# Set golang env
ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

WORKDIR /build

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go build -o alpamon ./cmd/alpamon/main.go

FROM debian:10@sha256:58ce6f1271ae1c8a2006ff7d3e54e9874d839f573d8009c20154ad0f2fb0a225

# Buster is EOL; its repositories now live only on archive.debian.org
RUN printf '%s\n' \
      'deb http://archive.debian.org/debian buster main' \
      'deb http://archive.debian.org/debian-security buster/updates main' \
    > /etc/apt/sources.list

RUN apt-get update -o Acquire::Retries=3 && apt-get install -y -o Acquire::Retries=3 --no-install-recommends ca-certificates

WORKDIR /usr/local/alpamon

COPY --from=builder /build/alpamon ./alpamon

COPY Dockerfiles/debian/10/entrypoint.sh /usr/local/alpamon/entrypoint.sh

RUN chmod +x /usr/local/alpamon/entrypoint.sh

ENTRYPOINT ["/usr/local/alpamon/entrypoint.sh"]