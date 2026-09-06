FROM golang:1.25 AS builder

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

FROM debian:11

# Debian 11 (bullseye) left LTS on 2026-08-31 and its security pool is being retired from the CDN while the index still lists the files, so drop the source before updating — this stage only needs ca-certificates from main.
RUN (sed -i '/bullseye-security/d' /etc/apt/sources.list 2>/dev/null || true) && \
    (sed -i '/bullseye-security/d' /etc/apt/sources.list.d/*.sources 2>/dev/null || true) && \
    apt-get update -o Acquire::Retries=3 && apt-get install -y -o Acquire::Retries=3 --no-install-recommends ca-certificates

WORKDIR /usr/local/alpamon

COPY --from=builder /build/alpamon ./alpamon

COPY Dockerfiles/debian/11/entrypoint.sh /usr/local/alpamon/entrypoint.sh

RUN chmod +x /usr/local/alpamon/entrypoint.sh

ENTRYPOINT ["/usr/local/alpamon/entrypoint.sh"]