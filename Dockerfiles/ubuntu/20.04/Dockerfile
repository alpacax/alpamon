FROM golang:1.26.9@sha256:d7722066f0b60ceccb6c0643cbed1f5f9e15506ac237146c95333504d7805d89 AS builder

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

FROM ubuntu:20.04@sha256:8feb4d8ca5354def3d8fce243717141ce31e2c428701f6682bd2fafe15388214

RUN apt-get update -o Acquire::Retries=3 && apt-get install -y -o Acquire::Retries=3 --no-install-recommends ca-certificates

WORKDIR /usr/local/alpamon

COPY --from=builder /build/alpamon ./alpamon

COPY Dockerfiles/ubuntu/20.04/entrypoint.sh /usr/local/alpamon/entrypoint.sh

RUN chmod +x /usr/local/alpamon/entrypoint.sh

ENTRYPOINT ["/usr/local/alpamon/entrypoint.sh"]