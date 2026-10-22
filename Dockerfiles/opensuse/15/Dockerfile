FROM golang:1.26.10@sha256:672c944cfd07599b5f1bb179869270cdc94c6254e41db4d431259693cb286b82 AS builder

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

FROM opensuse/leap:15@sha256:bd9b5fdf67c88509f01c7b108007f77580d750fb2c8b46aead15ccfafbb13b4e

WORKDIR /usr/local/alpamon

COPY --from=builder /build/alpamon ./alpamon

COPY Dockerfiles/opensuse/15/entrypoint.sh /usr/local/alpamon/entrypoint.sh

RUN chmod +x /usr/local/alpamon/entrypoint.sh

ENTRYPOINT ["/usr/local/alpamon/entrypoint.sh"]
