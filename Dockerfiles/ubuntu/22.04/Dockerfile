FROM golang:1.26.11@sha256:7af425da11f4fc1a9308eb704369e3f6d1c44e35bac0f874a59ade3f20fdc07e AS builder

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

FROM ubuntu:22.04@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11

RUN apt-get update -o Acquire::Retries=3 && apt-get install -y -o Acquire::Retries=3 --no-install-recommends \
    ca-certificates

WORKDIR /usr/local/alpamon

COPY --from=builder /build/alpamon ./alpamon

COPY Dockerfiles/ubuntu/22.04/entrypoint.sh /usr/local/alpamon/entrypoint.sh

RUN chmod +x /usr/local/alpamon/entrypoint.sh

ENTRYPOINT ["/usr/local/alpamon/entrypoint.sh"]