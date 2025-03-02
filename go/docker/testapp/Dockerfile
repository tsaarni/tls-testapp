FROM golang:1.23-alpine

WORKDIR /app

COPY . .
RUN go build ./cmd/tls && \
    go build ./cmd/http
