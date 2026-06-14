# syntax=docker/dockerfile:1.6

# ───── Stage 1: build ───────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

WORKDIR /src

# Resolve dependencies first — better Docker layer caching when only code changes.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# Copy source.
COPY cmd ./cmd
COPY internal ./internal
COPY docs ./docs
COPY migrations ./migrations

# Build a static, stripped binary.
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=linux go build \
        -trimpath \
        -ldflags="-s -w" \
        -o /out/server ./cmd/server

# ───── Stage 2: runtime ─────────────────────────────────────────────────
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S app && adduser -S app -G app

WORKDIR /app

COPY --from=builder /out/server ./server
COPY --from=builder /src/migrations ./migrations

USER app

EXPOSE 8080

CMD ["./server"]
