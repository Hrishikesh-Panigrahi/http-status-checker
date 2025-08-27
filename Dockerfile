# Multi-stage build for production-ready container
FROM golang:1.22.2-alpine AS builder

# Install git and ca-certificates (for HTTPS requests)
RUN apk update && apk add --no-cache git ca-certificates tzdata

# Create appuser for security
RUN adduser -D -g '' appuser

# Set build directory
WORKDIR /build

# Copy go mod files first (for better caching)
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build the binary with optimizations
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o http-status-checker .

# Final stage - minimal runtime image
FROM scratch

# Import from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/passwd /etc/passwd

# Copy the binary
COPY --from=builder /build/http-status-checker /http-status-checker

# Use non-root user
USER appuser

# Expose default health check port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/http-status-checker", "health", "check", "--once"] || exit 1

# Set entrypoint
ENTRYPOINT ["/http-status-checker"]
CMD ["--help"]
