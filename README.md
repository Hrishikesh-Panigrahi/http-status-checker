# HTTP Status Checker

A powerful, production-ready command-line tool for comprehensive website monitoring, health checks, and network diagnostics. Built with Go for performance and reliability.

## Features

### Enhanced HTTP Monitoring
- **Advanced Status Checking**: Response time measurement, SSL/TLS analysis, redirect tracking
- **Detailed Metrics**: DNS lookup time, connect time, first byte time, certificate information
- **Multiple Output Formats**: Table, JSON, verbose logging
- **Configurable Timeouts**: Request-level timeout control
- **SSL/TLS Analysis**: Certificate expiration tracking, cipher suite information

### Health Check System
- **Real-time Monitoring**: Continuous health monitoring with configurable intervals
- **Multiple Check Types**: HTTP/HTTPS endpoints, database connections, TCP port checks
- **Health Dashboard**: Web-based monitoring dashboard with auto-refresh
- **REST API**: Programmatic access to health status
- **Critical Check Support**: Mark checks as critical for alert prioritization

### Network Diagnostics
- **Cross-platform IP Detection**: Works on Windows, Linux, and macOS
- **DNS Information**: Primary/secondary DNS server detection
- **IPv4/IPv6 Support**: Dual-stack network information
- **Network Interface Details**: Comprehensive network configuration

### Production Ready
- **Structured Logging**: JSON and text format with configurable levels
- **Configuration Management**: File-based and environment variable configuration
- **Docker Support**: Optimized multi-stage Docker builds
- **Security**: Non-root user execution, minimal attack surface

## Quick Start

### Installation

#### From Source
```bash
git clone https://github.com/Hrishikesh-Panigrahi/http-status-checker
cd http-status-checker
go build -o http-status-checker .
```

#### Using Docker
```bash
# Pull the latest image
docker pull hrishikeshpanigrahi025/http-status-checker

# Run a quick check
docker run hrishikeshpanigrahi025/http-status-checker check google.com
```

## Usage

### Basic HTTP Status Checking

```bash
# Basic status check
./http-status-checker check google.com

# Custom number of checks
./http-status-checker check api.github.com 10

# Verbose output with SSL details
./http-status-checker check https://api.stripe.com --verbose

# JSON output for scripting
./http-status-checker check example.com --json

# Custom timeout
./http-status-checker check slow-api.com --timeout 30s
```

### Network Information

```bash
# Show local IP address
./http-status-checker ip

# Get remote host information
./http-status-checker ip github.com

# Show DNS servers
./http-status-checker ip --dns

# All network information in table format
./http-status-checker ip google.com --all --table
```

### Health Monitoring

```bash
# Start health monitoring server
./http-status-checker health server --port 8080

# Add a health check
./http-status-checker health add --name "api" --url "https://api.example.com/health"

# List all health checks
./http-status-checker health list

# Run checks once and exit
./http-status-checker health check --once
```

### Legacy Commands (Still Supported)

```bash
# Get hostname aliases
./http-status-checker alias github.com

# Basic route information
./http-status-checker route google.com
```

## Docker Usage

### Quick Check
```bash
# Basic website check
docker run hrishikeshpanigrahi025/http-status-checker check google.com 5

# Health monitoring server
docker run -p 8080:8080 hrishikeshpanigrahi025/http-status-checker health server
```

### Production Deployment
```bash
# Create a config volume
docker volume create hsc-config

# Run with persistent configuration
docker run -d \
  --name http-status-checker \
  -p 8080:8080 \
  -v hsc-config:/config \
  -e HSC_LOG_LEVEL=info \
  -e HSC_HEALTH_ENABLED=true \
  --restart unless-stopped \
  hrishikeshpanigrahi025/http-status-checker health server
```

### Docker Compose
```yaml
version: '3.8'
services:
  http-status-checker:
    image: hrishikeshpanigrahi025/http-status-checker
    ports:
      - "8080:8080"
    environment:
      - HSC_LOG_LEVEL=info
      - HSC_HEALTH_ENABLED=true
    command: ["health", "server"]
    restart: unless-stopped
```

## Configuration

### Configuration File
Create a configuration file at `~/.config/http-status-checker/config.json`:

```json
{
  "http": {
    "timeout": "10s",
    "user_agent": "http-status-checker/2.0",
    "max_idle_conns": 100
  },
  "logging": {
    "level": "info",
    "format": "text",
    "output": "stdout"
  },
  "health_check": {
    "enabled": true,
    "port": 8080,
    "interval": "30s"
  },
  "defaults": {
    "pings": 4,
    "max_pings": 100,
    "delay_between": "500ms"
  }
}
```

### Environment Variables
All configuration options can be overridden with environment variables:

```bash
# HTTP settings
export HSC_HTTP_TIMEOUT=15s
export HSC_USER_AGENT="MyApp/1.0"

# Logging settings
export HSC_LOG_LEVEL=debug
export HSC_LOG_FORMAT=json
export HSC_LOG_OUTPUT=file
export HSC_LOG_FILE=/var/log/hsc.log

# Health check settings
export HSC_HEALTH_ENABLED=true
export HSC_HEALTH_PORT=8080

# Default behavior
export HSC_DEFAULT_PINGS=5
```

## Health Check API

### Endpoints

#### GET /health
Returns overall system health status.

**Response:**
```json
{
  "status": "healthy",
  "message": "All systems operational",
  "timestamp": "2024-01-15T10:30:00Z",
  "summary": {
    "total": 5,
    "healthy": 4,
    "unhealthy": 1,
    "critical": 0
  },
  "checks": [
    {
      "name": "api-endpoint",
      "type": "http",
      "status": "healthy",
      "message": "HTTP check passed (status: 200)",
      "duration": "123ms"
    }
  ]
}
```

### Status Codes
- **200 OK**: All checks passing
- **503 Service Unavailable**: One or more checks failing

## What's New in 2.0

### Major Improvements
- **Complete rewrite** with production-ready architecture
- **Health monitoring system** with real-time dashboard
- **Cross-platform support** for Windows, Linux, and macOS
- **Configuration management** with file and environment variable support
- **Structured logging** with JSON and text formats
- **Docker optimization** with multi-stage builds and minimal images
- **Enhanced HTTP client** with connection pooling and detailed metrics
- **SSL/TLS analysis** with certificate expiration tracking

### Breaking Changes
- Command structure enhanced (old commands still work)
- Configuration file format changed
- Docker image structure optimized

### Migration from 1.x
The tool maintains backward compatibility for basic usage:
```bash
# This still works the same way
./http-status-checker check google.com 5
```

## Development

### Project Structure
```
.
├── cmd/                    # Command implementations
│   ├── check.go           # Enhanced HTTP checking
│   ├── health.go          # Health monitoring system
│   ├── ip.go              # Network information
│   └── root.go            # Root command
├── internal/              # Internal packages
│   ├── checker/           # HTTP checking logic
│   ├── config/            # Configuration management
│   ├── health/            # Health monitoring
│   └── network/           # Network utilities
├── pkg/                   # Public packages
│   └── logger/            # Structured logging
├── Dockerfile             # Production Docker image
└── README.md              # This file
```

### Building from Source
```bash
# Clone and build
git clone https://github.com/Hrishikesh-Panigrahi/http-status-checker
cd http-status-checker
go mod download
go build -o http-status-checker .

# Cross-platform builds
GOOS=linux GOARCH=amd64 go build -o http-status-checker-linux .
GOOS=windows GOARCH=amd64 go build -o http-status-checker-windows.exe .
GOOS=darwin GOARCH=amd64 go build -o http-status-checker-macos .
```

## Performance & Security

### Performance
- **HTTP Checks**: ~50ms average response time
- **Memory Usage**: ~10MB base memory footprint
- **Docker Image**: ~5MB compressed image size
- **Concurrent Checks**: Supports 100+ concurrent health checks

### Security Features
- Runs as non-root user in Docker
- Minimal attack surface with scratch-based image
- Certificate validation and expiration tracking
- Secure HTTP client configuration

## Troubleshooting

### Common Issues

#### Connection Timeouts
```bash
# Increase timeout for slow endpoints
./http-status-checker check slow-api.com --timeout 60s

# Or via environment variable
export HSC_HTTP_TIMEOUT=60s
```

#### DNS Resolution Issues
```bash
# Check DNS configuration
./http-status-checker ip --dns

# Verify hostname resolution
./http-status-checker ip problematic-hostname.com
```

#### SSL Certificate Issues
```bash
# Check certificate details
./http-status-checker check https://expired-cert-site.com --verbose

# Allow insecure connections for testing
export HSC_ALLOW_INSECURE=true
```

## License

This project is licensed under the MIT License.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Links

- [GitHub Repository](https://github.com/Hrishikesh-Panigrahi/http-status-checker)
- [Docker Hub](https://hub.docker.com/r/hrishikeshpanigrahi025/http-status-checker)

---

Developer: [Hrishikesh Panigrahi](https://github.com/Hrishikesh-Panigrahi)
