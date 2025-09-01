#!/bin/bash
# scripts/install.sh
# NovaSec Installation Script

set -e

echo "Installing NovaSec..."

# Check prerequisites
command -v docker >/dev/null 2>&1 || { echo "Docker is required but not installed. Aborting." >&2; exit 1; }
command -v docker-compose >/dev/null 2>&1 || { echo "Docker Compose is required but not installed. Aborting." >&2; exit 1; }
command -v go >/dev/null 2>&1 || { echo "Go is required but not installed. Aborting." >&2; exit 1; }

# Check Go version
GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
REQUIRED_VERSION="1.22"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$GO_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo "Go version $REQUIRED_VERSION or higher is required. Current version: $GO_VERSION"
    exit 1
fi

# Create necessary directories
mkdir -p logs
mkdir -p configs/tls
mkdir -p backups

# Generate TLS certificates
if [ ! -f configs/tls/ca.crt ]; then
    echo "Generating TLS certificates..."
    chmod +x scripts/gen-certs.sh
    ./scripts/gen-certs.sh
fi

# Download dependencies
echo "Downloading Go dependencies..."
go mod download

# Build services
echo "Building services..."
make build

# Start services
echo "Starting services..."
make run

echo "Installation complete!"
echo "NovaSec is now running on:"
echo "  - Ingest API: http://localhost:8080"
echo "  - Admin API: http://localhost:8081"
echo "  - Prometheus: http://localhost:9090"
echo "  - Grafana: http://localhost:3000 (admin/admin)"
