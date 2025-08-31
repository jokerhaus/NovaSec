#!/bin/bash
# scripts/setup.sh
# NovaSec Setup Script

set -e

echo "Setting up NovaSec..."

# Create necessary directories
mkdir -p logs
mkdir -p configs/tls

# Generate TLS certificates
if [ ! -f configs/tls/ca.crt ]; then
    echo "Generating TLS certificates..."
    ./scripts/gen-certs.sh
fi

# Download dependencies
echo "Downloading Go dependencies..."
go mod download

# Build services
echo "Building services..."
make build

echo "Setup complete!"
echo "Run 'make run' to start the platform"
