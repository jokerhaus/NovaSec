#!/bin/bash
# scripts/cleanup.sh
# NovaSec Cleanup Script

set -e

echo "Cleaning up NovaSec..."

# Stop services
make stop

# Remove containers and volumes
docker-compose -f docker/docker-compose.yml down -v

# Clean build artifacts
make clean

# Remove logs
rm -rf logs/*

echo "Cleanup complete!"
