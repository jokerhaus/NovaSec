#!/bin/bash
# scripts/update.sh
# NovaSec Update Script

set -e

echo "Updating NovaSec..."

# Stop services
make stop

# Pull latest changes
git pull origin main

# Update dependencies
go mod download
go mod tidy

# Rebuild services
make build

# Start services
make run

echo "Update complete!"
