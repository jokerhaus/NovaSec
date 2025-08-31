#!/bin/bash
# scripts/healthcheck.sh
# NovaSec Health Check Script

set -e

echo "Checking NovaSec services health..."

# Check Ingest service
if curl -f http://localhost:8080/api/v1/health > /dev/null 2>&1; then
    echo "✓ Ingest service is healthy"
else
    echo "✗ Ingest service is unhealthy"
fi

# Check Admin API service
if curl -f http://localhost:8081/api/v1/health > /dev/null 2>&1; then
    echo "✓ Admin API service is healthy"
else
    echo "✗ Admin API service is unhealthy"
fi

# Check NATS
if curl -f http://localhost:8222/healthz > /dev/null 2>&1; then
    echo "✓ NATS is healthy"
else
    echo "✗ NATS is unhealthy"
fi

# Check ClickHouse
if curl -f http://localhost:8123/ping > /dev/null 2>&1; then
    echo "✓ ClickHouse is healthy"
else
    echo "✗ ClickHouse is unhealthy"
fi

# Check PostgreSQL
if docker exec postgres pg_isready -U novasec > /dev/null 2>&1; then
    echo "✓ PostgreSQL is healthy"
else
    echo "✗ PostgreSQL is unhealthy"
fi

echo "Health check complete!"
