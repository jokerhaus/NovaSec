#!/bin/bash
# scripts/metrics.sh
# NovaSec Metrics Script

set -e

echo "NovaSec Platform Metrics"
echo "========================"

# System metrics
echo -e "\nSystem Resources:"
echo "CPU Usage: $(top -l 1 | grep "CPU usage" | awk '{print $3}' | sed 's/%//')%"
echo "Memory Usage: $(top -l 1 | grep PhysMem | awk '{print $2}')"

# Docker metrics
echo -e "\nDocker Containers:"
docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}"

# Service metrics
echo -e "\nService Status:"
docker-compose -f docker/docker-compose.yml ps --format "table {{.Service}}\t{{.Status}}\t{{.Ports}}"

# NATS metrics
echo -e "\nNATS Metrics:"
if curl -s http://localhost:8222/varz > /dev/null 2>&1; then
    echo "NATS is running on port 8222"
else
    echo "NATS is not accessible"
fi

# ClickHouse metrics
echo -e "\nClickHouse Metrics:"
if curl -s http://localhost:8123/ > /dev/null 2>&1; then
    echo "ClickHouse is running on port 8123"
else
    echo "ClickHouse is not accessible"
fi

# PostgreSQL metrics
echo -e "\nPostgreSQL Metrics:"
if docker exec postgres pg_isready -U novasec > /dev/null 2>&1; then
    echo "PostgreSQL is running on port 5432"
else
    echo "PostgreSQL is not accessible"
fi
