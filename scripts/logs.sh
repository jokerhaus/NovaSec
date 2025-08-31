#!/bin/bash
# scripts/logs.sh
# NovaSec Logs Script

set -e

SERVICE="${1:-all}"
LINES="${2:-100}"

case $SERVICE in
    ingest)
        docker logs --tail $LINES novasec-ingest
        ;;
    normalizer)
        docker logs --tail $LINES novasec-normalizer
        ;;
    correlator)
        docker logs --tail $LINES novasec-correlator
        ;;
    alerting)
        docker logs --tail $LINES novasec-alerting
        ;;
    adminapi)
        docker logs --tail $LINES novasec-adminapi
        ;;
    nats)
        docker logs --tail $LINES nats
        ;;
    clickhouse)
        docker logs --tail $LINES clickhouse
        ;;
    postgres)
        docker logs --tail $LINES postgres
        ;;
    all)
        echo "=== Ingest Service ==="
        docker logs --tail $LINES novasec-ingest 2>/dev/null || echo "Service not running"
        echo -e "\n=== Normalizer Service ==="
        docker logs --tail $LINES novasec-normalizer 2>/dev/null || echo "Service not running"
        echo -e "\n=== Correlator Service ==="
        docker logs --tail $LINES novasec-correlator 2>/dev/null || echo "Service not running"
        echo -e "\n=== Alerting Service ==="
        docker logs --tail $LINES novasec-alerting 2>/dev/null || echo "Service not running"
        echo -e "\n=== Admin API Service ==="
        docker logs --tail $LINES novasec-adminapi 2>/dev/null || echo "Service not running"
        ;;
    *)
        echo "Usage: $0 [service] [lines]"
        echo "Services: ingest, normalizer, correlator, alerting, adminapi, nats, clickhouse, postgres, all"
        echo "Default: all, 100 lines"
        exit 1
        ;;
esac
