#!/bin/bash
# scripts/backup.sh
# NovaSec Backup Script

set -e

BACKUP_DIR="backups/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

echo "Creating backup in $BACKUP_DIR..."

# Backup PostgreSQL
docker exec postgres pg_dump -U novasec novasec > "$BACKUP_DIR/postgres.sql"

# Backup ClickHouse
docker exec clickhouse clickhouse-client --query "BACKUP TABLE novasec.events TO '$BACKUP_DIR/clickhouse'"

# Backup configurations
cp -r configs "$BACKUP_DIR/"

# Backup rules
cp -r internal/rules "$BACKUP_DIR/"

echo "Backup complete: $BACKUP_DIR"
