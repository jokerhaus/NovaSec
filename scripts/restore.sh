#!/bin/bash
# scripts/restore.sh
# NovaSec Restore Script

set -e

if [ $# -eq 0 ]; then
    echo "Usage: $0 <backup_directory>"
    exit 1
fi

BACKUP_DIR="$1"

if [ ! -d "$BACKUP_DIR" ]; then
    echo "Backup directory $BACKUP_DIR does not exist"
    exit 1
fi

echo "Restoring from $BACKUP_DIR..."

# Stop services
make stop

# Restore PostgreSQL
docker exec -i postgres psql -U novasec novasec < "$BACKUP_DIR/postgres.sql"

# Restore ClickHouse
docker exec clickhouse clickhouse-client --query "RESTORE TABLE novasec.events FROM '$BACKUP_DIR/clickhouse'"

# Restore configurations
cp -r "$BACKUP_DIR/configs" ./

# Restore rules
cp -r "$BACKUP_DIR/rules" ./internal/

echo "Restore complete!"
echo "Run 'make run' to start the platform"
