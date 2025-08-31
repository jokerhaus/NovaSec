#!/bin/bash
# docker/init/clickhouse-init.sh
# Скрипт инициализации ClickHouse для NovaSec

set -e

echo "Initializing ClickHouse database..."

# Ждем, пока ClickHouse станет доступен
until clickhouse-client --host localhost --port 9000 --user novasec --password novasec123 --query "SELECT 1" > /dev/null 2>&1; do
    echo "Waiting for ClickHouse to be ready..."
    sleep 2
done

echo "ClickHouse is ready. Creating database and tables..."

# Создаем базу данных
clickhouse-client --host localhost --port 9000 --user novasec --password novasec123 --query "
CREATE DATABASE IF NOT EXISTS novasec;
"

# Создаем таблицу событий
clickhouse-client --host localhost --port 9000 --user novasec --password novasec123 --database novasec --query "
CREATE TABLE IF NOT EXISTS events (
    ts DateTime64(3),
    host String,
    agent_id String,
    env String,
    source String,
    severity String,
    category String,
    subtype String,
    message String,
    user_name String,
    user_uid Nullable(Int32),
    src_ip Nullable(UInt32),
    src_port Nullable(UInt16),
    dst_ip Nullable(UInt32),
    dst_port Nullable(UInt16),
    proto String,
    file_path String,
    process_pid Nullable(Int32),
    process_name String,
    sha256 String,
    labels Map(String, String),
    geo String,
    asn Nullable(UInt32),
    ioc String,
    raw String,
    json String
) ENGINE = MergeTree()
PARTITION BY toDate(ts)
ORDER BY (env, category, subtype, host, ts)
TTL ts + INTERVAL 180 DAY
SETTINGS index_granularity = 8192;
"

echo "ClickHouse initialization completed successfully!"
