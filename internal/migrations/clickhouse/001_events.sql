-- internal/migrations/clickhouse/001_events.sql
-- Создание базы данных и таблицы событий

CREATE DATABASE IF NOT EXISTS novasec;

USE novasec;

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
