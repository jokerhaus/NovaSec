#!/bin/bash
# filename: docker/init/clickhouse-init.sh
# Скрипт инициализации ClickHouse для NovaSec SIEM

set -e

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Функция логирования
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

# Ожидание запуска ClickHouse
log "Waiting for ClickHouse to start..."
sleep 10

# Функция выполнения SQL команд
execute_sql() {
    local sql="$1"
    local description="$2"
    
    log "Executing: $description"
    echo "$sql" | clickhouse-client --host=clickhouse --port=9000 || {
        error "Failed to execute: $description"
        return 1
    }
}

# Создание базы данных
log "Creating NovaSec database..."
execute_sql "CREATE DATABASE IF NOT EXISTS novasec;" "Create database"

# Создание таблицы событий
log "Creating events table..."
cat << 'EOF' | clickhouse-client --host=clickhouse --port=9000
CREATE TABLE IF NOT EXISTS novasec.events (
    ts DateTime64(3) DEFAULT now64(),
    host String,
    agent_id String,
    env String DEFAULT 'production',
    source String,
    severity String DEFAULT 'info',
    category String,
    subtype String,
    message String,
    user_name String DEFAULT '',
    user_uid Nullable(UInt32),
    src_ip String DEFAULT '',
    src_port Nullable(UInt16),
    dst_ip String DEFAULT '',
    dst_port Nullable(UInt16),
    proto String DEFAULT '',
    file_path String DEFAULT '',
    process_pid Nullable(UInt32),
    process_name String DEFAULT '',
    sha256 String DEFAULT '',
    geo String DEFAULT '',
    asn Nullable(UInt32),
    ioc String DEFAULT '',
    labels Map(String, String),
    raw String
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(ts)
ORDER BY (ts, host, category, severity)
TTL ts + INTERVAL 90 DAY DELETE
SETTINGS index_granularity = 8192;
EOF

if [ $? -eq 0 ]; then
    log "Events table created successfully"
else
    error "Failed to create events table"
    exit 1
fi

# Создание дополнительных индексов
log "Creating additional indexes..."

execute_sql "
ALTER TABLE novasec.events 
ADD INDEX idx_src_ip src_ip TYPE bloom_filter(0.01) GRANULARITY 1024;
" "Add source IP bloom filter index"

execute_sql "
ALTER TABLE novasec.events 
ADD INDEX idx_user_name user_name TYPE bloom_filter(0.01) GRANULARITY 1024;
" "Add username bloom filter index"

execute_sql "
ALTER TABLE novasec.events 
ADD INDEX idx_file_path file_path TYPE bloom_filter(0.01) GRANULARITY 1024;
" "Add file path bloom filter index"

execute_sql "
ALTER TABLE novasec.events 
ADD INDEX idx_sha256 sha256 TYPE bloom_filter(0.01) GRANULARITY 1024;
" "Add SHA256 bloom filter index"

# Создание материализованных представлений для аналитики
log "Creating materialized views..."

# Представление для агрегации по хостам
execute_sql "
CREATE MATERIALIZED VIEW IF NOT EXISTS novasec.events_by_host
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(ts)
ORDER BY (ts, host, severity)
AS SELECT
    toStartOfHour(ts) as ts,
    host,
    severity,
    count() as event_count
FROM novasec.events
GROUP BY ts, host, severity;
" "Create events by host materialized view"

# Представление для агрегации по источникам
execute_sql "
CREATE MATERIALIZED VIEW IF NOT EXISTS novasec.events_by_source
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(ts)
ORDER BY (ts, source, category)
AS SELECT
    toStartOfHour(ts) as ts,
    source,
    category,
    count() as event_count
FROM novasec.events
GROUP BY ts, source, category;
" "Create events by source materialized view"

# Представление для агрегации по сетевым адресам
execute_sql "
CREATE MATERIALIZED VIEW IF NOT EXISTS novasec.events_by_network
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(ts)
ORDER BY (ts, src_ip, dst_ip)
AS SELECT
    toStartOfHour(ts) as ts,
    src_ip,
    dst_ip,
    proto,
    count() as event_count
FROM novasec.events
WHERE src_ip != '' OR dst_ip != ''
GROUP BY ts, src_ip, dst_ip, proto;
" "Create events by network materialized view"

# Создание таблицы для статистики
log "Creating statistics table..."
execute_sql "
CREATE TABLE IF NOT EXISTS novasec.event_stats (
    ts DateTime DEFAULT now(),
    metric_name String,
    metric_value UInt64,
    tags Map(String, String)
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(ts)
ORDER BY (ts, metric_name)
TTL ts + INTERVAL 30 DAY DELETE;
" "Create statistics table"

# Создание пользователей и прав доступа
log "Creating users and permissions..."

execute_sql "
CREATE USER IF NOT EXISTS novasec_writer IDENTIFIED WITH plaintext_password BY 'writer_password_here';
" "Create writer user"

execute_sql "
CREATE USER IF NOT EXISTS novasec_reader IDENTIFIED WITH plaintext_password BY 'reader_password_here';
" "Create reader user"

execute_sql "
GRANT INSERT, SELECT ON novasec.events TO novasec_writer;
" "Grant writer permissions"

execute_sql "
GRANT SELECT ON novasec.* TO novasec_reader;
" "Grant reader permissions"

# Создание профилей производительности
log "Creating performance profiles..."

execute_sql "
CREATE SETTINGS PROFILE IF NOT EXISTS writer_profile SETTINGS
    max_memory_usage = 10000000000,
    max_execution_time = 60,
    load_balancing = 'random';
" "Create writer profile"

execute_sql "
CREATE SETTINGS PROFILE IF NOT EXISTS reader_profile SETTINGS
    max_memory_usage = 5000000000,
    max_execution_time = 30,
    readonly = 1;
" "Create reader profile"

execute_sql "
ALTER USER novasec_writer SETTINGS PROFILE writer_profile;
" "Apply writer profile"

execute_sql "
ALTER USER novasec_reader SETTINGS PROFILE reader_profile;
" "Apply reader profile"

# Вставка тестовых данных
log "Inserting test data..."
execute_sql "
INSERT INTO novasec.events (ts, host, agent_id, env, source, severity, category, subtype, message, src_ip, user_name) VALUES
    (now() - INTERVAL 1 HOUR, 'test-server-01', 'agent-001', 'test', 'linux_auth', 'medium', 'authentication', 'ssh_login_failed', 'SSH login failed for user admin from 192.168.1.100', '192.168.1.100', 'admin'),
    (now() - INTERVAL 30 MINUTE, 'test-server-01', 'agent-001', 'test', 'nginx', 'info', 'web', 'http_request', 'GET /api/health 200', '192.168.1.101', ''),
    (now() - INTERVAL 15 MINUTE, 'test-server-02', 'agent-002', 'test', 'linux_auth', 'info', 'authentication', 'ssh_login_success', 'SSH login successful for user developer from 192.168.1.102', '192.168.1.102', 'developer');
" "Insert test events"

# Создание функций для очистки данных
log "Creating cleanup functions..."
execute_sql "
CREATE OR REPLACE FUNCTION cleanup_old_events()
RETURNS String
AS $$
    OPTIMIZE TABLE novasec.events FINAL;
    ALTER TABLE novasec.events DELETE WHERE ts < now() - INTERVAL 90 DAY;
    RETURN 'Cleanup completed';
$$;
" "Create cleanup function"

# Создание задач по расписанию (если поддерживается)
log "Setting up scheduled tasks..."
execute_sql "
-- Оптимизация таблиц каждый час
SYSTEM RELOAD CONFIG;
" "Reload configuration"

# Проверка состояния
log "Checking database status..."
execute_sql "
SELECT 
    'events' as table_name,
    count() as row_count,
    formatBytes(sum(bytes_on_disk)) as disk_size
FROM system.parts 
WHERE database = 'novasec' AND table = 'events' AND active = 1;
" "Check events table status"

# Создание представления для мониторинга
execute_sql "
CREATE OR REPLACE VIEW novasec.system_status AS
SELECT
    'clickhouse' as component,
    'healthy' as status,
    map(
        'version', version(),
        'uptime', toString(uptime()),
        'events_count', toString((SELECT count() FROM novasec.events)),
        'disk_usage', formatBytes((SELECT sum(bytes_on_disk) FROM system.parts WHERE database = 'novasec'))
    ) as details;
" "Create system status view"

# Установка конфигурационных параметров
log "Setting configuration parameters..."
execute_sql "
SET max_memory_usage = 10000000000;
SET max_execution_time = 300;
SET send_logs_level = 'warning';
" "Set configuration parameters"

log "ClickHouse initialization completed successfully!"

# Вывод итоговой информации
echo ""
log "=== NovaSec ClickHouse Setup Summary ==="
log "Database: novasec"
log "Events table: novasec.events"
log "Materialized views: events_by_host, events_by_source, events_by_network"
log "Users: novasec_writer, novasec_reader"
log "Data retention: 90 days"
log "Test data: 3 sample events inserted"
echo ""
log "Setup completed successfully!"

exit 0
