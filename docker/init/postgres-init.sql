-- filename: docker/init/postgres-init.sql
-- Скрипт инициализации PostgreSQL для NovaSec SIEM

-- Создание базы данных (если не существует)
CREATE DATABASE IF NOT EXISTS novasec;
USE novasec;

-- Создание расширений
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Создание ролей
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'novasec_admin') THEN
        CREATE ROLE novasec_admin WITH LOGIN PASSWORD 'admin_password_here';
    END IF;
    
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'novasec_app') THEN
        CREATE ROLE novasec_app WITH LOGIN PASSWORD 'app_password_here';
    END IF;
    
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'novasec_readonly') THEN
        CREATE ROLE novasec_readonly WITH LOGIN PASSWORD 'readonly_password_here';
    END IF;
END $$;

-- Предоставление прав
GRANT ALL PRIVILEGES ON DATABASE novasec TO novasec_admin;
GRANT CONNECT ON DATABASE novasec TO novasec_app;
GRANT CONNECT ON DATABASE novasec TO novasec_readonly;

-- Инициализация схемы
\i /docker-entrypoint-initdb.d/migrations/001_meta.sql
\i /docker-entrypoint-initdb.d/migrations/002_alerts.sql
\i /docker-entrypoint-initdb.d/migrations/003_rules.sql
\i /docker-entrypoint-initdb.d/migrations/004_suppressions.sql

-- Создание дополнительных индексов для производительности
CREATE INDEX IF NOT EXISTS idx_alerts_ts_env ON alerts(ts, env);
CREATE INDEX IF NOT EXISTS idx_alerts_severity_status ON alerts(severity, status);
CREATE INDEX IF NOT EXISTS idx_rules_enabled_priority ON rules(enabled, name);

-- Настройка прав доступа для приложения
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO novasec_app;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO novasec_readonly;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO novasec_app;

-- Установка параметров конфигурации
ALTER SYSTEM SET shared_preload_libraries = 'pg_stat_statements';
ALTER SYSTEM SET log_statement = 'all';
ALTER SYSTEM SET log_duration = on;
ALTER SYSTEM SET log_min_duration_statement = 1000;

-- Создание задач обслуживания
DO $$
BEGIN
    -- Планировщик для очистки старых записей
    PERFORM cron.schedule('cleanup-old-heartbeats', '0 2 * * *', 'SELECT cleanup_old_heartbeats();');
    PERFORM cron.schedule('cleanup-old-agent-events', '0 3 * * *', 'SELECT cleanup_old_agent_events();');
    PERFORM cron.schedule('cleanup-expired-suppressions', '*/30 * * * *', 'SELECT cleanup_expired_suppressions();');
EXCEPTION
    WHEN OTHERS THEN
        RAISE NOTICE 'pg_cron extension not available, skipping scheduled tasks';
END $$;

-- Создание представлений для мониторинга
CREATE OR REPLACE VIEW system_health AS
SELECT
    'alerts' as table_name,
    COUNT(*) as total_records,
    COUNT(CASE WHEN ts > NOW() - INTERVAL '24 hours' THEN 1 END) as recent_records,
    MAX(ts) as latest_record
FROM alerts
UNION ALL
SELECT
    'agent_heartbeats' as table_name,
    COUNT(*) as total_records,
    COUNT(CASE WHEN ts > NOW() - INTERVAL '1 hour' THEN 1 END) as recent_records,
    MAX(ts) as latest_record
FROM agent_heartbeats
UNION ALL
SELECT
    'rules' as table_name,
    COUNT(*) as total_records,
    COUNT(CASE WHEN enabled = true THEN 1 END) as recent_records,
    MAX(updated_at) as latest_record
FROM rules;

-- Создание функции для проверки состояния системы
CREATE OR REPLACE FUNCTION check_system_status()
RETURNS TABLE (
    component TEXT,
    status TEXT,
    details JSONB
) AS $$
BEGIN
    -- Проверка активных агентов
    RETURN QUERY
    SELECT 
        'agents'::TEXT,
        CASE 
            WHEN COUNT(*) > 0 THEN 'healthy'::TEXT
            ELSE 'warning'::TEXT
        END,
        jsonb_build_object(
            'total_agents', COUNT(*),
            'active_agents', COUNT(CASE WHEN last_seen > NOW() - INTERVAL '5 minutes' THEN 1 END)
        )
    FROM agents;
    
    -- Проверка правил
    RETURN QUERY
    SELECT 
        'rules'::TEXT,
        CASE 
            WHEN COUNT(CASE WHEN enabled = true THEN 1 END) > 0 THEN 'healthy'::TEXT
            ELSE 'error'::TEXT
        END,
        jsonb_build_object(
            'total_rules', COUNT(*),
            'enabled_rules', COUNT(CASE WHEN enabled = true THEN 1 END)
        )
    FROM rules;
    
    -- Проверка алертов
    RETURN QUERY
    SELECT 
        'alerts'::TEXT,
        'healthy'::TEXT,
        jsonb_build_object(
            'total_alerts', COUNT(*),
            'new_alerts', COUNT(CASE WHEN status = 'new' THEN 1 END),
            'last_24h', COUNT(CASE WHEN ts > NOW() - INTERVAL '24 hours' THEN 1 END)
        )
    FROM alerts;
    
END;
$$ LANGUAGE plpgsql;

-- Финальная конфигурация
SELECT pg_reload_conf();

-- Логирование завершения инициализации
INSERT INTO agent_events (agent_id, event_type, message, created_at) 
VALUES ('system', 'initialization', 'PostgreSQL database initialized successfully', NOW())
ON CONFLICT DO NOTHING;
