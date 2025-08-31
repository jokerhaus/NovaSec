-- docker/init/postgres-init.sql
-- SQL скрипт инициализации PostgreSQL для NovaSec

-- Создание расширений
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Создание таблицы агентов
CREATE TABLE IF NOT EXISTS agents (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    host VARCHAR(255) NOT NULL,
    env VARCHAR(100) DEFAULT 'production',
    status VARCHAR(50) DEFAULT 'active',
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Создание таблицы интеграций
CREATE TABLE IF NOT EXISTS integrations (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(100) NOT NULL,
    config JSONB NOT NULL,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Создание таблицы алертов
CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ts TIMESTAMPTZ NOT NULL,
    rule_id VARCHAR(255) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    dedup_key VARCHAR(255) NOT NULL,
    payload JSONB NOT NULL,
    status VARCHAR(50) DEFAULT 'new',
    env VARCHAR(100) DEFAULT 'production',
    host VARCHAR(255),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Создание таблицы правил
CREATE TABLE IF NOT EXISTS rules (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    version INTEGER DEFAULT 1,
    yaml TEXT NOT NULL,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Создание таблицы подавлений
CREATE TABLE IF NOT EXISTS suppressions (
    rule_id VARCHAR(255) NOT NULL,
    key_hash VARCHAR(255) NOT NULL,
    until TIMESTAMPTZ NOT NULL,
    created TIMESTAMPTZ DEFAULT NOW(),
    reason VARCHAR(500),
    PRIMARY KEY (rule_id, key_hash)
);

-- Создание индексов для алертов
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts(rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_dedup_key ON alerts(dedup_key);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_env ON alerts(env);
CREATE INDEX IF NOT EXISTS idx_alerts_host ON alerts(host);

-- Создание индексов для правил
CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled);
CREATE INDEX IF NOT EXISTS idx_rules_version ON rules(version);

-- Создание индексов для подавлений
CREATE INDEX IF NOT EXISTS idx_suppressions_until ON suppressions(until);
CREATE INDEX IF NOT EXISTS idx_suppressions_rule_id ON suppressions(rule_id);

-- Вставка тестовых данных
INSERT INTO agents (id, name, host, env) VALUES 
    ('agent-001', 'Test Agent 1', 'server-01', 'production'),
    ('agent-002', 'Test Agent 2', 'server-02', 'production')
ON CONFLICT (id) DO NOTHING;

-- Создание пользователя для приложения (если не существует)
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'novasec_app') THEN
        CREATE ROLE novasec_app LOGIN PASSWORD 'novasec_app_pass';
    END IF;
END
$$;

-- Предоставление прав пользователю приложения
GRANT CONNECT ON DATABASE novasec TO novasec_app;
GRANT USAGE ON SCHEMA public TO novasec_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO novasec_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO novasec_app;

-- Создание триггера для обновления updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Применение триггера к таблицам
CREATE TRIGGER update_agents_updated_at BEFORE UPDATE ON agents FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_integrations_updated_at BEFORE UPDATE ON integrations FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_alerts_updated_at BEFORE UPDATE ON alerts FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_rules_updated_at BEFORE UPDATE ON rules FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Сообщение об успешной инициализации
SELECT 'PostgreSQL initialization completed successfully!' as status;
