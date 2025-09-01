-- internal/migrations/postgres/001_meta.sql
-- Создание таблиц метаданных

-- Создание функции для обновления updated_at (если не существует)
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

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

CREATE TABLE IF NOT EXISTS integrations (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(100) NOT NULL,
    config JSONB NOT NULL,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Создание индексов для агентов
CREATE INDEX IF NOT EXISTS idx_agents_host ON agents(host);
CREATE INDEX IF NOT EXISTS idx_agents_env ON agents(env);
CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);
CREATE INDEX IF NOT EXISTS idx_agents_last_seen ON agents(last_seen);

-- Создание индексов для интеграций
CREATE INDEX IF NOT EXISTS idx_integrations_type ON integrations(type);
CREATE INDEX IF NOT EXISTS idx_integrations_enabled ON integrations(enabled);
CREATE INDEX IF NOT EXISTS idx_integrations_config_gin ON integrations USING GIN (config);

-- Создание таблицы для мониторинга агентов
CREATE TABLE IF NOT EXISTS agent_heartbeats (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id VARCHAR(255) NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status VARCHAR(50) NOT NULL,
    metrics JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Создание индексов для heartbeat
CREATE INDEX IF NOT EXISTS idx_agent_heartbeats_agent_id ON agent_heartbeats(agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_heartbeats_timestamp ON agent_heartbeats(timestamp);
CREATE INDEX IF NOT EXISTS idx_agent_heartbeats_status ON agent_heartbeats(status);

-- Создание таблицы для конфигурации агентов
CREATE TABLE IF NOT EXISTS agent_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id VARCHAR(255) NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    config_type VARCHAR(100) NOT NULL,
    config_data JSONB NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Создание индексов для конфигураций
CREATE INDEX IF NOT EXISTS idx_agent_configs_agent_id ON agent_configs(agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_configs_type ON agent_configs(config_type);
CREATE INDEX IF NOT EXISTS idx_agent_configs_active ON agent_configs(active);
CREATE INDEX IF NOT EXISTS idx_agent_configs_version ON agent_configs(version);

-- Создание таблицы для событий агентов
CREATE TABLE IF NOT EXISTS agent_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id VARCHAR(255) NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    event_type VARCHAR(100) NOT NULL,
    event_data JSONB NOT NULL,
    severity VARCHAR(50) DEFAULT 'info',
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Создание индексов для событий агентов
CREATE INDEX IF NOT EXISTS idx_agent_events_agent_id ON agent_events(agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_events_type ON agent_events(event_type);
CREATE INDEX IF NOT EXISTS idx_agent_events_severity ON agent_events(severity);
CREATE INDEX IF NOT EXISTS idx_agent_events_timestamp ON agent_events(timestamp);

-- Создание триггеров для автоматического обновления updated_at
CREATE TRIGGER update_agents_updated_at 
    BEFORE UPDATE ON agents 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_integrations_updated_at 
    BEFORE UPDATE ON integrations 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_agent_configs_updated_at 
    BEFORE UPDATE ON agent_configs 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Создание функции для очистки старых heartbeat
CREATE OR REPLACE FUNCTION cleanup_old_heartbeats(p_days INTEGER DEFAULT 30)
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM agent_heartbeats 
    WHERE timestamp < NOW() - INTERVAL '1 day' * p_days;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Создание функции для очистки старых событий агентов
CREATE OR REPLACE FUNCTION cleanup_old_agent_events(p_days INTEGER DEFAULT 90)
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM agent_events 
    WHERE timestamp < NOW() - INTERVAL '1 day' * p_days;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Создание представления для активных агентов
CREATE OR REPLACE VIEW active_agents AS
SELECT 
    a.*,
    ah.timestamp as last_heartbeat,
    ah.status as heartbeat_status,
    EXTRACT(EPOCH FROM (NOW() - ah.timestamp))/60 as minutes_since_heartbeat
FROM agents a
LEFT JOIN LATERAL (
    SELECT timestamp, status 
    FROM agent_heartbeats 
    WHERE agent_id = a.id 
    ORDER BY timestamp DESC 
    LIMIT 1
) ah ON true
WHERE a.status = 'active'
ORDER BY a.last_seen DESC;

-- Создание представления для статистики агентов
CREATE OR REPLACE VIEW agent_stats AS
SELECT 
    a.env,
    a.status,
    COUNT(*) as agent_count,
    COUNT(CASE WHEN ah.timestamp > NOW() - INTERVAL '5 minutes' THEN 1 END) as online_count,
    COUNT(CASE WHEN ah.timestamp <= NOW() - INTERVAL '5 minutes' THEN 1 END) as offline_count
FROM agents a
LEFT JOIN LATERAL (
    SELECT timestamp 
    FROM agent_heartbeats 
    WHERE agent_id = a.id 
    ORDER BY timestamp DESC 
    LIMIT 1
) ah ON true
GROUP BY a.env, a.status
ORDER BY a.env, a.status;

-- Вставка тестовых данных
INSERT INTO agents (id, name, host, env, status) VALUES
('agent-001', 'Test Agent 1', 'server-01.example.com', 'production', 'active'),
('agent-002', 'Test Agent 2', 'server-02.example.com', 'production', 'active'),
('agent-003', 'Test Agent 3', 'server-03.example.com', 'staging', 'inactive')
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    host = EXCLUDED.host,
    env = EXCLUDED.env,
    status = EXCLUDED.status,
    updated_at = NOW();

INSERT INTO integrations (id, name, type, config, enabled) VALUES
('email-notifications', 'Email Notifications', 'email', 
 '{"smtp_host": "smtp.example.com", "smtp_port": 587, "username": "alerts@example.com"}', true),
('telegram-bot', 'Telegram Bot', 'telegram', 
 '{"bot_token": "123456789:ABC-DEF1234ghIkl-zyx57W2v1u123ew11", "chat_id": "-1001234567890"}', true),
('webhook-slack', 'Slack Webhook', 'webhook', 
 '{"url": "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX", "timeout": "10s"}', true)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    type = EXCLUDED.type,
    config = EXCLUDED.config,
    enabled = EXCLUDED.enabled,
    updated_at = NOW();
