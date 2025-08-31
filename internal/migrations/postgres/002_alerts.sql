-- internal/migrations/postgres/002_alerts.sql
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

CREATE INDEX idx_alerts_ts ON alerts(ts);
CREATE INDEX idx_alerts_rule_id ON alerts(rule_id);
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_dedup_key ON alerts(dedup_key);
CREATE INDEX idx_alerts_status ON alerts(status);
CREATE INDEX idx_alerts_env ON alerts(env);
CREATE INDEX idx_alerts_host ON alerts(host);
