-- internal/migrations/postgres/003_rules.sql
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

CREATE INDEX idx_rules_enabled ON rules(enabled);
CREATE INDEX idx_rules_version ON rules(version);
