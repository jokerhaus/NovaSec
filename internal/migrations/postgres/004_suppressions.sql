-- internal/migrations/postgres/004_suppressions.sql
-- Создание таблицы подавлений

CREATE TABLE IF NOT EXISTS suppressions (
    rule_id VARCHAR(255) NOT NULL,
    key_hash VARCHAR(255) NOT NULL,
    until TIMESTAMPTZ NOT NULL,
    created TIMESTAMPTZ DEFAULT NOW(),
    reason VARCHAR(500),
    PRIMARY KEY (rule_id, key_hash)
);

CREATE INDEX idx_suppressions_until ON suppressions(until);
CREATE INDEX idx_suppressions_rule_id ON suppressions(rule_id);
