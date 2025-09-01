-- internal/migrations/postgres/002_alerts.sql
-- Создание таблицы алертов

-- Создание функции для обновления updated_at (если не существует)
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ts TIMESTAMPTZ NOT NULL,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    dedup_key TEXT NOT NULL,
    payload JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'new',
    env TEXT,
    host TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Создание индексов
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts(rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_dedup_key ON alerts(dedup_key);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_env ON alerts(env);
CREATE INDEX IF NOT EXISTS idx_alerts_host ON alerts(host);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);

-- Создание составного индекса для эффективного поиска
CREATE INDEX IF NOT EXISTS idx_alerts_rule_severity_ts ON alerts(rule_id, severity, ts);

-- Создание индекса для JSONB поля
CREATE INDEX IF NOT EXISTS idx_alerts_payload_gin ON alerts USING GIN (payload);

-- Создание триггера для автоматического обновления updated_at
CREATE TRIGGER update_alerts_updated_at 
    BEFORE UPDATE ON alerts 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Создание таблицы для истории изменений статуса алертов
CREATE TABLE IF NOT EXISTS alert_status_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id UUID NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    old_status TEXT,
    new_status TEXT NOT NULL,
    changed_by TEXT,
    reason TEXT,
    changed_at TIMESTAMPTZ DEFAULT NOW()
);

-- Создание индексов для истории
CREATE INDEX IF NOT EXISTS idx_alert_status_history_alert_id ON alert_status_history(alert_id);
CREATE INDEX IF NOT EXISTS idx_alert_status_history_changed_at ON alert_status_history(changed_at);

-- Создание представления для активных алертов
CREATE OR REPLACE VIEW active_alerts AS
SELECT 
    a.*,
    CASE 
        WHEN a.status = 'new' THEN 1
        WHEN a.status = 'acknowledged' THEN 2
        WHEN a.status = 'resolved' THEN 3
        ELSE 4
    END as priority_order
FROM alerts a
WHERE a.status IN ('new', 'acknowledged')
ORDER BY a.severity DESC, a.ts DESC;

-- Создание представления для статистики алертов
CREATE OR REPLACE VIEW alert_stats AS
SELECT 
    DATE_TRUNC('hour', ts) as hour,
    rule_id,
    severity,
    status,
    COUNT(*) as count
FROM alerts
GROUP BY DATE_TRUNC('hour', ts), rule_id, severity, status
ORDER BY hour DESC, rule_id, severity, status;
