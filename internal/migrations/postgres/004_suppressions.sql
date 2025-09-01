-- internal/migrations/postgres/004_suppressions.sql
-- Создание таблицы подавлений алертов

-- Создание функции для обновления updated_at (если не существует)
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TABLE IF NOT EXISTS suppressions (
    rule_id TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    until TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    created_by TEXT,
    reason TEXT,
    PRIMARY KEY (rule_id, key_hash)
);

-- Создание индексов
CREATE INDEX IF NOT EXISTS idx_suppressions_rule_id ON suppressions(rule_id);
CREATE INDEX IF NOT EXISTS idx_suppressions_key_hash ON suppressions(key_hash);
CREATE INDEX IF NOT EXISTS idx_suppressions_until ON suppressions(until);
CREATE INDEX IF NOT EXISTS idx_suppressions_created_at ON suppressions(created_at);

-- Создание составного индекса для эффективного поиска
CREATE INDEX IF NOT EXISTS idx_suppressions_rule_until ON suppressions(rule_id, until);

-- Создание таблицы для истории подавлений
CREATE TABLE IF NOT EXISTS suppression_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    action TEXT NOT NULL, -- 'created', 'expired', 'deleted'
    until TIMESTAMPTZ NOT NULL,
    created_by TEXT,
    reason TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Создание индексов для истории
CREATE INDEX IF NOT EXISTS idx_suppression_history_rule_id ON suppression_history(rule_id);
CREATE INDEX IF NOT EXISTS idx_suppression_history_key_hash ON suppression_history(key_hash);
CREATE INDEX IF NOT EXISTS idx_suppression_history_action ON suppression_history(action);
CREATE INDEX IF NOT EXISTS idx_suppression_history_created_at ON suppression_history(created_at);

-- Создание представления для активных подавлений
CREATE OR REPLACE VIEW active_suppressions AS
SELECT 
    s.*,
    r.name as rule_name,
    r.severity as rule_severity,
    EXTRACT(EPOCH FROM (s.until - NOW()))/60 as minutes_remaining
FROM suppressions s
JOIN rules r ON s.rule_id = r.id
WHERE s.until > NOW()
ORDER BY s.until ASC;

-- Создание представления для истекших подавлений
CREATE OR REPLACE VIEW expired_suppressions AS
SELECT 
    s.*,
    r.name as rule_name,
    r.severity as rule_severity,
    EXTRACT(EPOCH FROM (NOW() - s.until))/60 as minutes_expired
FROM suppressions s
JOIN rules r ON s.rule_id = r.id
WHERE s.until <= NOW()
ORDER BY s.until DESC;

-- Создание функции для очистки истекших подавлений
CREATE OR REPLACE FUNCTION cleanup_expired_suppressions()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    -- Удаляем истекшие подавления
    DELETE FROM suppressions 
    WHERE until <= NOW();
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    
    -- Логируем удаление в историю
    INSERT INTO suppression_history (rule_id, key_hash, action, until, created_by, reason)
    SELECT rule_id, key_hash, 'expired', until, created_by, reason
    FROM suppressions 
    WHERE until <= NOW();
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Создание триггера для логирования изменений подавлений
CREATE OR REPLACE FUNCTION log_suppression_changes()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO suppression_history (rule_id, key_hash, action, until, created_by, reason)
        VALUES (NEW.rule_id, NEW.key_hash, 'created', NEW.until, NEW.created_by, NEW.reason);
        RETURN NEW;
    ELSIF TG_OP = 'UPDATE' THEN
        INSERT INTO suppression_history (rule_id, key_hash, action, until, created_by, reason)
        VALUES (NEW.rule_id, NEW.key_hash, 'updated', NEW.until, NEW.created_by, NEW.reason);
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO suppression_history (rule_id, key_hash, action, until, created_by, reason)
        VALUES (OLD.rule_id, OLD.key_hash, 'deleted', OLD.until, OLD.created_by, OLD.reason);
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Создание триггеров
CREATE TRIGGER log_suppression_insert
    AFTER INSERT ON suppressions
    FOR EACH ROW EXECUTE FUNCTION log_suppression_changes();

CREATE TRIGGER log_suppression_update
    AFTER UPDATE ON suppressions
    FOR EACH ROW EXECUTE FUNCTION log_suppression_changes();

CREATE TRIGGER log_suppression_delete
    AFTER DELETE ON suppressions
    FOR EACH ROW EXECUTE FUNCTION log_suppression_changes();

-- Создание функции для проверки активного подавления
CREATE OR REPLACE FUNCTION is_suppressed(p_rule_id TEXT, p_key_hash TEXT)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM suppressions 
        WHERE rule_id = p_rule_id 
        AND key_hash = p_key_hash 
        AND until > NOW()
    );
END;
$$ LANGUAGE plpgsql;

-- Создание функции для добавления подавления
CREATE OR REPLACE FUNCTION add_suppression(
    p_rule_id TEXT,
    p_key_hash TEXT,
    p_duration_minutes INTEGER,
    p_created_by TEXT DEFAULT NULL,
    p_reason TEXT DEFAULT NULL
)
RETURNS BOOLEAN AS $$
BEGIN
    INSERT INTO suppressions (rule_id, key_hash, until, created_by, reason)
    VALUES (p_rule_id, p_key_hash, NOW() + INTERVAL '1 minute' * p_duration_minutes, p_created_by, p_reason)
    ON CONFLICT (rule_id, key_hash) DO UPDATE SET
        until = EXCLUDED.until,
        created_by = EXCLUDED.created_by,
        reason = EXCLUDED.reason;
    
    RETURN TRUE;
EXCEPTION
    WHEN OTHERS THEN
        RETURN FALSE;
END;
$$ LANGUAGE plpgsql;

-- Создание представления для статистики подавлений
CREATE OR REPLACE VIEW suppression_stats AS
SELECT 
    s.rule_id,
    r.name as rule_name,
    r.severity as rule_severity,
    COUNT(*) as active_suppressions,
    MIN(s.until) as earliest_expiry,
    MAX(s.until) as latest_expiry,
    AVG(EXTRACT(EPOCH FROM (s.until - NOW()))/60) as avg_minutes_remaining
FROM suppressions s
JOIN rules r ON s.rule_id = r.id
WHERE s.until > NOW()
GROUP BY s.rule_id, r.name, r.severity
ORDER BY active_suppressions DESC;

-- Создание представления для мониторинга подавлений
CREATE OR REPLACE VIEW suppression_monitoring AS
SELECT 
    'active' as status,
    COUNT(*) as count,
    COUNT(CASE WHEN until <= NOW() + INTERVAL '1 hour' THEN 1 END) as expiring_soon
FROM suppressions 
WHERE until > NOW()

UNION ALL

SELECT 
    'expired' as status,
    COUNT(*) as count,
    0 as expiring_soon
FROM suppressions 
WHERE until <= NOW();

-- Вставка примера подавления для тестирования
INSERT INTO suppressions (rule_id, key_hash, until, created_by, reason) VALUES
('login_bruteforce', 'test_hash_123', NOW() + INTERVAL '1 hour', 'system', 'Test suppression')
ON CONFLICT (rule_id, key_hash) DO NOTHING;
