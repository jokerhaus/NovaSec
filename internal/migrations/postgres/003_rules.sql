-- internal/migrations/postgres/003_rules.sql
-- Создание таблицы правил корреляции

-- Создание функции для обновления updated_at (если не существует)
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TABLE IF NOT EXISTS rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    yaml TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Создание индексов
CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled);
CREATE INDEX IF NOT EXISTS idx_rules_version ON rules(version);
CREATE INDEX IF NOT EXISTS idx_rules_created_at ON rules(created_at);
CREATE INDEX IF NOT EXISTS idx_rules_updated_at ON rules(updated_at);

-- Создание триггера для автоматического обновления updated_at
CREATE TRIGGER update_rules_updated_at 
    BEFORE UPDATE ON rules 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Создание таблицы для версионирования правил
CREATE TABLE IF NOT EXISTS rule_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id TEXT NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    yaml TEXT NOT NULL,
    enabled BOOLEAN NOT NULL,
    created_by TEXT,
    change_reason TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Создание уникального индекса для версий правил
CREATE UNIQUE INDEX IF NOT EXISTS idx_rule_versions_rule_version ON rule_versions(rule_id, version);

-- Создание индексов для версий
CREATE INDEX IF NOT EXISTS idx_rule_versions_created_at ON rule_versions(created_at);
CREATE INDEX IF NOT EXISTS idx_rule_versions_enabled ON rule_versions(enabled);

-- Создание таблицы для метаданных правил
CREATE TABLE IF NOT EXISTS rule_metadata (
    rule_id TEXT PRIMARY KEY REFERENCES rules(id) ON DELETE CASCADE,
    description TEXT,
    tags TEXT[],
    category TEXT,
    mitre_technique TEXT,
    priority INTEGER DEFAULT 1,
    author TEXT,
    references TEXT[],
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Создание индексов для метаданных
CREATE INDEX IF NOT EXISTS idx_rule_metadata_category ON rule_metadata(category);
CREATE INDEX IF NOT EXISTS idx_rule_metadata_priority ON rule_metadata(priority);
CREATE INDEX IF NOT EXISTS idx_rule_metadata_tags ON rule_metadata USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_rule_metadata_mitre ON rule_metadata(mitre_technique);

-- Создание триггера для метаданных
CREATE TRIGGER update_rule_metadata_updated_at 
    BEFORE UPDATE ON rule_metadata 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Создание представления для активных правил с метаданными
CREATE OR REPLACE VIEW active_rules AS
SELECT 
    r.*,
    rm.description,
    rm.tags,
    rm.category,
    rm.mitre_technique,
    rm.priority,
    rm.author,
    rm.references
FROM rules r
LEFT JOIN rule_metadata rm ON r.id = rm.rule_id
WHERE r.enabled = true
ORDER BY rm.priority DESC, r.created_at DESC;

-- Создание представления для статистики правил
CREATE OR REPLACE VIEW rule_stats AS
SELECT 
    r.id,
    r.name,
    r.enabled,
    rm.category,
    rm.priority,
    COUNT(a.id) as alert_count,
    MAX(a.ts) as last_alert_ts
FROM rules r
LEFT JOIN rule_metadata rm ON r.id = rm.rule_id
LEFT JOIN alerts a ON r.id = a.rule_id
GROUP BY r.id, r.name, r.enabled, rm.category, rm.priority
ORDER BY alert_count DESC, rm.priority DESC;

-- Вставка базовых правил
INSERT INTO rules (id, name, version, yaml, enabled) VALUES
('login_bruteforce', 'SSH Login Bruteforce Detection', 1, 
'id: "login_bruteforce"
name: "SSH Login Bruteforce Detection"
description: "Обнаруживает множественные неудачные попытки входа по SSH с одного IP адреса"
severity: "high"
enabled: true
window:
  duration: "5m"
  sliding: true
group_by: ["src_ip", "host"]
threshold:
  count: 10
  type: "count"
  field: ""
suppress:
  duration: "15m"
  key: "rule_id + src_ip + host"
conditions:
  - field: "category"
    operator: "equals"
    value: "auth"
    invert: false
  - field: "subtype"
    operator: "equals"
    value: "login"
    invert: false
  - field: "severity"
    operator: "equals"
    value: "high"
    invert: false
  - field: "message"
    operator: "contains"
    value: "Failed password"
    invert: false
actions:
  - type: "alert"
    config:
      title: "SSH Bruteforce Attack Detected"
      description: "Multiple failed SSH login attempts detected"
    delay: "0s"
    retry: 3
    timeout: "30s"
  - type: "notify"
    config:
      channels: ["email", "telegram"]
      template: "ssh_bruteforce"
    delay: "0s"
    retry: 2
    timeout: "10s"
metadata:
  tags: ["ssh", "bruteforce", "auth"]
  references:
    - "https://attack.mitre.org/techniques/T1110/"
    - "https://attack.mitre.org/techniques/T1110/001/"
  priority: 1
  category: "authentication"
  mitre_technique: "T1110.001"', true),

('fim_critical', 'Critical File Integrity Monitoring', 1,
'id: "fim_critical"
name: "Critical File Integrity Monitoring"
description: "Обнаруживает изменения критически важных системных файлов"
severity: "critical"
enabled: true
window:
  duration: "1m"
  sliding: false
group_by: ["host", "file_path", "sha256"]
threshold:
  count: 1
  type: "count"
  field: ""
suppress:
  duration: "2m"
  key: "rule_id + host + file_path + sha256"
conditions:
  - field: "category"
    operator: "equals"
    value: "file"
    invert: false
  - field: "subtype"
    operator: "equals"
    value: "modify"
    invert: false
  - field: "file_path"
    operator: "in"
    value: "/etc/shadow,/etc/sudoers,/etc/passwd,/etc/group"
    invert: false
actions:
  - type: "alert"
    config:
      title: "Critical File Modification Detected"
      description: "Critical system file has been modified"
      severity: "critical"
    delay: "0s"
    retry: 3
    timeout: "30s"
  - type: "notify"
    config:
      channels: ["email", "telegram", "webhook"]
      template: "fim_critical"
      immediate: true
    delay: "0s"
    retry: 2
    timeout: "10s"
  - type: "block"
    config:
      action: "isolate_host"
      duration: "1h"
    delay: "0s"
    retry: 1
    timeout: "5s"
metadata:
  tags: ["fim", "file_integrity", "critical", "system"]
  references:
    - "https://attack.mitre.org/techniques/T1005/"
    - "https://attack.mitre.org/techniques/T1005/001/"
  priority: 1
  category: "file_integrity"
  mitre_technique: "T1005.001"
  response_time: "immediate"', true)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    version = EXCLUDED.version,
    yaml = EXCLUDED.yaml,
    enabled = EXCLUDED.enabled,
    updated_at = NOW();

-- Вставка метаданных для правил
INSERT INTO rule_metadata (rule_id, description, tags, category, mitre_technique, priority, author, references) VALUES
('login_bruteforce', 'Обнаруживает множественные неудачные попытки входа по SSH с одного IP адреса', 
 ARRAY['ssh', 'bruteforce', 'auth'], 'authentication', 'T1110.001', 1, 'NovaSec Team',
 ARRAY['https://attack.mitre.org/techniques/T1110/', 'https://attack.mitre.org/techniques/T1110/001/']),
('fim_critical', 'Обнаруживает изменения критически важных системных файлов', 
 ARRAY['fim', 'file_integrity', 'critical', 'system'], 'file_integrity', 'T1005.001', 1, 'NovaSec Team',
 ARRAY['https://attack.mitre.org/techniques/T1005/', 'https://attack.mitre.org/techniques/T1005/001/'])
ON CONFLICT (rule_id) DO UPDATE SET
    description = EXCLUDED.description,
    tags = EXCLUDED.tags,
    category = EXCLUDED.category,
    mitre_technique = EXCLUDED.mitre_technique,
    priority = EXCLUDED.priority,
    author = EXCLUDED.author,
    references = EXCLUDED.references,
    updated_at = NOW();
