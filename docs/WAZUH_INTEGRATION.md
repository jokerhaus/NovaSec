# filename: docs/WAZUH_INTEGRATION.md
# Интеграция Wazuh агента с NovaSec

## Обзор

NovaSec поддерживает интеграцию с Wazuh агентом для сбора и анализа событий безопасности. Wazuh агент собирает различные типы событий безопасности, включая аутентификацию, файловую целостность, сетевые события и многое другое.

## Архитектура интеграции

```
Wazuh Agent -> NovaSec Ingest -> Normalizer -> Correlator -> Alerting
```

1. **Wazuh Agent** - собирает события безопасности с хоста
2. **NovaSec Ingest** - принимает события от Wazuh агента
3. **Normalizer** - парсит и нормализует события Wazuh
4. **Correlator** - применяет правила корреляции
5. **Alerting** - отправляет уведомления о сработавших правилах

## Поддерживаемые типы событий

### Аутентификация
- SSH неудачные попытки входа
- SSH успешные входы
- Sudo команды
- Su команды
- PAM аутентификация

### Файловая целостность (FIM)
- Создание файлов
- Изменение файлов
- Удаление файлов
- Изменение прав доступа

### Сетевые события
- Блокировки файрвола
- Сетевые подключения
- Подозрительный трафик

### Malware
- Обнаружение вредоносного ПО
- Вирусные угрозы

### Системные события
- Windows Event Log
- Linux системные события
- Веб-серверы (Apache, Nginx)
- Базы данных

## Установка и настройка

### 1. Использование Docker Compose

Самый простой способ - использовать готовый Docker Compose файл:

```bash
# Клонируем репозиторий
git clone https://github.com/your-org/novasec.git
cd novasec

# Запускаем все сервисы включая Wazuh агент
docker-compose -f docker/docker-compose.yml up -d
```

### 2. Ручная установка Wazuh агента

#### На Ubuntu/Debian:

```bash
# Добавляем репозиторий Wazuh
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list

# Устанавливаем агент
sudo apt-get update
sudo apt-get install wazuh-agent=4.7.0-1

# Настраиваем агент
sudo /var/ossec/bin/agent-auth -m <WAZUH_MANAGER_IP>
sudo systemctl start wazuh-agent
sudo systemctl enable wazuh-agent
```

#### На CentOS/RHEL:

```bash
# Добавляем репозиторий Wazuh
rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
cat > /etc/yum.repos.d/wazuh.repo << EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-\$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF

# Устанавливаем агент
yum install wazuh-agent-4.7.0-1

# Настраиваем агент
/var/ossec/bin/agent-auth -m <WAZUH_MANAGER_IP>
systemctl start wazuh-agent
systemctl enable wazuh-agent
```

### 3. Настройка интеграции с NovaSec

#### Конфигурация Wazuh агента

Отредактируйте файл `/var/ossec/etc/ossec.conf`:

```xml
<ossec_config>
  <client>
    <server-hostname>NOVASEC_INGEST_IP</server-hostname>
    <server-ip>NOVASEC_INGEST_IP</server-ip>
    <config-profile>ubuntu, ubuntu18, ubuntu18.04</config-profile>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
    <crypto_method>aes</crypto_method>
  </client>

  <!-- Настройки для отправки в NovaSec -->
  <integration>
    <name>novasec</name>
    <hook_url>http://NOVASEC_INGEST_IP:8080/api/v1/events</hook_url>
    <level>3</level>
    <group>authentication,file_integrity,network,malware</group>
  </integration>
</ossec_config>
```

#### Конфигурация NovaSec

Обновите файл `configs/ingest.yml`:

```yaml
# Настройки Wazuh агента
wazuh:
  enabled: true
  manager_host: "localhost"
  manager_port: 1514
  agent_name: "novasec-agent"
  agent_group: "default"
  registration_password: ""
  keep_alive_interval: "60s"
  reconnect_interval: "30s"
  max_reconnect_attempts: 10
  log_level: "info"
  # Настройки для интеграции с NovaSec
  novasec:
    enabled: true
    endpoint: "http://localhost:8080/api/v1/events"
    api_key: ""
    timeout: "30s"
    batch_size: 100
    batch_timeout: "5s"
    retry_attempts: 3
    retry_delay: "1s"
```

## Мониторинг и отладка

### Проверка статуса Wazuh агента

```bash
# Проверка статуса сервиса
sudo systemctl status wazuh-agent

# Просмотр логов
sudo tail -f /var/ossec/logs/ossec.log

# Просмотр алертов
sudo tail -f /var/ossec/logs/alerts/alerts.log
```

### Проверка интеграции с NovaSec

```bash
# Проверка логов NovaSec Ingest
docker logs novasec-ingest

# Проверка логов Normalizer
docker logs novasec-normalizer

# Проверка метрик
curl http://localhost:9090/metrics
```

### Тестирование парсера Wazuh

```bash
# Запуск тестов
cd /path/to/novasec
go test ./internal/normalizer/parsers/ -v -run TestWazuhParser

# Тестирование с примером события
curl -X POST http://localhost:8080/api/v1/events \
  -H "Content-Type: application/json" \
  -d @internal/fixtures/wazuh_sample_events.jsonl
```

## Правила корреляции для Wazuh

### SSH Brute Force Detection

```yaml
# internal/rules/ssh_bruteforce_wazuh.yml
id: "ssh_bruteforce_wazuh"
name: "SSH Brute Force Detection (Wazuh)"
severity: "high"
description: "Detects multiple failed SSH login attempts from Wazuh"
enabled: true
window:
  duration: 5m
  sliding: true
threshold:
  count: 5
  type: unique
  field: src_ip
conditions:
  - field: "source"
    operator: "equals"
    value: "wazuh"
  - field: "subtype"
    operator: "equals"
    value: "ssh_login_failed"
  - field: "src_ip"
    operator: "count_unique"
    value: "5"
actions:
  - type: "alert"
    config:
      severity: "high"
      message: "Multiple failed SSH login attempts detected from {{src_ip}}"
```

### File Integrity Monitoring

```yaml
# internal/rules/fim_critical_wazuh.yml
id: "fim_critical_wazuh"
name: "Critical File Changes (Wazuh)"
severity: "critical"
description: "Detects changes to critical system files from Wazuh"
enabled: true
window:
  duration: 1m
  sliding: false
threshold:
  count: 1
  type: count
  field: file_path
conditions:
  - field: "source"
    operator: "equals"
    value: "wazuh"
  - field: "category"
    operator: "equals"
    value: "file_integrity"
  - field: "file_path"
    operator: "matches"
    value: "/etc/(passwd|shadow|sudoers|hosts|resolv.conf)"
actions:
  - type: "alert"
    config:
      severity: "critical"
      message: "Critical system file {{file_path}} was modified"
```

## Производительность и масштабирование

### Рекомендации по производительности

1. **Batch размер**: Настройте `batch_size` в зависимости от нагрузки
2. **Timeout**: Увеличьте `timeout` для медленных сетей
3. **Retry**: Настройте `retry_attempts` и `retry_delay` для надежности
4. **Log level**: Используйте `info` или `warn` в продакшене

### Масштабирование

1. **Множественные агенты**: Каждый хост должен иметь свой Wazuh агент
2. **Load balancing**: Используйте несколько инстансов NovaSec Ingest
3. **Кластеризация**: Настройте кластер Wazuh менеджеров для высокой доступности

## Безопасность

### Рекомендации по безопасности

1. **TLS**: Используйте TLS для связи между агентом и менеджером
2. **API ключи**: Используйте API ключи для аутентификации
3. **Firewall**: Ограничьте доступ к портам Wazuh (1514, 1515)
4. **Обновления**: Регулярно обновляйте Wazuh агент и NovaSec

### Настройка TLS

```xml
<!-- В ossec.conf -->
<ossec_config>
  <client>
    <server-hostname>NOVASEC_INGEST_IP</server-hostname>
    <server-ip>NOVASEC_INGEST_IP</server-ip>
    <crypto_method>aes</crypto_method>
    <server_ca>/var/ossec/etc/rootca.pem</server_ca>
    <server_cert>/var/ossec/etc/sslcert.pem</server_cert>
    <server_key>/var/ossec/etc/sslkey.pem</server_key>
  </client>
</ossec_config>
```

## Устранение неполадок

### Частые проблемы

1. **Агент не подключается к менеджеру**
   - Проверьте сетевую связность
   - Проверьте настройки файрвола
   - Проверьте ключи аутентификации

2. **События не поступают в NovaSec**
   - Проверьте логи Wazuh агента
   - Проверьте логи NovaSec Ingest
   - Проверьте конфигурацию интеграции

3. **Парсер не распознает события**
   - Проверьте формат JSON событий
   - Проверьте логи Normalizer
   - Обновите парсер при необходимости

### Логи для отладки

```bash
# Wazuh агент
sudo tail -f /var/ossec/logs/ossec.log
sudo tail -f /var/ossec/logs/alerts/alerts.log

# NovaSec
docker logs novasec-ingest -f
docker logs novasec-normalizer -f
docker logs novasec-correlator -f
```

## Поддержка

Для получения поддержки:

1. Проверьте документацию Wazuh: https://documentation.wazuh.com/
2. Создайте issue в репозитории NovaSec
3. Обратитесь к команде разработки

## Лицензия

Wazuh агент распространяется под лицензией GPLv2. NovaSec использует Wazuh агент в соответствии с условиями лицензии.
