# NovaSec - SIEM/HIDS Platform

[![Go Version](https://img.shields.io/badge/Go-1.22+-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)]()

**NovaSec** — это современная платформа для Security Information and Event Management (SIEM) и Host-based Intrusion Detection System (HIDS), разработанная как альтернатива Wazuh с упрощенной установкой и удобным использованием.

## 🚀 Особенности

- **Микросервисная архитектура** на Go 1.22+
- **NATS JetStream** для надежной доставки сообщений
- **ClickHouse** для высокопроизводительного хранения событий
- **PostgreSQL** для метаданных и конфигурации
- **mTLS** для безопасной коммуникации между агентами и сервисами
- **NDJSON** формат для эффективной передачи событий
- **DSL правила** для гибкой корреляции событий
- **Автоматические алерты** с подавлением дубликатов
- **REST API** для администрирования и мониторинга

## 🏗️ Архитектура

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Agent     │    │  Collector  │    │   Ingest    │
│             │───▶│             │───▶│   Service   │
└─────────────┘    └─────────────┘    └─────────────┘
                                              │
                                              ▼
                                    ┌─────────────┐
                                    │    NATS     │
                                    │  JetStream  │
                                    └─────────────┘
                                              │
                    ┌─────────────────────────┼─────────────────────────┐
                    ▼                         ▼                         ▼
            ┌─────────────┐         ┌─────────────┐         ┌─────────────┐
            │ Normalizer  │         │ Correlator  │         │  Alerting   │
            │  Service    │         │  Service    │         │  Service    │
            └─────────────┘         └─────────────┘         └─────────────┘
                    │                         │                         │
                    ▼                         ▼                         ▼
            ┌─────────────┐         ┌─────────────┐         ┌─────────────┐
            │ ClickHouse  │         │PostgreSQL   │         │   Admin     │
            │  (Events)   │         │ (Metadata)  │         │    API      │
            └─────────────┘         └─────────────┘         └─────────────┘
```

## 📋 Требования

- **Go 1.22+**
- **Docker & Docker Compose**
- **OpenSSL** (для генерации сертификатов)
- **4GB RAM** (минимум)
- **20GB свободного места**

## 🚀 Быстрый старт

### 1. Клонирование репозитория

```bash
git clone https://github.com/novasec/novasec.git
cd novasec
```

### 2. Инициализация проекта

```bash
make init
```

### 3. Генерация TLS сертификатов

```bash
make certs
```

### 4. Сборка сервисов

```bash
make build
```

### 5. Запуск через Docker Compose

```bash
make run
```

### 6. Проверка статуса

```bash
make status
```

## 📖 Подробная установка

### Предварительные требования

1. **Установите Go 1.22+**
   ```bash
   # macOS
   brew install go
   
   # Ubuntu/Debian
   sudo apt update
   sudo apt install golang-go
   
   # Проверка версии
   go version
   ```

2. **Установите Docker & Docker Compose**
   ```bash
   # macOS
   brew install docker docker-compose
   
   # Ubuntu/Debian
   curl -fsSL https://get.docker.com -o get-docker.sh
   sudo sh get-docker.sh
   sudo usermod -aG docker $USER
   ```

3. **Установите OpenSSL**
   ```bash
   # macOS
   brew install openssl
   
   # Ubuntu/Debian
   sudo apt install openssl
   ```

### Конфигурация

1. **Скопируйте примеры конфигурации**
   ```bash
   cp configs/ingest.example.yml configs/ingest.yml
   cp configs/services.example.yml configs/services.yml
   ```

2. **Отредактируйте конфигурацию**
   ```bash
   # Настройте адреса сервисов, пароли и другие параметры
   nano configs/ingest.yml
   nano configs/services.yml
   ```

3. **Сгенерируйте сертификаты**
   ```bash
   make certs
   ```

### Сборка и запуск

1. **Соберите все сервисы**
   ```bash
   make build
   ```

2. **Запустите инфраструктуру**
   ```bash
   make run
   ```

3. **Проверьте статус**
   ```bash
   make status
   ```

4. **Просмотрите логи**
   ```bash
   make logs
   ```

## 🔧 Использование

### Отправка событий

```bash
# Пример отправки события через ingest API
curl -X POST http://localhost:8080/api/v1/ingest \
  -H "Content-Type: application/x-ndjson" \
  -H "X-Agent-Id: agent-001" \
  -d '{"ts":"2024-01-15T10:30:00Z","host":"server-01","category":"auth","subtype":"login","message":"Failed login attempt","severity":"high"}'
```

### Проверка алертов

```bash
# Получение списка алертов
curl http://localhost:8081/api/v1/alerts

# Получение алертов по фильтру
curl "http://localhost:8081/api/v1/alerts?severity=high&from=2024-01-15T00:00:00Z"
```

### Управление правилами

```bash
# Получение списка правил
curl http://localhost:8081/api/v1/rules

# Загрузка нового правила
curl -X POST http://localhost:8081/api/v1/rules \
  -H "Content-Type: application/yaml" \
  -d @internal/rules/login_bruteforce.yml

# Тестирование правила
curl -X POST http://localhost:8081/api/v1/rules/test \
  -H "Content-Type: application/json" \
  -d '{"rule_id":"login_bruteforce","events_fixture":"internal/fixtures/ssh_11_failed.jsonl"}'
```

## 📊 Мониторинг

### Prometheus метрики

- **URL**: http://localhost:9090
- **Метрики**: События, алерты, производительность сервисов

### Grafana дашборды

- **URL**: http://localhost:3000
- **Логин**: admin/admin
- **Дашборды**: Обзор системы, события, алерты

### Health checks

```bash
# Ingest Service
curl http://localhost:8080/api/v1/health

# Admin API
curl http://localhost:8081/api/v1/health

# NATS
curl http://localhost:8222/healthz

# ClickHouse
curl http://localhost:8123/ping

# PostgreSQL
docker exec novasec-postgres pg_isready -U novasec
```

## 🛠️ Разработка

### Структура проекта

```
novasec/
├── cmd/                    # Основные исполняемые файлы
│   ├── ingest/            # Сервис приема событий
│   ├── normalizer/        # Сервис нормализации
│   ├── correlator/        # Сервис корреляции
│   ├── alerting/          # Сервис уведомлений
│   └── adminapi/          # Административный API
├── internal/               # Внутренние пакеты
│   ├── common/            # Общие утилиты
│   ├── models/            # Модели данных
│   ├── ingest/            # Логика ingest
│   ├── normalizer/        # Логика нормализации
│   ├── correlator/        # Логика корреляции
│   ├── alerting/          # Логика уведомлений
│   └── adminapi/          # Логика админ API
├── configs/                # Конфигурационные файлы
├── docker/                 # Docker конфигурация
├── scripts/                # Скрипты утилиты
└── docs/                   # Документация
```

### Команды разработки

```bash
# Установка зависимостей для разработки
make dev-deps

# Запуск тестов
make test

# Запуск тестов с покрытием
make test-coverage

# Проверка кода
make lint

# Форматирование кода
make fmt

# Запуск в режиме отладки
make debug
```

### Добавление нового правила

1. **Создайте YAML файл правила**
   ```yaml
   # internal/rules/example.yml
   id: "example_rule"
   name: "Example Rule"
   description: "Example correlation rule"
   severity: "medium"
   window: "5m"
   group_by: ["host", "user"]
   threshold: 5
   suppress: "15m"
   actions: ["alert"]
   conditions:
     - field: "category"
       operator: "equals"
       value: "auth"
   ```

2. **Загрузите правило через API**
   ```bash
   curl -X POST http://localhost:8081/api/v1/rules \
     -H "Content-Type: application/yaml" \
     -d @internal/rules/example.yml
   ```

3. **Протестируйте правило**
   ```bash
   curl -X POST http://localhost:8081/api/v1/rules/test \
     -H "Content-Type: application/json" \
     -d '{"rule_id":"example_rule","events_fixture":"internal/fixtures/test_events.jsonl"}'
   ```

## 🔒 Безопасность

### TLS сертификаты

- **Автоматическая генерация**: `make certs`
- **mTLS**: Взаимная аутентификация между сервисами
- **Ротация**: Рекомендуется обновлять сертификаты каждые 90 дней

### Аутентификация

- **Агенты**: Сертификаты клиентов
- **API**: JWT токены (в разработке)
- **База данных**: Пароли и SSL

### Сетевая безопасность

- **Firewall**: Ограничьте доступ к портам
- **VPN**: Рекомендуется для удаленного доступа
- **Мониторинг**: Логирование всех подключений

## 📈 Производительность

### Рекомендуемые характеристики

- **CPU**: 4+ ядра
- **RAM**: 8GB+ (16GB для продакшена)
- **Storage**: SSD для ClickHouse, HDD для PostgreSQL
- **Network**: 1Gbps+ для высоконагруженных систем

### Масштабирование

- **Горизонтальное**: Добавление инстансов сервисов
- **Вертикальное**: Увеличение ресурсов
- **Шардинг**: Разделение данных по хостам

### Мониторинг производительности

```bash
# Мониторинг ресурсов Docker
make monitor

# Логи производительности
make logs-ingest | grep "duration_ms"
make logs-correlator | grep "events_processed"
```

## 🚨 Устранение неполадок

### Частые проблемы

1. **Сервис не запускается**
   ```bash
   # Проверьте логи
   make logs-ingest
   
   # Проверьте конфигурацию
   make check-config
   
   # Проверьте зависимости
   make status
   ```

2. **Ошибки подключения к базе данных**
   ```bash
   # Проверьте статус PostgreSQL
   docker exec novasec-postgres pg_isready -U novasec
   
   # Проверьте логи PostgreSQL
   docker logs novasec-postgres
   ```

3. **Проблемы с NATS**
   ```bash
   # Проверьте статус NATS
   curl http://localhost:8222/healthz
   
   # Проверьте логи NATS
   docker logs novasec-nats
   ```

### Логи и отладка

```bash
# Логи конкретного сервиса
make logs-ingest
make logs-correlator
make logs-alerting

# Логи инфраструктуры
docker logs novasec-clickhouse
docker logs novasec-postgres
docker logs novasec-redis
```

### Восстановление

```bash
# Перезапуск сервиса
docker restart novasec-ingest

# Перезапуск всей системы
make stop
make run

# Полная очистка
make clean-all
make init
make certs
make build
make run
```

## 📚 Документация

- [API Reference](docs/api.md)
- [Configuration Guide](docs/configuration.md)
- [Rule DSL Reference](docs/rules.md)
- [Deployment Guide](docs/deployment.md)
- [Troubleshooting](docs/troubleshooting.md)

## 🤝 Вклад в проект

1. Fork репозитория
2. Создайте feature branch (`git checkout -b feature/amazing-feature`)
3. Commit изменения (`git commit -m 'Add amazing feature'`)
4. Push в branch (`git push origin feature/amazing-feature`)
5. Откройте Pull Request

### Требования к коду

- Go 1.22+
- Покрытие тестами >80%
- Соответствие линтеру
- Документированные публичные API

## 📄 Лицензия

Этот проект лицензирован под MIT License - см. файл [LICENSE](LICENSE) для деталей.

## 🆘 Поддержка

- **Issues**: [GitHub Issues](https://github.com/novasec/novasec/issues)
- **Discussions**: [GitHub Discussions](https://github.com/novasec/novasec/discussions)
- **Wiki**: [GitHub Wiki](https://github.com/novasec/novasec/wiki)

## 🙏 Благодарности

- [NATS](https://nats.io/) - Система обмена сообщениями
- [ClickHouse](https://clickhouse.com/) - Аналитическая СУБД
- [PostgreSQL](https://www.postgresql.org/) - Реляционная СУБД
- [Go](https://golang.org/) - Язык программирования

---

**NovaSec** - Защита вашей инфраструктуры, упрощенная и эффективная.
