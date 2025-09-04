# Makefile
# NovaSec SIEM/HIDS Platform

# Переменные
BINARY_DIR = bin
DOCKER_COMPOSE = docker/docker-compose.yml
VERSION = 1.0.0
GO_VERSION = 1.22

# Цвета для вывода
RED = \033[0;31m
GREEN = \033[0;32m
YELLOW = \033[1;33m
BLUE = \033[0;34m
NC = \033[0m # No Color

# Функции для вывода
define log_info
	@echo -e "$(BLUE)[INFO]$(NC) $1"
endef

define log_success
	@echo -e "$(GREEN)[SUCCESS]$(NC) $1"
endef

define log_warning
	@echo -e "$(YELLOW)[WARNING]$(NC) $1"
endef

define log_error
	@echo -e "$(RED)[ERROR]$(NC) $1"
endef

# Цели по умолчанию
.PHONY: help
help: ## Показать справку
	@echo "NovaSec SIEM/HIDS Platform - Makefile"
	@echo "====================================="
	@echo ""
	@echo "Доступные цели:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Примеры использования:"
	@echo "  make deps          # Установить зависимости"
	@echo "  make build         # Собрать все сервисы"
	@echo "  make run           # Запустить через docker-compose"
	@echo "  make test          # Запустить тесты"
	@echo "  make clean         # Очистить артефакты сборки"

# Проверка зависимостей
.PHONY: check-deps
check-deps: ## Проверить наличие необходимых зависимостей
	$(call log_info,"Проверяем зависимости...")
	@command -v go >/dev/null 2>&1 || { echo -e "$(RED)Go не установлен$(NC)"; exit 1; }
	@command -v docker >/dev/null 2>&1 || { echo -e "$(RED)Docker не установлен$(NC)"; exit 1; }
	@command -v docker-compose >/dev/null 2>&1 || { echo -e "$(RED)Docker Compose не установлен$(NC)"; exit 1; }
	@command -v openssl >/dev/null 2>&1 || { echo -e "$(YELLOW)OpenSSL не установлен (нужен для генерации сертификатов)$(NC)"; }
	$(call log_success,"Все зависимости проверены")

# Установка зависимостей Go
.PHONY: deps
deps: check-deps ## Установить/обновить Go зависимости
	$(call log_info,"Устанавливаем Go зависимости...")
	@go mod download
	@go mod tidy
	@go mod verify
	$(call log_success,"Go зависимости установлены")

# Сборка всех сервисов
.PHONY: build
build: deps ## Собрать все сервисы
	$(call log_info,"Собираем все сервисы...")
	@mkdir -p $(BINARY_DIR)
	
	$(call log_info,"Собираем ingest сервис...")
	@go build -o $(BINARY_DIR)/novasec-ingest ./cmd/ingest
	
	$(call log_info,"Собираем normalizer сервис...")
	@go build -o $(BINARY_DIR)/novasec-normalizer ./cmd/normalizer
	
	$(call log_info,"Собираем correlator сервис...")
	@go build -o $(BINARY_DIR)/novasec-correlator ./cmd/correlator
	
	$(call log_info,"Собираем alerting сервис...")
	@go build -o $(BINARY_DIR)/novasec-alerting ./cmd/alerting
	
	$(call log_info,"Собираем adminapi сервис...")
	@go build -o $(BINARY_DIR)/novasec-adminapi ./cmd/adminapi
	
	$(call log_success,"Все сервисы собраны в директории $(BINARY_DIR)")

# Сборка отдельного сервиса
.PHONY: build-ingest build-normalizer build-correlator build-alerting build-adminapi
build-ingest: deps ## Собрать ingest сервис
	$(call log_info,"Собираем ingest сервис...")
	@mkdir -p $(BINARY_DIR)
	@go build -o $(BINARY_DIR)/novasec-ingest ./cmd/ingest
	$(call log_success,"Ingest сервис собран")

build-normalizer: deps ## Собрать normalizer сервис
	$(call log_info,"Собираем normalizer сервис...")
	@mkdir -p $(BINARY_DIR)
	@go build -o $(BINARY_DIR)/novasec-normalizer ./cmd/normalizer
	$(call log_success,"Normalizer сервис собран")

build-correlator: deps ## Собрать correlator сервис
	$(call log_info,"Собираем correlator сервис...")
	@mkdir -p $(BINARY_DIR)
	@go build -o $(BINARY_DIR)/novasec-correlator ./cmd/correlator
	$(call log_success,"Correlator сервис собран")

build-alerting: deps ## Собрать alerting сервис
	$(call log_info,"Собираем alerting сервис...")
	@mkdir -p $(BINARY_DIR)
	@go build -o $(BINARY_DIR)/novasec-alerting ./cmd/alerting
	$(call log_success,"Alerting сервис собран")

build-adminapi: deps ## Собрать adminapi сервис
	$(call log_info,"Собираем adminapi сервис...")
	@mkdir -p $(BINARY_DIR)
	@go build -o $(BINARY_DIR)/novasec-adminapi ./cmd/adminapi
	$(call log_success,"AdminAPI сервис собран")

# Генерация сертификатов
.PHONY: certs
certs: ## Сгенерировать TLS сертификаты
	$(call log_info,"Генерируем TLS сертификаты...")
	@chmod +x scripts/gen-certs.sh
	@./scripts/gen-certs.sh
	$(call log_success,"TLS сертификаты сгенерированы")

# Запуск через docker-compose
.PHONY: run
run: ## Запустить через docker-compose
	$(call log_info,"Запускаем NovaSec через docker-compose...")
	@docker-compose -f $(DOCKER_COMPOSE) up -d
	$(call log_success,"NovaSec запущен")
	$(call log_info,"Проверьте статус: make status")

# Остановка docker-compose
.PHONY: stop
stop: ## Остановить docker-compose
	$(call log_info,"Останавливаем NovaSec...")
	@docker-compose -f $(DOCKER_COMPOSE) down
	$(call log_success,"NovaSec остановлен")

# Статус сервисов
.PHONY: status
status: ## Показать статус сервисов
	$(call log_info,"Статус сервисов NovaSec:")
	@docker-compose -f $(DOCKER_COMPOSE) ps

# Логи сервисов
.PHONY: logs
logs: ## Показать логи всех сервисов
	@docker-compose -f $(DOCKER_COMPOSE) logs -f

# Логи конкретного сервиса
.PHONY: logs-ingest logs-normalizer logs-correlator logs-alerting logs-adminapi logs-wazuh
logs-ingest: ## Показать логи ingest сервиса
	@docker-compose -f $(DOCKER_COMPOSE) logs -f novasec-ingest

logs-normalizer: ## Показать логи normalizer сервиса
	@docker-compose -f $(DOCKER_COMPOSE) logs -f novasec-normalizer

logs-correlator: ## Показать логи correlator сервиса
	@docker-compose -f $(DOCKER_COMPOSE) logs -f novasec-correlator

logs-alerting: ## Показать логи alerting сервиса
	@docker-compose -f $(DOCKER_COMPOSE) logs -f novasec-alerting

logs-adminapi: ## Показать логи adminapi сервиса
	@docker-compose -f $(DOCKER_COMPOSE) logs -f novasec-adminapi

logs-wazuh: ## Показать логи Wazuh агента
	@docker-compose -f $(DOCKER_COMPOSE) logs -f wazuh-agent

# Запуск тестов
.PHONY: test
test: deps ## Запустить Go тесты
	$(call log_info,"Запускаем тесты...")
	@go test -v ./...
	$(call log_success,"Тесты завершены")

# Запуск тестов с покрытием
.PHONY: test-coverage
test-coverage: deps ## Запустить тесты с покрытием кода
	$(call log_info,"Запускаем тесты с покрытием...")
	@go test -v -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	$(call log_success,"Тесты с покрытием завершены")
	$(call log_info,"Отчет о покрытии: coverage.html")

# Запуск бенчмарков
.PHONY: bench
bench: deps ## Запустить бенчмарки
	$(call log_info,"Запускаем бенчмарки...")
	@go test -bench=. -benchmem ./...
	$(call log_success,"Бенчмарки завершены")

# Применение миграций
.PHONY: migrate
migrate: ## Применить миграции ClickHouse и PostgreSQL
	$(call log_info,"Применяем миграции...")
	@echo "ClickHouse миграции:"
	@ls -la internal/migrations/clickhouse/
	@echo ""
	@echo "PostgreSQL миграции:"
	@ls -la internal/migrations/postgres/
	$(call log_info,"Миграции готовы к применению")
	$(call log_warning,"Для применения миграций запустите сервисы: make run")

# Проверка кода
.PHONY: lint
lint: deps ## Проверить код линтером
	$(call log_info,"Проверяем код линтером...")
	@go vet ./...
	@go fmt ./...
	$(call log_success,"Проверка кода завершена")

# Форматирование кода
.PHONY: fmt
fmt: ## Отформатировать код
	$(call log_info,"Форматируем код...")
	@go fmt ./...
	$(call log_success,"Код отформатирован")

# Очистка
.PHONY: clean
clean: ## Очистить артефакты сборки
	$(call log_info,"Очищаем артефакты сборки...")
	@rm -rf $(BINARY_DIR)
	@rm -f coverage.out coverage.html
	@go clean -cache
	$(call log_success,"Очистка завершена")

# Полная очистка
.PHONY: clean-all
clean-all: clean ## Полная очистка (включая Docker)
	$(call log_info,"Полная очистка...")
	@docker-compose -f $(DOCKER_COMPOSE) down -v --remove-orphans
	@docker system prune -f
	$(call log_success,"Полная очистка завершена")

# Проверка безопасности
.PHONY: security
security: ## Проверить зависимости на уязвимости
	$(call log_info,"Проверяем зависимости на уязвимости...")
	@go list -m all | grep -E "(github|golang.org)" | head -10
	$(call log_warning,"Для полной проверки используйте: go list -m all")

# Обновление зависимостей
.PHONY: update-deps
update-deps: ## Обновить Go зависимости
	$(call log_info,"Обновляем Go зависимости...")
	@go get -u ./...
	@go mod tidy
	$(call log_success,"Зависимости обновлены")

# Создание релиза
.PHONY: release
release: clean build ## Создать релиз
	$(call log_info,"Создаем релиз v$(VERSION)...")
	@mkdir -p release/v$(VERSION)
	@cp -r $(BINARY_DIR)/* release/v$(VERSION)/
	@cp configs/*.example.yml release/v$(VERSION)/
	@cp -r configs/tls release/v$(VERSION)/
	@cp scripts/gen-certs.sh release/v$(VERSION)/
	@cp docker/docker-compose.yml release/v$(VERSION)/
	@cp README.md LICENSE release/v$(VERSION)/
	@cd release && tar -czf novasec-v$(VERSION).tar.gz v$(VERSION)/
	@rm -rf release/v$(VERSION)
	$(call log_success,"Релиз создан: release/novasec-v$(VERSION).tar.gz")

# Информация о проекте
.PHONY: info
info: ## Показать информацию о проекте
	@echo "NovaSec SIEM/HIDS Platform"
	@echo "=========================="
	@echo "Версия: $(VERSION)"
	@echo "Go версия: $(GO_VERSION)"
	@echo "Архитектура: $(shell go env GOARCH)"
	@echo "ОС: $(shell go env GOOS)"
	@echo ""
	@echo "Сервисы:"
	@echo "  - Ingest (прием событий)"
	@echo "  - Normalizer (нормализация)"
	@echo "  - Correlator (корреляция)"
	@echo "  - Alerting (уведомления)"
	@echo "  - AdminAPI (администрирование)"
	@echo ""
	@echo "Хранилища:"
	@echo "  - ClickHouse (события)"
	@echo "  - PostgreSQL (метаданные)"
	@echo "  - Redis (кэш)"
	@echo ""
	@echo "Коммуникация:"
	@echo "  - NATS JetStream (шина сообщений)"
	@echo "  - HTTP/2 + mTLS (API)"

# Установка зависимостей для разработки
.PHONY: dev-deps
dev-deps: ## Установить зависимости для разработки
	$(call log_info,"Устанавливаем зависимости для разработки...")
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@go install github.com/go-delve/delve/cmd/dlv@latest
	@go install github.com/ramya-rao-a/go-outline@latest
	$(call log_success,"Зависимости для разработки установлены")

# Запуск в режиме отладки
.PHONY: debug
debug: build ## Запустить в режиме отладки
	$(call log_info,"Запускаем в режиме отладки...")
	$(call log_warning,"Используйте dlv для отладки")
	@echo "Пример: dlv exec bin/novasec-ingest -- -config configs/ingest.yml"

# Мониторинг ресурсов
.PHONY: monitor
monitor: ## Мониторинг ресурсов Docker
	$(call log_info,"Мониторинг ресурсов Docker:")
	@docker stats --no-stream

# Резервное копирование
.PHONY: backup
backup: ## Создать резервную копию данных
	$(call log_info,"Создаем резервную копию...")
	@mkdir -p backups/$(shell date +%Y%m%d_%H%M%S)
	$(call log_warning,"Для создания резервной копии остановите сервисы: make stop")
	$(call log_info,"Затем скопируйте данные из Docker volumes")

# Восстановление из резервной копии
.PHONY: restore
restore: ## Восстановить из резервной копии
	$(call log_warning,"Восстановление из резервной копии")
	$(call log_info,"Укажите путь к резервной копии: make restore BACKUP_PATH=/path/to/backup")
	@if [ -z "$(BACKUP_PATH)" ]; then \
		echo "Использование: make restore BACKUP_PATH=/path/to/backup"; \
		exit 1; \
	fi
	$(call log_info,"Восстанавливаем из: $(BACKUP_PATH)")

# Проверка конфигурации
.PHONY: check-config
check-config: ## Проверить конфигурационные файлы
	$(call log_info,"Проверяем конфигурационные файлы...")
	@if [ -f "configs/ingest.yml" ]; then \
		echo "✓ ingest.yml найден"; \
	else \
		echo "✗ ingest.yml не найден (используйте ingest.example.yml)"; \
	fi
	@if [ -f "configs/services.yml" ]; then \
		echo "✓ services.yml найден"; \
	else \
		echo "✗ services.yml не найден (используйте services.example.yml)"; \
	fi
	$(call log_info,"Проверка конфигурации завершена")

# Команды для работы с Wazuh агентом
.PHONY: wazuh-build wazuh-start wazuh-stop wazuh-restart wazuh-status wazuh-test
wazuh-build: ## Собрать Docker образ Wazuh агента
	$(call log_info,"Собираем Docker образ Wazuh агента...")
	@docker build -f docker/Dockerfile.wazuh-agent -t novasec-wazuh-agent .
	$(call log_success,"Docker образ Wazuh агента собран")

wazuh-start: ## Запустить Wazuh агент
	$(call log_info,"Запускаем Wazuh агент...")
	@docker-compose -f $(DOCKER_COMPOSE) up -d wazuh-agent
	$(call log_success,"Wazuh агент запущен")

wazuh-stop: ## Остановить Wazuh агент
	$(call log_info,"Останавливаем Wazuh агент...")
	@docker-compose -f $(DOCKER_COMPOSE) stop wazuh-agent
	$(call log_success,"Wazuh агент остановлен")

wazuh-restart: ## Перезапустить Wazuh агент
	$(call log_info,"Перезапускаем Wazuh агент...")
	@docker-compose -f $(DOCKER_COMPOSE) restart wazuh-agent
	$(call log_success,"Wazuh агент перезапущен")

wazuh-status: ## Показать статус Wazuh агента
	$(call log_info,"Статус Wazuh агента:")
	@docker-compose -f $(DOCKER_COMPOSE) ps wazuh-agent

wazuh-test: ## Тестировать парсер Wazuh
	$(call log_info,"Тестируем парсер Wazuh...")
	@go test -v ./internal/normalizer/parsers/ -run TestWazuhParser
	$(call log_success,"Тесты парсера Wazuh завершены")

wazuh-send-test: ## Отправить тестовое событие Wazuh
	$(call log_info,"Отправляем тестовое событие Wazuh...")
	@curl -X POST http://localhost:8080/api/v1/events \
		-H "Content-Type: application/json" \
		-d @internal/fixtures/wazuh_sample_events.jsonl
	$(call log_success,"Тестовое событие отправлено")

# Инициализация проекта
.PHONY: init
init: ## Инициализировать проект
	$(call log_info,"Инициализируем проект NovaSec...")
	@cp configs/ingest.example.yml configs/ingest.yml
	@cp configs/services.example.yml configs/services.yml
	@chmod +x scripts/gen-certs.sh
	@mkdir -p logs
	@mkdir -p data
	$(call log_success,"Проект инициализирован")
	$(call log_info,"Следующие шаги:")
	$(call log_info,"  1. Отредактируйте configs/*.yml")
	$(call log_info,"  2. Сгенерируйте сертификаты: make certs")
	$(call log_info,"  3. Соберите сервисы: make build")
	$(call log_info,"  4. Запустите: make run")

# Помощь по конкретной цели
.PHONY: help-target
help-target: ## Показать справку по конкретной цели
	@if [ -z "$(TARGET)" ]; then \
		echo "Использование: make help-target TARGET=<цель>"; \
		echo "Пример: make help-target TARGET=build"; \
		exit 1; \
	fi
	@echo "Справка по цели: $(TARGET)"
	@echo "========================"
	@grep -A 5 "^$(TARGET):" $(MAKEFILE_LIST) || echo "Цель '$(TARGET)' не найдена"

# Цель по умолчанию
.DEFAULT_GOAL := help
