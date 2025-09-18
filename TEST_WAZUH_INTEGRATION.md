# filename: TEST_WAZUH_INTEGRATION.md
# Тестирование интеграции Wazuh агента с NovaSec

## Обзор

Этот документ описывает комплексные юнит-тесты для интеграции Wazuh агента с системой NovaSec. Тесты покрывают все аспекты интеграции: парсер, конфигурацию, Docker, Makefile и документацию.

## Структура тестов

### 1. Парсер Wazuh (`internal/normalizer/parsers/`)

#### `wazuh_test.go`
- **TestWazuhParser_ParseEvent** - тестирует парсинг различных типов событий
- **TestWazuhParser_GetSupportedSources** - проверяет поддерживаемые источники
- **TestWazuhParser_GetSupportedCategories** - проверяет поддерживаемые категории
- **TestWazuhParser_GetSupportedSubtypes** - проверяет поддерживаемые подтипы
- **TestWazuhParser_DetermineSeverity** - тестирует определение серьезности
- **TestWazuhParser_DetermineCategory** - тестирует определение категории

#### `wazuh_integration_test.go`
- **TestWazuhParserIntegration** - комплексное тестирование парсера
- **TestWazuhParserEdgeCasesIntegration** - тестирование граничных случаев
- **TestWazuhParserPerformanceIntegration** - тестирование производительности
- **TestWazuhParserConcurrencyIntegration** - тестирование конкурентности
- **TestWazuhParserRegistryIntegrationTest** - тестирование интеграции с реестром
- **TestWazuhParserJSONValidationIntegration** - валидация JSON структуры

#### `wazuh_complete_integration_test.go`
- **TestWazuhCompleteIntegration** - полная интеграция end-to-end
- **TestWazuhParserRegistryIntegrationComplete** - интеграция с реестром
- **TestWazuhParserPerformanceComplete** - производительность
- **TestWazuhParserConcurrencyComplete** - конкурентность
- **TestWazuhParserEdgeCasesComplete** - граничные случаи
- **TestWazuhParserJSONValidationComplete** - валидация JSON

### 2. Конфигурация (`configs/`)

#### `wazuh_config_test.go`
- **TestWazuhConfigValidation** - валидация конфигурации
- **TestWazuhConfigYAML** - загрузка из YAML
- **TestWazuhConfigDefaults** - значения по умолчанию
- **TestWazuhConfigEnvironmentVariables** - переменные окружения
- **TestWazuhConfigIntegration** - полная интеграция конфигурации

### 3. Docker (`docker/`)

#### `wazuh_docker_test.go`
- **TestWazuhDockerfileValidation** - валидация Dockerfile
- **TestWazuhDockerComposeValidation** - валидация docker-compose.yml
- **TestWazuhIntegrationScript** - тестирование скрипта интеграции
- **TestWazuhSystemdService** - тестирование systemd сервиса
- **TestWazuhDockerBuild** - тестирование сборки Docker образа
- **TestWazuhDockerComposeUp** - тестирование запуска через docker-compose
- **TestWazuhDockerVolumes** - тестирование volumes
- **TestWazuhDockerNetworking** - тестирование сетевой конфигурации
- **TestWazuhDockerEnvironment** - тестирование переменных окружения
- **TestWazuhDockerSecurity** - тестирование настроек безопасности

### 4. Makefile (`Makefile_wazuh_test.go`)

- **TestWazuhMakefileCommands** - тестирование команд Makefile
- **TestWazuhMakefileHelp** - тестирование справки
- **TestWazuhMakefileDockerCommands** - тестирование Docker команд
- **TestWazuhMakefileTestCommands** - тестирование тестовых команд
- **TestWazuhMakefileVariables** - тестирование переменных
- **TestWazuhMakefileLogging** - тестирование логирования
- **TestWazuhMakefileIntegration** - интеграция команд
- **TestWazuhMakefileDependencies** - тестирование зависимостей
- **TestWazuhMakefileExecution** - выполнение команд
- **TestWazuhMakefileSyntax** - синтаксис Makefile
- **TestWazuhMakefileCompleteness** - полнота команд

### 5. Главный тест (`test_wazuh_integration.go`)

- **TestWazuhIntegrationAll** - запуск всех тестов
- **TestWazuhIntegrationFiles** - проверка наличия файлов
- **TestWazuhIntegrationCommands** - проверка команд Makefile
- **TestWazuhIntegrationDocker** - проверка Docker конфигурации
- **TestWazuhIntegrationDocumentation** - проверка документации
- **TestWazuhIntegrationSampleData** - проверка тестовых данных

## Запуск тестов

### Запуск всех тестов Wazuh

```bash
# Запуск всех тестов интеграции
go test -v ./test_wazuh_integration.go

# Запуск тестов парсера
go test -v ./internal/normalizer/parsers/ -run TestWazuh

# Запуск тестов конфигурации
go test -v ./configs/ -run TestWazuh

# Запуск тестов Docker
go test -v ./docker/ -run TestWazuh

# Запуск тестов Makefile
go test -v . -run TestWazuhMakefile
```

### Запуск через Makefile

```bash
# Тестирование парсера Wazuh
make wazuh-test

# Отправка тестового события
make wazuh-send-test

# Запуск всех тестов
make test
```

### Запуск конкретных тестов

```bash
# Тестирование парсера
go test -v ./internal/normalizer/parsers/ -run TestWazuhParser_ParseEvent

# Тестирование производительности
go test -v ./internal/normalizer/parsers/ -run TestWazuhParserPerformance

# Тестирование конфигурации
go test -v ./configs/ -run TestWazuhConfigValidation

# Тестирование Docker
go test -v ./docker/ -run TestWazuhDockerfileValidation
```

## Покрытие тестами

### Парсер Wazuh
- ✅ Парсинг всех типов событий Wazuh
- ✅ Обработка граничных случаев
- ✅ Производительность (1000 событий/сек)
- ✅ Конкурентность (10 горутин)
- ✅ Валидация JSON структуры
- ✅ Интеграция с реестром парсеров

### Конфигурация
- ✅ Валидация всех полей конфигурации
- ✅ Загрузка из YAML файлов
- ✅ Применение значений по умолчанию
- ✅ Переменные окружения
- ✅ Обработка ошибок

### Docker
- ✅ Валидация Dockerfile
- ✅ Валидация docker-compose.yml
- ✅ Тестирование скриптов интеграции
- ✅ Systemd сервисы
- ✅ Volumes и networking
- ✅ Безопасность

### Makefile
- ✅ Все команды Wazuh
- ✅ Синтаксис команд
- ✅ Интеграция с основными командами
- ✅ Логирование и вывод
- ✅ Зависимости команд

## Тестовые данные

### Примеры событий Wazuh (`internal/fixtures/wazuh_sample_events.jsonl`)

| #  | Уровень | Rule ID | Описание                                      | Категория         | Подтип             | Серьезность |
|----|---------|---------|-----------------------------------------------|-------------------|--------------------|-------------|
| 1  | 0       | 100001  | Agent connected to manager                    | system            | wazuh_event        | info        |
| 2  | 1       | 100002  | Integrity check started                       | file_integrity    | wazuh_event        | info        |
| 3  | 2       | 5715    | SSH login success                             | authentication    | ssh_login_success  | info        |
| 4  | 3       | 554     | File added to the system                      | file_integrity    | file_created       | low         |
| 5  | 4       | 555     | File modified on system                       | file_integrity    | file_modified      | low         |
| 6  | 5       | 556     | Critical file deleted from system             | file_integrity    | file_deleted       | medium      |
| 7  | 6       | 600     | User executed sudo command                    | authentication    | sudo_command       | medium      |
| 8  | 7       | 5716    | SSH login failed                              | authentication    | ssh_login_failed   | medium      |
| 9  | 8       | 650     | Firewall blocked suspicious connection        | network           | firewall_block     | high        |
| 10 | 9       | 651     | Multiple outbound connection attempts detected| network           | network_connection | high        |
| 11 | 10      | 700     | Malware detected in file upload               | malware           | malware_detected   | high        |
| 12 | 11      | 800     | Windows logon failure event                   | windows           | windows_event      | high        |
| 13 | 12      | 5717    | High number of failed login attempts          | authentication    | wazuh_event        | critical    |
| 14 | 13      | 900     | Critical file tampering detected              | file_integrity    | file_integrity     | critical    |
| 15 | 14      | 901     | Suspicious su command usage detected          | authentication    | su_command         | critical    |
| 16 | 15      | 999     | Rootkit detected on system                    | malware           | wazuh_event        | critical    |

## Ожидаемые результаты

### Успешное выполнение тестов

```
=== RUN   TestWazuhIntegrationAll
=== RUN   TestWazuhIntegrationAll/Parser_Tests
--- PASS: TestWazuhIntegrationAll/Parser_Tests (0.15s)
=== RUN   TestWazuhIntegrationAll/Config_Tests
--- PASS: TestWazuhIntegrationAll/Config_Tests (0.08s)
=== RUN   TestWazuhIntegrationAll/Docker_Tests
--- PASS: TestWazuhIntegrationAll/Docker_Tests (0.12s)
=== RUN   TestWazuhIntegrationAll/Makefile_Tests
--- PASS: TestWazuhIntegrationAll/Makefile_Tests (0.05s)
--- PASS: TestWazuhIntegrationAll (0.40s)
PASS
```

### Метрики производительности

- **Парсинг событий**: > 1000 событий/сек
- **Конкурентность**: 10 горутин × 100 событий = 1000 событий
- **Время выполнения**: < 1 секунды для 1000 событий
- **Память**: < 100MB для 1000 событий

## Отладка тестов

### Включение подробного вывода

```bash
# Подробный вывод
go test -v -run TestWazuh

# С покрытием кода
go test -v -cover -run TestWazuh

# С профилированием
go test -v -cpuprofile=cpu.prof -run TestWazuh
```

### Проверка конкретных компонентов

```bash
# Проверка парсера
go test -v ./internal/normalizer/parsers/ -run TestWazuhParser_ParseEvent

# Проверка конфигурации
go test -v ./configs/ -run TestWazuhConfigValidation

# Проверка Docker
go test -v ./docker/ -run TestWazuhDockerfileValidation
```

## Требования

- Go 1.22+
- Docker и Docker Compose
- Make
- Доступ к интернету для загрузки зависимостей

## Заключение

Комплексные тесты интеграции Wazuh агента с NovaSec обеспечивают:

1. **Полное покрытие** всех компонентов интеграции
2. **Высокую производительность** парсера событий
3. **Надежность** в различных условиях
4. **Простоту отладки** и мониторинга
5. **Документированность** всех аспектов интеграции

Тесты готовы к использованию в CI/CD пайплайнах и обеспечивают качество интеграции Wazuh агента с системой NovaSec.
