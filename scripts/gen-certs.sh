#!/bin/bash
# scripts/gen-certs.sh
# Скрипт для генерации TLS сертификатов для NovaSec

set -e

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Функции для вывода
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Проверяем наличие OpenSSL
check_openssl() {
    if ! command -v openssl &> /dev/null; then
        log_error "OpenSSL не установлен. Установите OpenSSL и повторите попытку."
        exit 1
    fi
    
    log_info "OpenSSL версия: $(openssl version)"
}

# Создаем директорию для сертификатов
create_cert_dir() {
    local cert_dir="configs/tls"
    
    if [ ! -d "$cert_dir" ]; then
        log_info "Создаем директорию $cert_dir"
        mkdir -p "$cert_dir"
    fi
    
    cd "$cert_dir"
}

# Генерируем CA сертификат
generate_ca() {
    log_info "Генерируем Certificate Authority (CA)..."
    
    if [ -f "ca.key" ] || [ -f "ca.crt" ]; then
        log_warning "CA сертификат уже существует. Удалите ca.key и ca.crt для пересоздания."
        return
    fi
    
    # Генерируем CA приватный ключ
    log_info "Генерируем CA приватный ключ (4096 бит)..."
    openssl genrsa -out ca.key 4096
    
    # Генерируем CA сертификат
    log_info "Генерируем CA сертификат..."
    openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
        -subj "/C=US/ST=CA/L=San Francisco/O=NovaSec/OU=Security/CN=NovaSec CA" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -addext "subjectKeyIdentifier=hash"
    
    # Устанавливаем правильные права доступа
    chmod 600 ca.key
    chmod 644 ca.crt
    
    log_success "CA сертификат создан успешно"
}

# Генерируем сертификат для сервиса
generate_service_cert() {
    local service_name=$1
    local common_name="${service_name}.novasec.local"
    
    log_info "Генерируем сертификат для сервиса $service_name..."
    
    if [ -f "${service_name}.key" ] || [ -f "${service_name}.crt" ]; then
        log_warning "Сертификат для $service_name уже существует. Удалите ${service_name}.key и ${service_name}.crt для пересоздания."
        return
    fi
    
    # Генерируем приватный ключ
    log_info "Генерируем приватный ключ для $service_name..."
    openssl genrsa -out "${service_name}.key" 2048
    
    # Создаем конфигурационный файл для SAN
    cat > "${service_name}.conf" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = CA
L = San Francisco
O = NovaSec
OU = Security
CN = $common_name

[v3_req]
keyUsage = keyEncipherment, dataEncipherment, digitalSignature
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $common_name
DNS.2 = localhost
DNS.3 = $service_name
IP.1 = 127.0.0.1
IP.2 = ::1
EOF
    
    # Генерируем CSR
    log_info "Генерируем CSR для $service_name..."
    openssl req -new -key "${service_name}.key" -out "${service_name}.csr" \
        -config "${service_name}.conf"
    
    # Подписываем сертификат CA
    log_info "Подписываем сертификат для $service_name..."
    openssl x509 -req -days 365 -in "${service_name}.csr" \
        -CA ca.crt -CAkey ca.key -CAcreateserial \
        -out "${service_name}.crt" -extensions v3_req \
        -extfile "${service_name}.conf"
    
    # Устанавливаем правильные права доступа
    chmod 600 "${service_name}.key"
    chmod 644 "${service_name}.crt"
    
    # Удаляем временные файлы
    rm -f "${service_name}.csr" "${service_name}.conf" ca.srl
    
    log_success "Сертификат для $service_name создан успешно"
}

# Генерируем клиентский сертификат
generate_client_cert() {
    local client_name="agent"
    local common_name="${client_name}.novasec.local"
    
    log_info "Генерируем клиентский сертификат для агента..."
    
    if [ -f "${client_name}.key" ] || [ -f "${client_name}.crt" ]; then
        log_warning "Клиентский сертификат уже существует. Удалите ${client_name}.key и ${client_name}.crt для пересоздания."
        return
    fi
    
    # Генерируем приватный ключ
    log_info "Генерируем приватный ключ для агента..."
    openssl genrsa -out "${client_name}.key" 2048
    
    # Создаем конфигурационный файл для SAN
    cat > "${client_name}.conf" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = CA
L = San Francisco
O = NovaSec
OU = Security
CN = $common_name

[v3_req]
keyUsage = keyEncipherment, dataEncipherment, digitalSignature
extendedKeyUsage = clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $common_name
DNS.2 = localhost
DNS.3 = agent
IP.1 = 127.0.0.1
IP.2 = ::1
EOF
    
    # Генерируем CSR
    log_info "Генерируем CSR для агента..."
    openssl req -new -key "${client_name}.key" -out "${client_name}.csr" \
        -config "${client_name}.conf"
    
    # Подписываем сертификат CA
    log_info "Подписываем сертификат для агента..."
    openssl x509 -req -days 365 -in "${client_name}.csr" \
        -CA ca.crt -CAkey ca.key -CAcreateserial \
        -out "${client_name}.crt" -extensions v3_req \
        -extfile "${client_name}.conf"
    
    # Устанавливаем правильные права доступа
    chmod 600 "${client_name}.key"
    chmod 644 "${client_name}.crt"
    
    # Удаляем временные файлы
    rm -f "${client_name}.csr" "${client_name}.conf" ca.srl
    
    log_success "Клиентский сертификат создан успешно"
}

# Проверяем сертификаты
verify_certificates() {
    log_info "Проверяем созданные сертификаты..."
    
    # Проверяем CA сертификат
    if [ -f "ca.crt" ]; then
        log_info "CA сертификат:"
        openssl x509 -in ca.crt -noout -subject -issuer -dates
        echo
    fi
    
    # Проверяем сервисные сертификаты
    for service in ingest normalizer correlator alerting adminapi; do
        if [ -f "${service}.crt" ]; then
            log_info "Сертификат $service:"
            openssl x509 -in "${service}.crt" -noout -subject -issuer -dates
            echo
        fi
    done
    
    # Проверяем клиентский сертификат
    if [ -f "agent.crt" ]; then
        log_info "Клиентский сертификат:"
        openssl x509 -in agent.crt -noout -subject -issuer -dates
        echo
    fi
}

# Создаем bundle сертификатов
create_bundle() {
    log_info "Создаем bundle сертификатов..."
    
    # Bundle для клиентов (CA + клиентский сертификат)
    if [ -f "ca.crt" ] && [ -f "agent.crt" ]; then
        cat ca.crt agent.crt > agent-bundle.crt
        chmod 644 agent-bundle.crt
        log_success "Bundle для агента создан: agent-bundle.crt"
    fi
    
    # Bundle для сервисов (CA + сервисный сертификат)
    for service in ingest normalizer correlator alerting adminapi; do
        if [ -f "ca.crt" ] && [ -f "${service}.crt" ]; then
            cat ca.crt "${service}.crt" > "${service}-bundle.crt"
            chmod 644 "${service}-bundle.crt"
            log_success "Bundle для $service создан: ${service}-bundle.crt"
        fi
    done
}

# Основная функция
main() {
    local action=${1:-"all"}
    
    log_info "NovaSec Certificate Generator"
    log_info "Действие: $action"
    
    # Проверяем OpenSSL
    check_openssl
    
    # Создаем директорию для сертификатов
    create_cert_dir
    
    case $action in
        "ca")
            generate_ca
            ;;
        "ingest")
            generate_service_cert "ingest"
            ;;
        "normalizer")
            generate_service_cert "normalizer"
            ;;
        "correlator")
            generate_service_cert "correlator"
            ;;
        "alerting")
            generate_service_cert "alerting"
            ;;
        "adminapi")
            generate_service_cert "adminapi"
            ;;
        "agent"|"client")
            generate_client_cert
            ;;
        "all")
            generate_ca
            generate_service_cert "ingest"
            generate_service_cert "normalizer"
            generate_service_cert "correlator"
            generate_service_cert "alerting"
            generate_service_cert "adminapi"
            generate_client_cert
            ;;
        "verify")
            verify_certificates
            ;;
        "bundle")
            create_bundle
            ;;
        "help"|"-h"|"--help")
            echo "Использование: $0 [действие]"
            echo ""
            echo "Действия:"
            echo "  all        - Генерировать все сертификаты (по умолчанию)"
            echo "  ca         - Генерировать только CA сертификат"
            echo "  ingest     - Генерировать сертификат для ingest сервиса"
            echo "  normalizer - Генерировать сертификат для normalizer сервиса"
            echo "  correlator - Генерировать сертификат для correlator сервиса"
            echo "  alerting   - Генерировать сертификат для alerting сервиса"
            echo "  adminapi   - Генерировать сертификат для adminapi сервиса"
            echo "  agent      - Генерировать клиентский сертификат для агента"
            echo "  verify     - Проверить созданные сертификаты"
            echo "  bundle     - Создать bundle сертификатов"
            echo "  help       - Показать эту справку"
            echo ""
            echo "Примеры:"
            echo "  $0                    # Генерировать все сертификаты"
            echo "  $0 ca                 # Только CA"
            echo "  $0 ingest             # Только для ingest"
            echo "  $0 verify             # Проверить сертификаты"
            exit 0
            ;;
        *)
            log_error "Неизвестное действие: $action"
            echo "Используйте '$0 help' для справки"
            exit 1
            ;;
    esac
    
    if [ "$action" != "verify" ] && [ "$action" != "bundle" ]; then
        log_info "Проверяем созданные сертификаты..."
        verify_certificates
        
        log_info "Создаем bundle сертификатов..."
        create_bundle
    fi
    
    log_success "Генерация сертификатов завершена успешно!"
    log_info "Сертификаты сохранены в директории: $(pwd)"
}

# Запускаем основную функцию
main "$@"
