#!/bin/bash
# filename: scripts/gen-certs.sh
# Скрипт генерации TLS сертификатов для NovaSec SIEM

set -e

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Конфигурация
CERTS_DIR="configs/tls"
CA_NAME="novasec-ca"
SERVER_NAME="novasec-server"
CLIENT_NAME="novasec-client"
KEY_SIZE=4096
DAYS=3650
COUNTRY="US"
STATE="CA"
CITY="San Francisco"
ORG="NovaSec"
OU="Security Operations"

# Функции логирования
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1${NC}"
}

# Функция для создания директории
create_dir() {
    local dir="$1"
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir"
        log "Created directory: $dir"
    fi
}

# Функция для генерации случайного серийного номера
generate_serial() {
    openssl rand -hex 16
}

# Функция очистки существующих сертификатов
cleanup_certs() {
    if [ -d "$CERTS_DIR" ]; then
        warn "Removing existing certificates..."
        rm -rf "$CERTS_DIR"/*
    fi
}

# Функция создания конфигурации OpenSSL для CA
create_ca_config() {
    cat > "$CERTS_DIR/ca.conf" << EOF
[ req ]
default_bits = $KEY_SIZE
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[ req_distinguished_name ]
C = $COUNTRY
ST = $STATE
L = $CITY
O = $ORG
OU = $OU
CN = $CA_NAME

[ v3_ca ]
basicConstraints = critical,CA:TRUE
keyUsage = critical,digitalSignature,keyEncipherment,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
EOF
}

# Функция создания конфигурации OpenSSL для сервера
create_server_config() {
    cat > "$CERTS_DIR/server.conf" << EOF
[ req ]
default_bits = $KEY_SIZE
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[ req_distinguished_name ]
C = $COUNTRY
ST = $STATE
L = $CITY
O = $ORG
OU = $OU
CN = $SERVER_NAME

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation,digitalSignature,keyEncipherment
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
DNS.2 = novasec-ingest
DNS.3 = novasec-api
DNS.4 = novasec-admin
DNS.5 = *.novasec.local
IP.1 = 127.0.0.1
IP.2 = ::1
EOF
}

# Функция создания конфигурации OpenSSL для клиента
create_client_config() {
    cat > "$CERTS_DIR/client.conf" << EOF
[ req ]
default_bits = $KEY_SIZE
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[ req_distinguished_name ]
C = $COUNTRY
ST = $STATE
L = $CITY
O = $ORG
OU = $OU
CN = $CLIENT_NAME

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
EOF
}

# Функция создания расширений для подписи сертификатов
create_extensions() {
    cat > "$CERTS_DIR/server_ext.conf" << EOF
basicConstraints = CA:FALSE
keyUsage = nonRepudiation,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
DNS.2 = novasec-ingest
DNS.3 = novasec-api
DNS.4 = novasec-admin
DNS.5 = *.novasec.local
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

    cat > "$CERTS_DIR/client_ext.conf" << EOF
basicConstraints = CA:FALSE
keyUsage = nonRepudiation,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
EOF
}

# Проверка зависимостей
check_dependencies() {
    log "Checking dependencies..."
    
    if ! command -v openssl &> /dev/null; then
        error "OpenSSL is not installed"
        exit 1
    fi
    
    info "OpenSSL version: $(openssl version)"
}

# Показать справку
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help        Show this help message"
    echo "  -c, --clean       Clean existing certificates before generating new ones"
    echo "  -d, --days DAYS   Certificate validity period in days (default: $DAYS)"
    echo "  -k, --key-size    Key size in bits (default: $KEY_SIZE)"
    echo "  -o, --org ORG     Organization name (default: $ORG)"
    echo "  --country CODE    Country code (default: $COUNTRY)"
    echo "  --state STATE     State/Province (default: $STATE)"
    echo "  --city CITY       City/Locality (default: $CITY)"
    echo ""
    echo "Examples:"
    echo "  $0                Generate certificates with default settings"
    echo "  $0 -c             Clean and regenerate certificates"
    echo "  $0 -d 365         Generate certificates valid for 1 year"
    echo "  $0 -k 2048        Use 2048-bit keys"
}

# Парсинг аргументов командной строки
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -c|--clean)
                CLEAN_FIRST=true
                shift
                ;;
            -d|--days)
                DAYS="$2"
                shift 2
                ;;
            -k|--key-size)
                KEY_SIZE="$2"
                shift 2
                ;;
            -o|--org)
                ORG="$2"
                shift 2
                ;;
            --country)
                COUNTRY="$2"
                shift 2
                ;;
            --state)
                STATE="$2"
                shift 2
                ;;
            --city)
                CITY="$2"
                shift 2
                ;;
            *)
                error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# Основная функция
main() {
    echo ""
    log "=== NovaSec TLS Certificate Generator ==="
    echo ""
    
    # Парсинг аргументов
    parse_args "$@"
    
    # Проверка зависимостей
    check_dependencies
    
    # Очистка существующих сертификатов (если указано)
    if [ "$CLEAN_FIRST" = true ]; then
        cleanup_certs
    fi
    
    # Создание директории
    create_dir "$CERTS_DIR"
    
    # Переход в директорию сертификатов
    cd "$CERTS_DIR"
    
    info "Configuration:"
    info "  Organization: $ORG"
    info "  Country: $COUNTRY"
    info "  State: $STATE"
    info "  City: $CITY"
    info "  Key size: $KEY_SIZE bits"
    info "  Validity: $DAYS days"
    echo ""
    
    # 1. Создание конфигурационных файлов
    log "Creating OpenSSL configuration files..."
    create_ca_config
    create_server_config
    create_client_config
    create_extensions
    
    # 2. Генерация приватного ключа CA
    log "Generating CA private key..."
    openssl genrsa -out ca-key.pem $KEY_SIZE
    chmod 400 ca-key.pem
    
    # 3. Создание самоподписанного сертификата CA
    log "Creating CA certificate..."
    openssl req -new -x509 -key ca-key.pem -out ca-cert.pem -days $DAYS -config ca.conf
    
    # 4. Генерация приватного ключа сервера
    log "Generating server private key..."
    openssl genrsa -out server-key.pem $KEY_SIZE
    chmod 400 server-key.pem
    
    # 5. Создание запроса на подпись сертификата (CSR) для сервера
    log "Creating server certificate signing request..."
    openssl req -new -key server-key.pem -out server.csr -config server.conf
    
    # 6. Подпись сертификата сервера CA
    log "Signing server certificate..."
    openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem \
        -out server-cert.pem -days $DAYS -extensions v3_req \
        -extfile server_ext.conf -CAcreateserial
    
    # 7. Генерация приватного ключа клиента
    log "Generating client private key..."
    openssl genrsa -out client-key.pem $KEY_SIZE
    chmod 400 client-key.pem
    
    # 8. Создание CSR для клиента
    log "Creating client certificate signing request..."
    openssl req -new -key client-key.pem -out client.csr -config client.conf
    
    # 9. Подпись сертификата клиента CA
    log "Signing client certificate..."
    openssl x509 -req -in client.csr -CA ca-cert.pem -CAkey ca-key.pem \
        -out client-cert.pem -days $DAYS -extensions v3_req \
        -extfile client_ext.conf -CAcreateserial
    
    # 10. Создание комбинированных файлов
    log "Creating combined certificate files..."
    cat server-cert.pem ca-cert.pem > server-bundle.pem
    cat client-cert.pem ca-cert.pem > client-bundle.pem
    
    # 11. Создание PFX файлов (если нужно)
    log "Creating PKCS#12 files..."
    openssl pkcs12 -export -out server.p12 -inkey server-key.pem \
        -in server-cert.pem -certfile ca-cert.pem -passout pass:novasec
    openssl pkcs12 -export -out client.p12 -inkey client-key.pem \
        -in client-cert.pem -certfile ca-cert.pem -passout pass:novasec
    
    # 12. Установка правильных прав доступа
    log "Setting file permissions..."
    chmod 644 *.pem *.p12
    chmod 400 *-key.pem
    
    # 13. Очистка временных файлов
    log "Cleaning up temporary files..."
    rm -f *.csr *.conf *.srl
    
    # 14. Создание README файла
    log "Creating README file..."
    cat > README.md << EOF
# NovaSec TLS Certificates

This directory contains TLS certificates for NovaSec SIEM platform.

## Generated Files

### Certificate Authority (CA)
- \`ca-cert.pem\` - CA certificate (public)
- \`ca-key.pem\` - CA private key (keep secure!)

### Server Certificates
- \`server-cert.pem\` - Server certificate
- \`server-key.pem\` - Server private key
- \`server-bundle.pem\` - Server certificate + CA chain
- \`server.p12\` - Server certificate in PKCS#12 format (password: novasec)

### Client Certificates
- \`client-cert.pem\` - Client certificate
- \`client-key.pem\` - Client private key
- \`client-bundle.pem\` - Client certificate + CA chain
- \`client.p12\` - Client certificate in PKCS#12 format (password: novasec)

## Configuration

These certificates are configured for the following domains/IPs:
- localhost
- novasec-ingest
- novasec-api
- novasec-admin
- *.novasec.local
- 127.0.0.1
- ::1

## Security Notes

1. **Keep private keys secure** - Never share or commit \`*-key.pem\` files
2. **Certificate validation** - Always validate certificates in production
3. **Regular rotation** - Rotate certificates before expiration
4. **Backup** - Keep secure backups of CA private key

## Usage Examples

### Docker Compose
Mount the certificates directory:
\`\`\`yaml
volumes:
  - ./configs/tls:/etc/ssl/novasec:ro
\`\`\`

### Nginx Configuration
\`\`\`nginx
ssl_certificate /etc/ssl/novasec/server-bundle.pem;
ssl_certificate_key /etc/ssl/novasec/server-key.pem;
ssl_trusted_certificate /etc/ssl/novasec/ca-cert.pem;
\`\`\`

### Go TLS Client
\`\`\`go
cert, err := tls.LoadX509KeyPair("client-cert.pem", "client-key.pem")
\`\`\`

## Certificate Information

- **Validity**: $DAYS days
- **Key Size**: $KEY_SIZE bits
- **Algorithm**: RSA
- **Generated**: $(date)
- **Organization**: $ORG

## Verification Commands

Verify certificate:
\`\`\`bash
openssl x509 -in server-cert.pem -text -noout
\`\`\`

Verify certificate chain:
\`\`\`bash
openssl verify -CAfile ca-cert.pem server-cert.pem
\`\`\`

Test TLS connection:
\`\`\`bash
openssl s_client -connect localhost:443 -cert client-cert.pem -key client-key.pem
\`\`\`
EOF
    
    # Возврат в исходную директорию
    cd - > /dev/null
    
    # 15. Проверка сгенерированных сертификатов
    log "Verifying generated certificates..."
    
    echo ""
    info "=== Certificate Verification ==="
    
    # Проверка CA сертификата
    echo "CA Certificate:"
    openssl x509 -in "$CERTS_DIR/ca-cert.pem" -noout -subject -issuer -dates
    
    echo ""
    echo "Server Certificate:"
    openssl x509 -in "$CERTS_DIR/server-cert.pem" -noout -subject -issuer -dates
    
    echo ""
    echo "Client Certificate:"
    openssl x509 -in "$CERTS_DIR/client-cert.pem" -noout -subject -issuer -dates
    
    # Проверка цепочки сертификатов
    echo ""
    info "Certificate chain verification:"
    if openssl verify -CAfile "$CERTS_DIR/ca-cert.pem" "$CERTS_DIR/server-cert.pem" > /dev/null 2>&1; then
        log "✓ Server certificate chain is valid"
    else
        error "✗ Server certificate chain is invalid"
    fi
    
    if openssl verify -CAfile "$CERTS_DIR/ca-cert.pem" "$CERTS_DIR/client-cert.pem" > /dev/null 2>&1; then
        log "✓ Client certificate chain is valid"
    else
        error "✗ Client certificate chain is invalid"
    fi
    
    echo ""
    log "=== Certificate Generation Complete ==="
    log "Certificates are available in: $CERTS_DIR"
    log "Documentation: $CERTS_DIR/README.md"
    warn "Keep private keys secure and never commit them to version control!"
    echo ""
}

# Выполнение основной функции
main "$@"
