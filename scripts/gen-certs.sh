#!/bin/bash
# filename: scripts/gen-certs.sh
# Скрипт генерации TLS сертификатов для NovaSec SIEM

set -e

# Определяем абсолютные пути, чтобы скрипт работал из любой директории
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CERTS_RELATIVE_PATH="configs/tls"

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Конфигурация
CERTS_DIR="$REPO_ROOT/$CERTS_RELATIVE_PATH"
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
CLEAN_FIRST=false

CA_CONF="$CERTS_DIR/ca.conf"
SERVER_CONF="$CERTS_DIR/server.conf"
CLIENT_CONF="$CERTS_DIR/client.conf"
SERVER_EXT_CONF="$CERTS_DIR/server_ext.conf"
CLIENT_EXT_CONF="$CERTS_DIR/client_ext.conf"

CA_KEY="$CERTS_DIR/ca-key.pem"
CA_CERT="$CERTS_DIR/ca-cert.pem"
CA_SERIAL="$CERTS_DIR/ca-cert.srl"

SERVER_KEY="$CERTS_DIR/server-key.pem"
SERVER_CERT="$CERTS_DIR/server-cert.pem"
SERVER_CSR="$CERTS_DIR/server.csr"
SERVER_BUNDLE="$CERTS_DIR/server-bundle.pem"
SERVER_P12="$CERTS_DIR/server.p12"

CLIENT_KEY="$CERTS_DIR/client-key.pem"
CLIENT_CERT="$CERTS_DIR/client-cert.pem"
CLIENT_CSR="$CERTS_DIR/client.csr"
CLIENT_BUNDLE="$CERTS_DIR/client-bundle.pem"
CLIENT_P12="$CERTS_DIR/client.p12"

README_FILE="$CERTS_DIR/README.md"

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
        rm -rf "$CERTS_DIR"
    fi
}

# Функция создания конфигурации OpenSSL для CA
create_ca_config() {
    cat > "$CA_CONF" << EOF
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
    cat > "$SERVER_CONF" << EOF
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
    cat > "$CLIENT_CONF" << EOF
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
    cat > "$SERVER_EXT_CONF" << EOF
[ v3_req ]
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

    cat > "$CLIENT_EXT_CONF" << EOF
[ v3_req ]
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
    openssl genrsa -out "$CA_KEY" $KEY_SIZE
    chmod 400 "$CA_KEY"
    
    # 3. Создание самоподписанного сертификата CA
    log "Creating CA certificate..."
    openssl req -new -x509 -key "$CA_KEY" -out "$CA_CERT" -days $DAYS -config "$CA_CONF"
    
    # 4. Генерация приватного ключа сервера
    log "Generating server private key..."
    openssl genrsa -out "$SERVER_KEY" $KEY_SIZE
    chmod 400 "$SERVER_KEY"
    
    # 5. Создание запроса на подпись сертификата (CSR) для сервера
    log "Creating server certificate signing request..."
    openssl req -new -key "$SERVER_KEY" -out "$SERVER_CSR" -config "$SERVER_CONF"
    
    # 6. Подпись сертификата сервера CA
    log "Signing server certificate..."
    rm -f "$CA_SERIAL"
    openssl x509 -req -in "$SERVER_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" \
        -out "$SERVER_CERT" -days $DAYS -extensions v3_req \
        -extfile "$SERVER_EXT_CONF" -CAcreateserial -CAserial "$CA_SERIAL"
    
    # 7. Генерация приватного ключа клиента
    log "Generating client private key..."
    openssl genrsa -out "$CLIENT_KEY" $KEY_SIZE
    chmod 400 "$CLIENT_KEY"
    
    # 8. Создание CSR для клиента
    log "Creating client certificate signing request..."
    openssl req -new -key "$CLIENT_KEY" -out "$CLIENT_CSR" -config "$CLIENT_CONF"
    
    # 9. Подпись сертификата клиента CA
    log "Signing client certificate..."
    openssl x509 -req -in "$CLIENT_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" \
        -out "$CLIENT_CERT" -days $DAYS -extensions v3_req \
        -extfile "$CLIENT_EXT_CONF" -CAserial "$CA_SERIAL"
    
    # 10. Создание комбинированных файлов
    log "Creating combined certificate files..."
    cat "$SERVER_CERT" "$CA_CERT" > "$SERVER_BUNDLE"
    cat "$CLIENT_CERT" "$CA_CERT" > "$CLIENT_BUNDLE"
    
    # 11. Создание PFX файлов (если нужно)
    log "Creating PKCS#12 files..."
    openssl pkcs12 -export -out "$SERVER_P12" -inkey "$SERVER_KEY" \
        -in "$SERVER_CERT" -certfile "$CA_CERT" -passout pass:novasec
    openssl pkcs12 -export -out "$CLIENT_P12" -inkey "$CLIENT_KEY" \
        -in "$CLIENT_CERT" -certfile "$CA_CERT" -passout pass:novasec
    
    # 12. Установка правильных прав доступа
    log "Setting file permissions..."
    chmod 644 "$CA_CERT" "$SERVER_CERT" "$CLIENT_CERT" "$SERVER_BUNDLE" "$CLIENT_BUNDLE" "$SERVER_P12" "$CLIENT_P12"
    chmod 400 "$CA_KEY" "$SERVER_KEY" "$CLIENT_KEY"
    
    # 13. Очистка временных файлов
    log "Cleaning up temporary files..."
    rm -f "$SERVER_CSR" "$CLIENT_CSR" "$CA_CONF" "$SERVER_CONF" "$CLIENT_CONF" "$SERVER_EXT_CONF" "$CLIENT_EXT_CONF" "$CA_SERIAL"

    # 14. Создание алиасов для конфигураций
    log "Creating compatibility symlinks..."
    ln -sf "ca-cert.pem" "$CERTS_DIR/ca.crt"
    ln -sf "server-cert.pem" "$CERTS_DIR/service.crt"
    ln -sf "server-key.pem" "$CERTS_DIR/service.key"
    ln -sf "server-cert.pem" "$CERTS_DIR/ingest.crt"
    ln -sf "server-key.pem" "$CERTS_DIR/ingest.key"

    # 15. Создание README файла
    log "Creating README file..."
    cat > "$README_FILE" << EOF
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

## Compatibility Links

These symlinks align with default NovaSec configuration paths:
- \`ca.crt\` → \`ca-cert.pem\`
- \`service.crt\` / \`service.key\` → \`server-cert.pem\` / \`server-key.pem\`
- \`ingest.crt\` / \`ingest.key\` → \`server-cert.pem\` / \`server-key.pem\`

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
    
    # 16. Проверка сгенерированных сертификатов
    log "Verifying generated certificates..."

    echo ""
    info "=== Certificate Verification ==="

    # Проверка CA сертификата
    echo "CA Certificate:"
    openssl x509 -in "$CA_CERT" -noout -subject -issuer -dates

    echo ""
    echo "Server Certificate:"
    openssl x509 -in "$SERVER_CERT" -noout -subject -issuer -dates

    echo ""
    echo "Client Certificate:"
    openssl x509 -in "$CLIENT_CERT" -noout -subject -issuer -dates

    # Проверка цепочки сертификатов
    echo ""
    info "Certificate chain verification:"
    if openssl verify -CAfile "$CA_CERT" "$SERVER_CERT" > /dev/null 2>&1; then
        log "✓ Server certificate chain is valid"
    else
        error "✗ Server certificate chain is invalid"
    fi

    if openssl verify -CAfile "$CA_CERT" "$CLIENT_CERT" > /dev/null 2>&1; then
        log "✓ Client certificate chain is valid"
    else
        error "✗ Client certificate chain is invalid"
    fi
    
    echo ""
    log "=== Certificate Generation Complete ==="
    log "Certificates are available in: $CERTS_RELATIVE_PATH"
    log "Documentation: $CERTS_RELATIVE_PATH/README.md"
    warn "Keep private keys secure and never commit them to version control!"
    echo ""
}

# Выполнение основной функции
main "$@"
