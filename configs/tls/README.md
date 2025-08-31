# TLS Configuration for NovaSec

This directory contains TLS certificates and keys for secure communication between NovaSec services.

## Directory Structure

```
configs/tls/
├── README.md           # This file
├── ca.crt             # Certificate Authority certificate
├── ca.key             # Certificate Authority private key
├── ingest.crt         # Ingest service certificate
├── ingest.key         # Ingest service private key
├── normalizer.crt     # Normalizer service certificate
├── normalizer.key     # Normalizer service private key
├── correlator.crt     # Correlator service certificate
├── correlator.key     # Correlator service private key
├── alerting.crt       # Alerting service certificate
├── alerting.key       # Alerting service private key
├── adminapi.crt       # Admin API service certificate
└── adminapi.key       # Admin API service private key
```

## Certificate Generation

### Option 1: Using the provided script (Recommended)

```bash
# Make the script executable
chmod +x ../../scripts/gen-certs.sh

# Generate all certificates
../../scripts/gen-certs.sh

# Or generate specific certificates
../../scripts/gen-certs.sh ca
../../scripts/gen-certs.sh ingest
../../scripts/gen-certs.sh normalizer
../../scripts/gen-certs.sh correlator
../../scripts/gen-certs.sh alerting
../../scripts/gen-certs.sh adminapi
```

### Option 2: Manual generation

#### 1. Generate Certificate Authority (CA)

```bash
# Generate CA private key
openssl genrsa -out ca.key 4096

# Generate CA certificate
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
  -subj "/C=US/ST=CA/L=San Francisco/O=NovaSec/OU=Security/CN=NovaSec CA"
```

#### 2. Generate Service Certificates

For each service (ingest, normalizer, correlator, alerting, adminapi):

```bash
# Generate service private key
openssl genrsa -out service.key 2048

# Generate service certificate signing request (CSR)
openssl req -new -key service.key -out service.csr \
  -subj "/C=US/ST=CA/L=San Francisco/O=NovaSec/OU=Security/CN=service.novasec.local"

# Sign service certificate with CA
openssl x509 -req -days 365 -in service.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out service.crt -extensions v3_req \
  -extfile <(echo -e "[v3_req]\nsubjectAltName=DNS:service.novasec.local,DNS:localhost,IP:127.0.0.1")
```

#### 3. Generate Client Certificates (for mTLS)

```bash
# Generate client private key
openssl genrsa -out client.key 2048

# Generate client CSR
openssl req -new -key client.key -out client.csr \
  -subj "/C=US/ST=CA/L=San Francisco/O=NovaSec/OU=Security/CN=agent.novasec.local"

# Sign client certificate with CA
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out client.crt -extensions v3_req \
  -extfile <(echo -e "[v3_req]\nsubjectAltName=DNS:agent.novasec.local,DNS:localhost,IP:127.0.0.1")
```

## Certificate Validation

### Check CA certificate
```bash
openssl x509 -in ca.crt -text -noout
```

### Check service certificate
```bash
openssl x509 -in service.crt -text -noout
```

### Verify certificate chain
```bash
openssl verify -CAfile ca.crt service.crt
```

### Check certificate expiration
```bash
openssl x509 -in service.crt -noout -dates
```

## Security Considerations

1. **Private Keys**: Keep private keys secure and restrict access to authorized personnel only
2. **Certificate Expiration**: Monitor certificate expiration dates and renew before expiry
3. **Key Rotation**: Regularly rotate certificates and keys
4. **Access Control**: Use appropriate file permissions (600 for private keys, 644 for certificates)
5. **Backup**: Securely backup certificates and keys

## File Permissions

```bash
# Set correct permissions
chmod 600 *.key          # Private keys: owner read/write only
chmod 644 *.crt          # Certificates: owner read/write, group/others read
chmod 644 README.md      # Documentation: readable by all
```

## Testing TLS Configuration

### Test server certificate
```bash
# Start a test HTTPS server
openssl s_server -cert service.crt -key service.key -port 8443
```

### Test client connection
```bash
# Test connection with client certificate
openssl s_client -connect localhost:8443 -cert client.crt -key client.key -CAfile ca.crt
```

## Troubleshooting

### Common Issues

1. **Certificate not trusted**: Ensure CA certificate is properly configured
2. **Hostname mismatch**: Check Subject Alternative Names (SAN) in certificates
3. **Expired certificates**: Renew expired certificates
4. **Permission denied**: Check file permissions on private keys
5. **TLS handshake failure**: Verify certificate chain and cipher suites

### Debug Commands

```bash
# Check certificate details
openssl x509 -in certificate.crt -text -noout

# Verify certificate chain
openssl verify -verbose -CAfile ca.crt certificate.crt

# Test TLS connection
openssl s_client -connect host:port -servername hostname

# Check supported cipher suites
openssl ciphers -v
```

## Integration with NovaSec

### Configuration Files

Update your service configuration files to include TLS settings:

```yaml
tls:
  enabled: true
  ca_file: "configs/tls/ca.crt"
  cert_file: "configs/tls/service.crt"
  key_file: "configs/tls/service.key"
  min_version: "1.2"
  client_auth: "require_and_verify"
```

### Environment Variables

You can also use environment variables for TLS configuration:

```bash
export NOVASEC_TLS_ENABLED=true
export NOVASEC_TLS_CA_FILE=configs/tls/ca.crt
export NOVASEC_TLS_CERT_FILE=configs/tls/service.crt
export NOVASEC_TLS_KEY_FILE=configs/tls/service.key
```

## Support

For issues with TLS configuration:

1. Check the logs for specific error messages
2. Verify certificate validity and expiration
3. Ensure proper file permissions
4. Test with OpenSSL commands
5. Check NovaSec documentation and issue tracker
