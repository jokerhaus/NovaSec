# NovaSec TLS Certificates

This directory contains TLS certificates for NovaSec SIEM platform.

## Generated Files

### Certificate Authority (CA)
- `ca-cert.pem` - CA certificate (public)
- `ca-key.pem` - CA private key (keep secure!)

### Server Certificates
- `server-cert.pem` - Server certificate
- `server-key.pem` - Server private key
- `server-bundle.pem` - Server certificate + CA chain
- `server.p12` - Server certificate in PKCS#12 format (password: novasec)

### Client Certificates
- `client-cert.pem` - Client certificate
- `client-key.pem` - Client private key
- `client-bundle.pem` - Client certificate + CA chain
- `client.p12` - Client certificate in PKCS#12 format (password: novasec)

## Compatibility Links

These symlinks align with default NovaSec configuration paths:
- `ca.crt` → `ca-cert.pem`
- `service.crt` / `service.key` → `server-cert.pem` / `server-key.pem`
- `ingest.crt` / `ingest.key` → `server-cert.pem` / `server-key.pem`

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

1. **Keep private keys secure** - Never share or commit `*-key.pem` files
2. **Certificate validation** - Always validate certificates in production
3. **Regular rotation** - Rotate certificates before expiration
4. **Backup** - Keep secure backups of CA private key

## Usage Examples

### Docker Compose
Mount the certificates directory:
```yaml
volumes:
  - ./configs/tls:/etc/ssl/novasec:ro
```

### Nginx Configuration
```nginx
ssl_certificate /etc/ssl/novasec/server-bundle.pem;
ssl_certificate_key /etc/ssl/novasec/server-key.pem;
ssl_trusted_certificate /etc/ssl/novasec/ca-cert.pem;
```

### Go TLS Client
```go
cert, err := tls.LoadX509KeyPair("client-cert.pem", "client-key.pem")
```

## Certificate Information

- **Validity**: 3650 days
- **Key Size**: 4096 bits
- **Algorithm**: RSA
- **Generated**: Wed Sep 17 12:05:58 UTC 2025
- **Organization**: NovaSec

## Verification Commands

Verify certificate:
```bash
openssl x509 -in server-cert.pem -text -noout
```

Verify certificate chain:
```bash
openssl verify -CAfile ca-cert.pem server-cert.pem
```

Test TLS connection:
```bash
openssl s_client -connect localhost:443 -cert client-cert.pem -key client-key.pem
```
