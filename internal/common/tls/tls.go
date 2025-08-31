// internal/common/tls/tls.go
package tls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

// Config представляет конфигурацию TLS
type Config struct {
	Enabled    bool   `yaml:"enabled"`
	CAFile     string `yaml:"ca_file"`
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	MinVersion string `yaml:"min_version"`
	ClientAuth string `yaml:"client_auth"`
}

// ServerConfig представляет конфигурацию TLS сервера
type ServerConfig struct {
	CertFile   string
	KeyFile    string
	CAFile     string
	ClientAuth tls.ClientAuthType
	MinVersion uint16
}

// ClientConfig представляет конфигурацию TLS клиента
type ClientConfig struct {
	CAFile     string
	CertFile   string
	KeyFile    string
	ServerName string
	Insecure   bool
}

// NewServerConfig создает конфигурацию TLS сервера // v1.0
func NewServerConfig(config Config) (*ServerConfig, error) {
	if !config.Enabled {
		return nil, fmt.Errorf("TLS is not enabled")
	}

	if config.CertFile == "" || config.KeyFile == "" {
		return nil, fmt.Errorf("cert_file and key_file are required for TLS server")
	}

	// Проверяем существование файлов
	if _, err := os.Stat(config.CertFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("certificate file not found: %s", config.CertFile)
	}
	if _, err := os.Stat(config.KeyFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("private key file not found: %s", config.KeyFile)
	}

	// Определяем минимальную версию TLS
	var minVersion uint16 = tls.VersionTLS12
	switch config.MinVersion {
	case "1.0":
		minVersion = tls.VersionTLS10
	case "1.1":
		minVersion = tls.VersionTLS11
	case "1.2":
		minVersion = tls.VersionTLS12
	case "1.3":
		minVersion = tls.VersionTLS13
	}

	// Определяем тип аутентификации клиента
	clientAuth := tls.NoClientCert
	switch config.ClientAuth {
	case "request":
		clientAuth = tls.RequestClientCert
	case "require":
		clientAuth = tls.RequireAnyClientCert
	case "verify":
		clientAuth = tls.VerifyClientCertIfGiven
	case "require_and_verify":
		clientAuth = tls.RequireAndVerifyClientCert
	}

	return &ServerConfig{
		CertFile:   config.CertFile,
		KeyFile:    config.KeyFile,
		CAFile:     config.CAFile,
		ClientAuth: clientAuth,
		MinVersion: minVersion,
	}, nil
}

// NewClientConfig создает конфигурацию TLS клиента // v1.0
func NewClientConfig(config Config, serverName string) (*ClientConfig, error) {
	if !config.Enabled {
		return nil, fmt.Errorf("TLS is not enabled")
	}

	// Для клиента CA файл обязателен
	if config.CAFile == "" {
		return nil, fmt.Errorf("ca_file is required for TLS client")
	}

	// Проверяем существование CA файла
	if _, err := os.Stat(config.CAFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("CA file not found: %s", config.CAFile)
	}

	return &ClientConfig{
		CAFile:     config.CAFile,
		CertFile:   config.CertFile,
		KeyFile:    config.KeyFile,
		ServerName: serverName,
		Insecure:   false,
	}, nil
}

// LoadServerTLSConfig загружает TLS конфигурацию сервера // v1.0
func LoadServerTLSConfig(config *ServerConfig) (*tls.Config, error) {
	// Загружаем сертификат и приватный ключ
	cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate and key: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   config.ClientAuth,
		MinVersion:   config.MinVersion,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: getSecureCipherSuites(),
	}

	// Если указан CA файл, загружаем его для проверки клиентских сертификатов
	if config.CAFile != "" {
		caCert, err := os.ReadFile(config.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA file: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to append CA cert to pool")
		}

		tlsConfig.ClientCAs = caCertPool
	}

	return tlsConfig, nil
}

// LoadClientTLSConfig загружает TLS конфигурацию клиента // v1.0
func LoadClientTLSConfig(config *ClientConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		ServerName:         config.ServerName,
		InsecureSkipVerify: config.Insecure,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
		CipherSuites:       getSecureCipherSuites(),
	}

	// Загружаем CA сертификат
	if config.CAFile != "" {
		caCert, err := os.ReadFile(config.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA file: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to append CA cert to pool")
		}

		tlsConfig.RootCAs = caCertPool
	}

	// Если указаны клиентские сертификаты, загружаем их
	if config.CertFile != "" && config.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate and key: %w", err)
		}

		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return tlsConfig, nil
}

// getSecureCipherSuites возвращает безопасные наборы шифров // v1.0
func getSecureCipherSuites() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}
}

// GenerateSelfSignedCert генерирует самоподписанный сертификат // v1.0
func GenerateSelfSignedCert(commonName, certFile, keyFile string, validDays int) error {
	// Генерируем приватный ключ
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Создаем шаблон сертификата
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"NovaSec"},
			Country:      []string{"US"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, validDays),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:              []string{commonName, "localhost"},
	}

	// Создаем сертификат
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Сохраняем сертификат
	certOut, err := os.Create(certFile)
	if err != nil {
		return fmt.Errorf("failed to create cert file: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("failed to write cert: %w", err)
	}

	// Сохраняем приватный ключ
	keyOut, err := os.Create(keyFile)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer keyOut.Close()

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateKeyBytes}); err != nil {
		return fmt.Errorf("failed to write key: %w", err)
	}

	return nil
}

// ValidateCertificate проверяет валидность сертификата // v1.0
func ValidateCertificate(certFile string) error {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("failed to read certificate file: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Проверяем срок действия
	if time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) {
		return fmt.Errorf("certificate is not valid at current time")
	}

	return nil
}

// GetCertificateInfo возвращает информацию о сертификате // v1.0
func GetCertificateInfo(certFile string) (map[string]interface{}, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return map[string]interface{}{
		"subject":      cert.Subject.CommonName,
		"issuer":       cert.Issuer.CommonName,
		"serial":       cert.SerialNumber.String(),
		"not_before":   cert.NotBefore,
		"not_after":    cert.NotAfter,
		"dns_names":    cert.DNSNames,
		"ip_addresses": cert.IPAddresses,
		"key_usage":    cert.KeyUsage,
	}, nil
}
