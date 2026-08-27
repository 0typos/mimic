package mitm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Authority struct {
	cert   *x509.Certificate
	key    *ecdsa.PrivateKey
	ttl    time.Duration
	mu     sync.RWMutex
	leaves map[string]*tls.Certificate
}

func Generate(certPath, keyPath string) error {
	for _, path := range []string{certPath, keyPath} {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("refusing to overwrite existing CA file %s", path)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("inspect CA path %s: %w", path, err)
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Mimic Local Interception CA", Organization: []string{"Mimic"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create CA certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal CA key: %w", err)
	}
	if err := writePEM(certPath, 0o644, "CERTIFICATE", der); err != nil {
		return err
	}
	if err := writePEM(keyPath, 0o600, "PRIVATE KEY", keyDER); err != nil {
		return err
	}
	return nil
}

func Load(certPath, keyPath string, ttl time.Duration) (*Authority, error) {
	if ttl <= 0 {
		return nil, fmt.Errorf("interception leaf TTL must be greater than zero")
	}
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load interception CA: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return nil, fmt.Errorf("interception CA certificate is empty")
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse interception CA: %w", err)
	}
	key, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("interception CA must use an ECDSA private key")
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("interception certificate is not a CA")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, fmt.Errorf("interception CA is not permitted to sign certificates")
	}
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return nil, fmt.Errorf("interception CA is not valid before %s", cert.NotBefore.Format(time.RFC3339))
	}
	if !now.Before(cert.NotAfter) {
		return nil, fmt.Errorf("interception CA expired at %s", cert.NotAfter.Format(time.RFC3339))
	}
	return &Authority{cert: cert, key: key, ttl: ttl, leaves: map[string]*tls.Certificate{}}, nil
}

func (a *Authority) TLSConfig(host string) (*tls.Config, error) {
	host = strings.Trim(host, "[]")
	a.mu.RLock()
	leaf := a.leaves[host]
	a.mu.RUnlock()
	if leaf == nil {
		generated, err := a.issue(host)
		if err != nil {
			return nil, err
		}
		a.mu.Lock()
		if existing := a.leaves[host]; existing != nil {
			leaf = existing
		} else {
			a.leaves[host] = generated
			leaf = generated
		}
		a.mu.Unlock()
	}
	return &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}, nil
}

func (a *Authority) issue(host string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	notAfter := now.Add(a.ttl)
	if notAfter.After(a.cert.NotAfter) {
		notAfter = a.cert.NotAfter
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host, Organization: []string{"Mimic intercepted upstream"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, &key.PublicKey, a.key)
	if err != nil {
		return nil, fmt.Errorf("issue certificate for %s: %w", host, err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &pair, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	return serial, nil
}

func writePEM(path string, mode os.FileMode, blockType string, der []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create directory for %s: %w", path, err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer file.Close()
	if err := pem.Encode(file, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return file.Sync()
}
