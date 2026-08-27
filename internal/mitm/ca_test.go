package mitm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateLoadAndIssue(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")
	if err := Generate(certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	if err := Generate(certPath, keyPath); err == nil {
		t.Fatal("expected overwrite refusal")
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("private key permissions = %v", info.Mode().Perm())
	}
	authority, err := Load(certPath, keyPath, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	server, err := authority.TLSConfig("example.test")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(server.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.VerifyHostname("example.test"); err != nil {
		t.Fatal(err)
	}
	if server.MinVersion != tls.VersionTLS12 {
		t.Fatalf("downstream minimum = %x", server.MinVersion)
	}
	cached, err := authority.TLSConfig("example.test")
	if err != nil {
		t.Fatal(err)
	}
	if string(cached.Certificates[0].Certificate[0]) != string(server.Certificates[0].Certificate[0]) {
		t.Fatal("leaf certificate was not cached")
	}
	ipConfig, err := authority.TLSConfig("[127.0.0.1]")
	if err != nil {
		t.Fatal(err)
	}
	ipLeaf, err := x509.ParseCertificate(ipConfig.Certificates[0].Certificate[0])
	if err != nil || ipLeaf.VerifyHostname("127.0.0.1") != nil {
		t.Fatalf("IP leaf verification: %v", err)
	}
}

func TestLoadRejectsNonPositiveLeafTTL(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")
	if err := Generate(certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(certPath, keyPath, 0); err == nil {
		t.Fatal("expected non-positive leaf TTL rejection")
	}
}

func TestLoadRejectsInvalidAuthorities(t *testing.T) {
	dir := t.TempDir()
	badCert := filepath.Join(dir, "bad-cert.pem")
	badKey := filepath.Join(dir, "bad-key.pem")
	if err := os.WriteFile(badCert, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(badKey, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(badCert, badKey, time.Hour); err == nil {
		t.Fatal("invalid key pair unexpectedly loaded")
	}

	now := time.Now()
	for _, test := range []struct {
		name      string
		isCA      bool
		keyUsage  x509.KeyUsage
		notBefore time.Time
		notAfter  time.Time
	}{
		{"not CA", false, x509.KeyUsageCertSign, now.Add(-time.Hour), now.Add(time.Hour)},
		{"cannot sign", true, x509.KeyUsageDigitalSignature, now.Add(-time.Hour), now.Add(time.Hour)},
		{"not yet valid", true, x509.KeyUsageCertSign, now.Add(time.Hour), now.Add(2 * time.Hour)},
		{"expired", true, x509.KeyUsageCertSign, now.Add(-2 * time.Hour), now.Add(-time.Hour)},
	} {
		t.Run(test.name, func(t *testing.T) {
			certPath, keyPath := writeTestAuthority(t, test.isCA, test.keyUsage, test.notBefore, test.notAfter)
			if _, err := Load(certPath, keyPath, time.Hour); err == nil {
				t.Fatal("invalid authority unexpectedly loaded")
			}
		})
	}
}

func TestWritePEMFailurePaths(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "existing.pem")
	if err := os.WriteFile(existing, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writePEM(existing, 0o600, "TEST", []byte{1}); err == nil {
		t.Fatal("expected exclusive-create failure")
	}
	if err := writePEM(filepath.Join(existing, "child.pem"), 0o600, "TEST", []byte{1}); err == nil {
		t.Fatal("expected parent-directory failure")
	}
}

func writeTestAuthority(t *testing.T, isCA bool, usage x509.KeyUsage, notBefore, notAfter time.Time) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "test authority"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              usage,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}
