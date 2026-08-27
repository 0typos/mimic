package mitm

import (
	"crypto/tls"
	"crypto/x509"
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
