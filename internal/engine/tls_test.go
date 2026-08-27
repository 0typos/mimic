package engine

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/msmythe/mimic/internal/config"
	"github.com/msmythe/mimic/internal/profiles"
)

func TestTLSDialerModernProfile(t *testing.T) {
	listener, versions := startTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{selfSignedRSA(t)},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	})
	defer listener.Close()
	state := tlsTestState(t, false)
	dialer := NewTLSDialer(state, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, profile, err := dialer.Dial(ctx, listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if profile.Name != "chrome-133" {
		t.Fatalf("profile = %q", profile.Name)
	}
	if got := conn.(*utls.UConn).ConnectionState().Version; got != tls.VersionTLS12 {
		t.Fatalf("TLS version = %x", got)
	}
	select {
	case version := <-versions:
		if version != tls.VersionTLS12 {
			t.Fatalf("server TLS version = %x", version)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not complete handshake")
	}
}

func TestTLSDialerLegacyRetry(t *testing.T) {
	listener, versions := startTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{selfSignedRSA(t)},
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS10,
		CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA},
		NextProtos:   []string{"http/1.1"},
	})
	defer listener.Close()
	state := tlsTestState(t, true)
	dialer := NewTLSDialer(state, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := dialer.Dial(ctx, listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got := conn.(*utls.UConn).ConnectionState().Version; got != tls.VersionTLS10 {
		t.Fatalf("TLS version = %x, want TLS 1.0", got)
	}
	if state.Status().TLSFallbacks != 1 {
		t.Fatalf("fallback count = %d", state.Status().TLSFallbacks)
	}
	select {
	case version := <-versions:
		if version != tls.VersionTLS10 {
			t.Fatalf("server TLS version = %x", version)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not complete legacy handshake")
	}
}

func TestTLSDialerProbeCapturesEmittedClientHello(t *testing.T) {
	listener, _ := startTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{selfSignedRSA(t)},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	})
	defer listener.Close()
	state := tlsTestState(t, false)
	dialer := NewTLSDialer(state, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := dialer.Probe(ctx, listener.Addr().String(), "")
	if err != nil {
		t.Fatal(err)
	}
	if result.Profile != "chrome-133" || len(result.Attempts) != 1 {
		t.Fatalf("unexpected probe result: %+v", result)
	}
	attempt := result.Attempts[0]
	if attempt.JA4 == nil || attempt.JA4.Fingerprint == "" || attempt.FingerprintError != "" {
		t.Fatalf("missing captured JA4: %+v", attempt)
	}
	if attempt.CapturedBytes == 0 || attempt.NegotiatedVersion == "" || attempt.Cipher == "" {
		t.Fatalf("missing handshake details: %+v", attempt)
	}
	if attempt.JA4.SNI {
		t.Fatalf("IP target unexpectedly emitted SNI: %+v", attempt.JA4)
	}
}

func TestBuiltinProfileJA4Values(t *testing.T) {
	listener, versions := startTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{selfSignedRSA(t)},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	})
	defer listener.Close()
	state := tlsTestState(t, false)
	cfg := state.Snapshot().Config
	cfg.Legacy.InsecureSkipVerify = true
	registry, err := profiles.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	state, err = New(cfg, registry, new(slog.LevelVar))
	if err != nil {
		t.Fatal(err)
	}
	dialer := NewTLSDialer(state, slog.New(slog.NewTextHandler(io.Discard, nil)))
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	target := net.JoinHostPort("localhost", port)
	for _, name := range []string{"chrome-133", "firefox-120", "safari-16", "ios-14", "android-11"} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		result, probeErr := dialer.Probe(ctx, target, name)
		cancel()
		if probeErr != nil {
			t.Fatalf("probe %s: %v", name, probeErr)
		}
		if len(result.Attempts) != 1 || result.Attempts[0].JA4 == nil {
			t.Fatalf("probe %s did not capture JA4: %+v", name, result)
		}
		if result.ExpectedJA4 == "" || result.Attempts[0].JA4.Fingerprint != result.ExpectedJA4 {
			t.Fatalf("probe %s JA4 = %q, want %q", name, result.Attempts[0].JA4.Fingerprint, result.ExpectedJA4)
		}
		select {
		case <-versions:
		case <-time.After(time.Second):
			t.Fatalf("server did not complete %s handshake", name)
		}
	}
}

func TestRetryPolicyHelpers(t *testing.T) {
	if !retryable(context.DeadlineExceeded, []string{"deadline"}) {
		t.Fatal("expected retry fragment match")
	}
	if retryable(context.Canceled, []string{"deadline"}) {
		t.Fatal("unexpected retry match")
	}
	if !hostAllowed("node.lab.test", []string{"*.lab.test"}) {
		t.Fatal("expected host allowlist match")
	}
	if hostAllowed("public.test", []string{"*.lab.test"}) {
		t.Fatal("unexpected host allowlist match")
	}
}

func tlsTestState(t *testing.T, legacy bool) *State {
	t.Helper()
	cfg := config.Defaults()
	cfg.Listeners = []config.Listener{{Name: "test", Protocol: "http", Listen: "tcp://127.0.0.1:0", Mode: "tunnel"}}
	cfg.Legacy.Enabled = legacy
	cfg.Legacy.Retry = legacy
	cfg.Legacy.AllowHosts = []string{"127.0.0.1"}
	cfg.Legacy.RetryOn = []string{"protocol version", "handshake failure", "no cipher suite"}
	cfg.Routes = []config.Route{{Host: "127.0.0.1", Profile: "chrome-133", InsecureVerify: true}}
	registry, err := profiles.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	state, err := New(cfg, registry, new(slog.LevelVar))
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func startTLSServer(t *testing.T, tlsConfig *tls.Config) (net.Listener, <-chan uint16) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	versions := make(chan uint16, 1)
	go func() {
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
			conn := tls.Server(raw, tlsConfig)
			if err := conn.Handshake(); err != nil {
				conn.Close()
				continue
			}
			versions <- conn.ConnectionState().Version
			_ = conn.SetDeadline(time.Time{})
			go func() {
				_, _ = io.Copy(io.Discard, conn)
				conn.Close()
			}()
		}
	}()
	return listener, versions
}

func selfSignedRSA(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
