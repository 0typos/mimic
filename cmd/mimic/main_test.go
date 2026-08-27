package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/msmythe/mimic/internal/control"
)

func TestRunVersionHelpAndUnknown(t *testing.T) {
	original := version
	version = "test-version"
	defer func() { version = original }()
	var stdout, stderr bytes.Buffer
	if err := run([]string{"version"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "test-version\n" {
		t.Fatalf("version output = %q", stdout.String())
	}
	stdout.Reset()
	if err := run([]string{"help"}, &stdout, &stderr); err != nil || !strings.Contains(stdout.String(), "fingerprint-aware") {
		t.Fatalf("help output = %q, %v", stdout.String(), err)
	}
	if err := run([]string{"not-a-command"}, &stdout, &stderr); err == nil {
		t.Fatal("expected unknown command error")
	}
}

func TestDaemonLifecycle(t *testing.T) {
	dir := t.TempDir()
	controlPath := filepath.Join(dir, "control.sock")
	configPath := filepath.Join(dir, "config.toml")
	configBody := `
version = 1
[control]
listen = "unix://` + controlPath + `"
[logging]
level = "error"
format = "text"
[[listeners]]
name = "http"
protocol = "http"
listen = "tcp://127.0.0.1:0"
mode = "tunnel"
`
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatal(err)
	}
	errCh := make(chan error, 1)
	go func() { errCh <- daemon([]string{"-config", configPath}, &bytes.Buffer{}) }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(controlPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("daemon control socket did not appear")
		}
		time.Sleep(10 * time.Millisecond)
	}
	endpoint := "unix://" + controlPath
	response, err := control.Call(context.Background(), endpoint, "status", nil)
	if err != nil || response.Error != "" {
		t.Fatalf("daemon status: %+v, %v", response, err)
	}
	response, err = control.Call(context.Background(), endpoint, "daemon.shutdown", nil)
	if err != nil || response.Error != "" {
		t.Fatalf("daemon shutdown: %+v, %v", response, err)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("daemon did not stop")
	}
}

func TestRunValidateAndInitCA(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	configBody := `
version = 1
[control]
listen = "unix:///tmp/mimic-cli-test.sock"
[[listeners]]
name = "http"
protocol = "http"
listen = "tcp://127.0.0.1:0"
mode = "tunnel"
`
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := run([]string{"validate", "-config", configPath}, &output, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "valid:") {
		t.Fatalf("validate output = %q", output.String())
	}
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")
	output.Reset()
	if err := run([]string{"init-ca", "-cert", certPath, "-key", keyPath}, &output, &output); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{certPath, keyPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected %s: %v", path, err)
		}
	}
}

func TestValidateRejectsUnknownRouteProfile(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.toml")
	configBody := `
version = 1
[[listeners]]
name = "http"
protocol = "http"
listen = "tcp://127.0.0.1:0"
mode = "tunnel"
[[routes]]
host = "*.example.test"
profile = "missing"
`
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err := run([]string{"validate", "-config", configPath}, &output, &output)
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("expected invalid route profile, got %v", err)
	}
}

func TestValidateRejectsInvalidCA(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")
	if err := os.WriteFile(certPath, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.toml")
	configBody := `
version = 1
[mitm]
enabled = true
ca_cert = "` + certPath + `"
ca_key = "` + keyPath + `"
[[listeners]]
name = "intercept"
protocol = "http"
listen = "tcp://127.0.0.1:0"
mode = "intercept"
`
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := run([]string{"validate", "-config", configPath}, &output, &output); err == nil {
		t.Fatal("expected invalid CA rejection")
	}
}

func TestProbeReportsMatchingEmittedJA4(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		t.Fatal(err)
	}
	target := "https://" + net.JoinHostPort("localhost", port)
	configPath := writeProbeConfig(t)
	var stdout, stderr bytes.Buffer
	err = run([]string{"probe", "-config", configPath, "-profile", "chrome-133", "-target", target, "-format", "json"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("probe: %v, stderr=%s", err, stderr.String())
	}
	var report probeReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("decode report: %v\n%s", err, stdout.String())
	}
	if report.Status != "pass" || report.Match == nil || !*report.Match {
		t.Fatalf("unexpected report: %+v", report)
	}
	if report.ObservedJA4 == "" || report.ObservedJA4 != report.ExpectedJA4 {
		t.Fatalf("unexpected fingerprints: %+v", report)
	}
	if len(report.Attempts) != 1 || report.Attempts[0].JA4 == nil || !report.Attempts[0].JA4.SNI {
		t.Fatalf("missing ClientHello evidence: %+v", report.Attempts)
	}
}

func TestProbeMismatchReturnsFailureAfterReport(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	parsed, _ := url.Parse(server.URL)
	_, port, _ := net.SplitHostPort(parsed.Host)
	target := "https://" + net.JoinHostPort("localhost", port)
	var stdout, stderr bytes.Buffer
	err := run([]string{
		"probe", "-config", writeProbeConfig(t), "-profile", "chrome-133",
		"-target", target, "-expect", "t13d000000_000000000000_000000000000", "-format", "json",
	}, &stdout, &stderr)
	if !errors.Is(err, errProbeMismatch) {
		t.Fatalf("expected mismatch error, got %v", err)
	}
	var report probeReport
	if decodeErr := json.Unmarshal(stdout.Bytes(), &report); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if report.Status != "mismatch" || report.Match == nil || *report.Match {
		t.Fatalf("unexpected mismatch report: %+v", report)
	}
}

func TestProbeRejectsMalformedExpectationBeforeLoadingConfig(t *testing.T) {
	var output bytes.Buffer
	err := run([]string{"probe", "-target", "example.test", "-expect", "not-a-ja4"}, &output, &output)
	if err == nil || !strings.Contains(err.Error(), "normalized JA4 fingerprint") {
		t.Fatalf("expected malformed fingerprint error, got %v", err)
	}
}

func TestNormalizeProbeTarget(t *testing.T) {
	for _, test := range []struct {
		raw, want string
	}{
		{"https://example.test/path?q=1", "example.test:443"},
		{"example.test", "example.test:443"},
		{"example.test:8443", "example.test:8443"},
		{"2001:db8::1", "[2001:db8::1]:443"},
	} {
		got, err := normalizeProbeTarget(test.raw)
		if err != nil || got != test.want {
			t.Errorf("normalizeProbeTarget(%q) = %q, %v; want %q", test.raw, got, err, test.want)
		}
	}
	for _, raw := range []string{"", "http://example.test", "https://user@example.test", "bad/path"} {
		if _, err := normalizeProbeTarget(raw); err == nil {
			t.Errorf("normalizeProbeTarget(%q) unexpectedly succeeded", raw)
		}
	}
}

func writeProbeConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	body := `
version = 1
[legacy]
insecure_skip_verify = true
[[listeners]]
name = "http"
protocol = "http"
listen = "tcp://127.0.0.1:0"
mode = "tunnel"
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
