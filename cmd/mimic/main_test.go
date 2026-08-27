package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/msmythe/mimic/internal/config"
	"github.com/msmythe/mimic/internal/control"
	"github.com/msmythe/mimic/internal/engine"
	"github.com/msmythe/mimic/internal/fingerprint"
	"github.com/msmythe/mimic/internal/profiles"
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
	if err := run(nil, &stdout, &stderr); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("empty command error = %v", err)
	}
	for _, command := range []string{"--version", "-version", "--help", "-h"} {
		if err := run([]string{command}, &stdout, &stderr); err != nil {
			t.Errorf("run(%q): %v", command, err)
		}
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

func TestDaemonReloadAndRestartBoundary(t *testing.T) {
	dir := t.TempDir()
	controlPath := filepath.Join(dir, "control.sock")
	configPath := filepath.Join(dir, "config.toml")
	write := func(timeout, listener string) {
		t.Helper()
		body := `
version = 1
[control]
listen = "unix://` + controlPath + `"
[logging]
level = "error"
format = "json"
[runtime]
connect_timeout = "` + timeout + `"
[[listeners]]
name = "http"
protocol = "http"
listen = "` + listener + `"
mode = "tunnel"
`
		if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("1s", "tcp://127.0.0.1:0")
	errCh := make(chan error, 1)
	go func() { errCh <- daemon([]string{"-config", configPath}, io.Discard) }()
	waitForSocket(t, controlPath)
	endpoint := "unix://" + controlPath
	write("2s", "tcp://127.0.0.1:0")
	response, err := control.Call(context.Background(), endpoint, "config.reload", nil)
	if err != nil || response.Error != "" {
		t.Fatalf("mutable reload: %+v, %v", response, err)
	}
	write("2s", "tcp://127.0.0.1:1")
	response, err = control.Call(context.Background(), endpoint, "config.reload", nil)
	if err != nil || !strings.Contains(response.Error, "require a daemon restart") {
		t.Fatalf("immutable reload: %+v, %v", response, err)
	}
	response, err = control.Call(context.Background(), endpoint, "daemon.shutdown", nil)
	if err != nil || response.Error != "" {
		t.Fatalf("shutdown: %+v, %v", response, err)
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

func TestControlCLICommandsAndErrors(t *testing.T) {
	endpoint, configPath, stop, errCh := startCLIControlServer(t)
	for _, args := range [][]string{
		{"ctl", "-socket", endpoint, "info"},
		{"ctl", "-socket", endpoint, "status"},
		{"ctl", "-socket", endpoint, "profiles"},
		{"ctl", "-socket", endpoint, "use", "firefox-120"},
		{"ctl", "-socket", endpoint, "log-level", "warning"},
		{"ctl", "-socket", endpoint, "reload"},
		{"ctl", "-config", configPath, "status"},
	} {
		var output bytes.Buffer
		if err := run(args, &output, &output); err != nil {
			t.Errorf("run(%v): %v", args, err)
		} else if !json.Valid(output.Bytes()) {
			t.Errorf("run(%v) returned invalid JSON: %q", args, output.String())
		}
	}
	for _, args := range [][]string{
		{"ctl", "-socket", endpoint},
		{"ctl", "-socket", endpoint, "use"},
		{"ctl", "-socket", endpoint, "log-level"},
		{"ctl", "-socket", endpoint, "unknown"},
		{"ctl", "-socket", endpoint, "use", "missing"},
		{"ctl", "-socket", endpoint, "log-level", "verbose"},
		{"ctl", "-unknown"},
	} {
		if err := run(args, io.Discard, io.Discard); err == nil {
			t.Errorf("run(%v) unexpectedly succeeded", args)
		}
	}
	if err := run([]string{"ctl", "-socket", endpoint, "status"}, errorWriter{}, io.Discard); err == nil {
		t.Fatal("expected control output error")
	}
	if err := run([]string{"ctl", "-socket", endpoint, "shutdown"}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	stop()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("control server did not stop")
	}
	if err := run([]string{"ctl", "-socket", endpoint, "status"}, io.Discard, io.Discard); err == nil {
		t.Fatal("expected stopped control endpoint error")
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
	if err := run([]string{"init-ca", "-cert", certPath, "-key", keyPath}, &output, &output); err == nil {
		t.Fatal("expected CA overwrite error")
	}
	if err := run([]string{"init-ca", "-unknown"}, &output, &output); err == nil {
		t.Fatal("expected init-ca flag error")
	}

	mitmConfig := filepath.Join(dir, "mitm.toml")
	mitmBody := `
version = 1
[mitm]
enabled = true
ca_cert = "` + certPath + `"
ca_key = "` + keyPath + `"
leaf_ttl = "1h"
[[listeners]]
name = "intercept"
protocol = "http"
listen = "tcp://127.0.0.1:0"
mode = "intercept"
`
	if err := os.WriteFile(mitmConfig, []byte(mitmBody), 0o600); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := run([]string{"validate", "-config", mitmConfig}, &output, &output); err != nil {
		t.Fatalf("validate MITM config: %v", err)
	}
	if err := run([]string{"validate", "-unknown"}, &output, &output); err == nil {
		t.Fatal("expected validate flag error")
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

func TestValidateRejectsUnknownProfilePreset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	body := `
version = 1
[profiles.bad]
hello = "unknown-browser"
[[listeners]]
name = "http"
protocol = "http"
listen = "tcp://127.0.0.1:0"
mode = "tunnel"
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"validate", "-config", path}, io.Discard, io.Discard); err == nil {
		t.Fatal("expected unknown profile preset error")
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

func TestProbeFlagAndReportVariants(t *testing.T) {
	for _, args := range [][]string{
		{"probe"},
		{"probe", "-target", "example.test", "-format", "yaml"},
		{"probe", "-target", "example.test", "positional"},
		{"probe", "-unknown"},
		{"probe", "-target", "example.test", "-expect", "q13d1516h2_8daaf6152771_d8a2da3f94cd"},
	} {
		if err := run(args, io.Discard, io.Discard); err == nil {
			t.Errorf("run(%v) unexpectedly succeeded", args)
		}
	}

	match := true
	report := probeReport{
		Target:      "example.test:443",
		Profile:     "chrome-133",
		Route:       "*.example.test",
		ExpectedJA4: "t13d1516h2_8daaf6152771_d8a2da3f94cd",
		ObservedJA4: "t13d1516h2_8daaf6152771_d8a2da3f94cd",
		Status:      "pass",
		Match:       &match,
		Attempts: []engine.HandshakeAttempt{{
			CapturedBytes:     512,
			NegotiatedVersion: "TLS1.3",
			Cipher:            "TLS_AES_128_GCM_SHA256",
			ALPN:              "h2",
			JA4: &fingerprint.JA4{
				Raw:      "raw-sorted",
				Original: "raw-original",
			},
		}, {Legacy: true, Error: "fallback error"}},
	}
	var output bytes.Buffer
	if err := writeProbeReport(&output, report, "text", true); err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"route:", "TLS1.3", "alpn=h2", "JA4_r:", "legacy fallback", "fallback error"} {
		if !strings.Contains(output.String(), fragment) {
			t.Errorf("text report omitted %q:\n%s", fragment, output.String())
		}
	}
	output.Reset()
	if err := writeProbeReport(&output, probeReport{Status: "unverified"}, "text", false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "not configured") || !strings.Contains(output.String(), "unavailable") {
		t.Fatalf("unverified report = %q", output.String())
	}
	if err := writeProbeReport(errorWriter{}, report, "json", false); err == nil {
		t.Fatal("expected JSON report write error")
	}
}

func TestNewProbeReportStates(t *testing.T) {
	ja4 := &fingerprint.JA4{Fingerprint: "observed"}
	base := engine.ProbeResult{Target: "target", Profile: "profile", Attempts: []engine.HandshakeAttempt{{JA4: ja4}}}
	if got := newProbeReport(base, "", nil); got.Status != "unverified" || got.Match != nil {
		t.Fatalf("unverified report: %+v", got)
	}
	if got := newProbeReport(base, "expected", nil); got.Status != "mismatch" || got.Match == nil || *got.Match {
		t.Fatalf("mismatch report: %+v", got)
	}
	base.Attempts = nil
	if got := newProbeReport(base, "", errors.New("failed")); got.Status != "error" {
		t.Fatalf("error report: %+v", got)
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
	for _, raw := range []string{"", "http://example.test", "https://user@example.test", "https://", "example.test:", "bad/path"} {
		if _, err := normalizeProbeTarget(raw); err == nil {
			t.Errorf("normalizeProbeTarget(%q) unexpectedly succeeded", raw)
		}
	}
}

func TestDefaultConfigPathEnvironment(t *testing.T) {
	t.Setenv("MIMIC_CONFIG", "/tmp/mimic-explicit.toml")
	if got := defaultConfigPath(); got != "/tmp/mimic-explicit.toml" {
		t.Fatalf("defaultConfigPath = %q", got)
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

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func waitForSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("socket %s did not appear", path)
}

func startCLIControlServer(t *testing.T) (string, string, context.CancelFunc, <-chan error) {
	t.Helper()
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "control.sock")
	endpoint := "unix://" + socketPath
	configPath := filepath.Join(dir, "config.toml")
	body := `
version = 1
[control]
listen = "` + endpoint + `"
[[listeners]]
name = "http"
protocol = "http"
listen = "tcp://127.0.0.1:0"
mode = "tunnel"
`
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := profiles.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	state, err := engine.New(cfg, registry, new(slog.LevelVar))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	server := control.NewServer(state, slog.New(slog.NewTextHandler(io.Discard, nil)), func() error { return nil }, cancel)
	errCh := make(chan error, 1)
	go func() { errCh <- server.Serve(ctx, endpoint) }()
	waitForSocket(t, socketPath)
	return endpoint, configPath, cancel, errCh
}
