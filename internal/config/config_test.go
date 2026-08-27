package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadAppliesDefaultsAndResolvesPaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	data := `
version = 1
[control]
listen = "unix:///tmp/mimic-test.sock"
[profiles.test]
client_hello_file = "profile.hex"
[[listeners]]
name = "http"
protocol = "http"
listen = "tcp://127.0.0.1:0"
mode = "tunnel"
`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Logging.Level != "info" || cfg.Runtime.DefaultProfile != "chrome-133" {
		t.Fatalf("defaults not retained: %+v", cfg)
	}
	want := filepath.Join(dir, "profile.hex")
	if got := cfg.Profiles["test"].ClientHelloFile; got != want {
		t.Fatalf("profile path = %q, want %q", got, want)
	}
}

func TestLoadRejectsUnknownKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("version = 1\nsurprise = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "surprise") {
		t.Fatalf("expected unknown-key error, got %v", err)
	}
}

func TestInterceptRequiresCA(t *testing.T) {
	cfg := Defaults()
	cfg.Listeners = []Listener{{Name: "intercept", Protocol: "http", Listen: "tcp://127.0.0.1:0", Mode: "intercept"}}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "mitm.enabled") {
		t.Fatalf("expected MITM validation error, got %v", err)
	}
}

func TestEndpointSchemes(t *testing.T) {
	for _, test := range []struct {
		raw, network string
		udp          bool
	}{
		{"tcp://127.0.0.1:8080", "tcp", false},
		{"unix:///tmp/mimic.sock", "unix", false},
		{"udp://127.0.0.1:1080", "udp", true},
	} {
		_, got, err := ParseEndpoint(test.raw, test.udp)
		if err != nil || got != test.network {
			t.Errorf("ParseEndpoint(%q) = %q, %v", test.raw, got, err)
		}
	}
	for _, raw := range []string{
		"tcp://127.0.0.1",
		"tcp://127.0.0.1:8080/path",
		"tcp://user@127.0.0.1:8080",
		"unix://relative/socket",
		"udp://127.0.0.1",
	} {
		if _, _, err := ParseEndpoint(raw, true); err == nil {
			t.Errorf("ParseEndpoint(%q) unexpectedly succeeded", raw)
		}
	}
}

func TestValidationRejectsOperationallyInvalidValues(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"no listeners", func(c *Config) { c.Listeners = nil }, "at least one"},
		{"remote control", func(c *Config) { c.Control.Listen = "tcp://0.0.0.0:9000" }, "must be loopback"},
		{"negative timeout", func(c *Config) { c.Runtime.ConnectTimeout = "-1s" }, "greater than zero"},
		{"legacy tls13", func(c *Config) { c.Legacy.MinVersion = "tls1.3" }, "cannot be higher"},
		{"HTTP mode", func(c *Config) { c.Listeners[0].Mode = "magic" }, "mode must be"},
		{"log level", func(c *Config) { c.Logging.Level = "verbose" }, "logging.level"},
		{"log format", func(c *Config) { c.Logging.Format = "yaml" }, "logging.format"},
		{"default profile", func(c *Config) { c.Runtime.DefaultProfile = "" }, "default_profile"},
		{"legacy host glob", func(c *Config) { c.Legacy.AllowHosts = []string{"["} }, "invalid glob"},
		{"route host", func(c *Config) { c.Routes = []Route{{Profile: "chrome-133"}} }, "host is required"},
		{"header name", func(c *Config) {
			c.Profiles["bad"] = Profile{Hello: "chrome-133", Headers: map[string]string{"Bad Header": "value"}}
		}, "invalid HTTP header name"},
		{"header value", func(c *Config) {
			c.Profiles["bad"] = Profile{Hello: "chrome-133", Headers: map[string]string{"X-Test": "one\ntwo"}}
		}, "valid HTTP header value"},
		{"profile versions", func(c *Config) {
			c.Profiles["bad"] = Profile{Hello: "chrome-133", MinVersion: "tls1.3", MaxVersion: "tls1.2"}
		}, "min_version cannot"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Listeners = []Listener{{Name: "http", Protocol: "http", Listen: "tcp://127.0.0.1:0", Mode: "tunnel"}}
			test.mutate(&cfg)
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected %q, got %v", test.want, err)
			}
		})
	}
}
