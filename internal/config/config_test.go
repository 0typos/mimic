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
	if cfg.Logging.Level != "info" || cfg.Runtime.DefaultProfile != "chrome-152-linux" {
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

func TestLoadErrorsAndRelativeSecurityPaths(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "missing.toml")); err == nil {
		t.Fatal("expected missing config error")
	}
	dir := t.TempDir()
	for _, name := range []string{"ca.pem", "key.pem"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "config.toml")
	data := `
version = 1
[mitm]
enabled = true
ca_cert = "ca.pem"
ca_key = "key.pem"
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
	if cfg.MITM.CACert != filepath.Join(dir, "ca.pem") || cfg.MITM.CAKey != filepath.Join(dir, "key.pem") {
		t.Fatalf("MITM paths were not resolved: %+v", cfg.MITM)
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
		"%",
		"tcp://127.0.0.1",
		"tcp://127.0.0.1:8080/path",
		"tcp://user@127.0.0.1:8080",
		"tcp://127.0.0.1:8080?query=yes",
		"tcp://127.0.0.1:8080#fragment",
		"unix://relative/socket",
		"unix://host/tmp/socket",
		"udp://127.0.0.1",
		"udp://127.0.0.1:53/path",
		"npipe://mimic",
	} {
		if _, _, err := ParseEndpoint(raw, true); err == nil {
			t.Errorf("ParseEndpoint(%q) unexpectedly succeeded", raw)
		}
	}
	if _, _, err := ParseEndpoint("udp://127.0.0.1:53", false); err == nil {
		t.Fatal("UDP endpoint unexpectedly accepted where disabled")
	}
}

func TestTLSVersionAliases(t *testing.T) {
	for _, test := range []struct {
		raw  string
		want uint16
	}{
		{"TLS1", 0x0301}, {"tls1.0", 0x0301}, {"tls10", 0x0301},
		{"tls1.1", 0x0302}, {"tls11", 0x0302},
		{"tls1.2", 0x0303}, {"tls12", 0x0303},
		{"tls1.3", 0x0304}, {"tls13", 0x0304},
	} {
		got, err := TLSVersion(test.raw)
		if err != nil || got != test.want {
			t.Errorf("TLSVersion(%q) = %x, %v; want %x", test.raw, got, err, test.want)
		}
	}
	if _, err := TLSVersion("ssl3"); err == nil {
		t.Fatal("unsupported TLS version unexpectedly accepted")
	}
}

func TestValidComplexConfiguration(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "ca.pem")
	key := filepath.Join(dir, "key.pem")
	for _, path := range []string{cert, key} {
		if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := Defaults()
	cfg.Control.Listen = "tcp://localhost:0"
	cfg.Logging.Level = "warning"
	cfg.Logging.Format = "json"
	cfg.MITM = MITM{Enabled: true, CACert: cert, CAKey: key, LeafTTL: "1h"}
	cfg.Listeners = []Listener{
		{Name: "http", Protocol: "http", Listen: "tcp://127.0.0.1:0", Mode: "intercept", AllowCIDRs: []string{"127.0.0.0/8"}},
		{Name: "socks", Protocol: "socks5", Listen: "tcp://127.0.0.1:0", UDPListen: "udp://127.0.0.1:0"},
		{Name: "caido", Protocol: "caido", Listen: "unix:///tmp/mimic-caido-coverage.sock"},
	}
	cfg.Profiles["custom"] = Profile{
		Hello:       "chrome-133",
		JA4:         "t13d1516h2_8daaf6152771_d8a2da3f94cd",
		UserAgent:   "coverage-agent",
		HeaderOrder: []string{"host", "user-agent"},
		Headers:     map[string]string{"X-Coverage": "yes"},
		MinVersion:  "tls1.2",
		MaxVersion:  "tls1.3",
	}
	cfg.Routes = []Route{{Host: "*.example.test", Profile: "custom"}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidationRejectsOperationallyInvalidValues(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"no listeners", func(c *Config) { c.Listeners = nil }, "at least one"},
		{"version", func(c *Config) { c.Version = 2 }, "version must be 1"},
		{"control endpoint", func(c *Config) { c.Control.Listen = "invalid" }, "control.listen"},
		{"remote control", func(c *Config) { c.Control.Listen = "tcp://0.0.0.0:9000" }, "must be loopback"},
		{"bad timeout", func(c *Config) { c.Runtime.HandshakeTimeout = "soon" }, "handshake_timeout"},
		{"negative timeout", func(c *Config) { c.Runtime.ConnectTimeout = "-1s" }, "greater than zero"},
		{"MITM paths", func(c *Config) { c.MITM.Enabled = true }, "ca_cert and mitm.ca_key"},
		{"MITM files", func(c *Config) {
			c.MITM = MITM{Enabled: true, CACert: "/missing/cert", CAKey: "/missing/key", LeafTTL: "1h"}
		}, "MITM file"},
		{"leaf TTL", func(c *Config) { c.MITM.LeafTTL = "never" }, "mitm.leaf_ttl"},
		{"legacy version", func(c *Config) { c.Legacy.MinVersion = "ssl3" }, "legacy.min_version"},
		{"legacy tls13", func(c *Config) { c.Legacy.MinVersion = "tls1.3" }, "cannot be higher"},
		{"empty legacy host", func(c *Config) { c.Legacy.AllowHosts = []string{""} }, "cannot be empty"},
		{"listener name", func(c *Config) { c.Listeners[0].Name = "" }, "name is required"},
		{"duplicate listener", func(c *Config) { c.Listeners = append(c.Listeners, c.Listeners[0]) }, "duplicate listener"},
		{"listener protocol", func(c *Config) { c.Listeners[0].Protocol = "smtp" }, "protocol must be"},
		{"HTTP mode", func(c *Config) { c.Listeners[0].Mode = "magic" }, "mode must be"},
		{"non-HTTP mode", func(c *Config) {
			c.Listeners[0].Protocol, c.Listeners[0].Mode = "caido", "tunnel"
		}, "mode is only valid"},
		{"listener endpoint", func(c *Config) { c.Listeners[0].Listen = "invalid" }, "listeners[0].listen"},
		{"SOCKS UDP endpoint", func(c *Config) {
			c.Listeners[0] = Listener{Name: "socks", Protocol: "socks5", Listen: "tcp://127.0.0.1:0", UDPListen: "tcp://127.0.0.1:1"}
		}, "udp_listen must be"},
		{"HTTP UDP field", func(c *Config) { c.Listeners[0].UDPListen = "udp://127.0.0.1:0" }, "only valid for SOCKS5"},
		{"allow CIDR", func(c *Config) { c.Listeners[0].AllowCIDRs = []string{"invalid"} }, "invalid CIDR"},
		{"log level", func(c *Config) { c.Logging.Level = "verbose" }, "logging.level"},
		{"log format", func(c *Config) { c.Logging.Format = "yaml" }, "logging.format"},
		{"default profile", func(c *Config) { c.Runtime.DefaultProfile = "" }, "default_profile"},
		{"legacy host glob", func(c *Config) { c.Legacy.AllowHosts = []string{"["} }, "invalid glob"},
		{"route host", func(c *Config) { c.Routes = []Route{{Profile: "chrome-133"}} }, "host is required"},
		{"route glob", func(c *Config) { c.Routes = []Route{{Host: "[", Profile: "chrome-133"}} }, "invalid glob"},
		{"route profile", func(c *Config) { c.Routes = []Route{{Host: "*"}} }, "profile is required"},
		{"empty profile name", func(c *Config) { c.Profiles[""] = Profile{Hello: "chrome-133"} }, "profile name cannot be empty"},
		{"profile identity", func(c *Config) { c.Profiles["bad"] = Profile{} }, "requires hello"},
		{"profile identities", func(c *Config) {
			c.Profiles["bad"] = Profile{Hello: "chrome-133", ClientHelloFile: "hello.bin"}
		}, "cannot set both"},
		{"profile TLS version", func(c *Config) {
			c.Profiles["bad"] = Profile{Hello: "chrome-133", MinVersion: "ssl3"}
		}, "unsupported TLS version"},
		{"JA4 transport", func(c *Config) {
			c.Profiles["bad"] = Profile{Hello: "chrome-133", JA4: "q13d1516h2_8daaf6152771_d8a2da3f94cd"}
		}, "TLS over TCP"},
		{"user agent", func(c *Config) {
			c.Profiles["bad"] = Profile{Hello: "chrome-133", UserAgent: "one\ntwo"}
		}, "user_agent"},
		{"header order", func(c *Config) {
			c.Profiles["bad"] = Profile{Hello: "chrome-133", HeaderOrder: []string{"Bad Header"}}
		}, "header_order"},
		{"header name", func(c *Config) {
			c.Profiles["bad"] = Profile{Hello: "chrome-133", Headers: map[string]string{"Bad Header": "value"}}
		}, "invalid HTTP header name"},
		{"header value", func(c *Config) {
			c.Profiles["bad"] = Profile{Hello: "chrome-133", Headers: map[string]string{"X-Test": "one\ntwo"}}
		}, "valid HTTP header value"},
		{"JA4 shape", func(c *Config) {
			c.Profiles["bad"] = Profile{Hello: "chrome-133", JA4: "not-a-ja4"}
		}, "normalized JA4"},
		{"profile versions", func(c *Config) {
			c.Profiles["bad"] = Profile{Hello: "chrome-133", MinVersion: "tls1.3", MaxVersion: "tls1.2"}
		}, "min_version cannot"},
		{"profile lifecycle", func(c *Config) {
			c.Profiles["bad"] = Profile{Hello: "chrome-133", Lifecycle: "stale"}
		}, "lifecycle"},
		{"profile captured at", func(c *Config) {
			c.Profiles["bad"] = Profile{Hello: "chrome-133", CapturedAt: "yesterday"}
		}, "captured_at"},
		{"profile metadata newline", func(c *Config) {
			c.Profiles["bad"] = Profile{Hello: "chrome-133", Browser: "one\ntwo"}
		}, "browser"},
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
