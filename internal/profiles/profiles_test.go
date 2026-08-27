package profiles

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/msmythe/mimic/internal/config"
)

func TestRegistryIncludesBuiltinsAndCustomPreset(t *testing.T) {
	registry, err := New(map[string]config.Profile{
		"lab": {Hello: "firefox-99", JA4: "expected", HeaderOrder: []string{"host", "user-agent"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	builtin, ok := registry.Get("chrome-133")
	if !ok {
		t.Fatal("chrome builtin missing")
	}
	if builtin.JA4 == "" {
		t.Fatal("chrome builtin has no expected JA4")
	}
	p, ok := registry.Get("lab")
	if !ok || p.JA4 != "expected" || p.Hello.Version != "99" {
		t.Fatalf("custom profile not loaded: %+v", p)
	}
}

func TestRegistryRejectsUnknownPreset(t *testing.T) {
	_, err := New(map[string]config.Profile{"bad": {Hello: "netscape-2"}})
	if err == nil {
		t.Fatal("expected unknown preset error")
	}
}

func TestRegistryRejectsMalformedCapturedClientHello(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.hex")
	if err := os.WriteFile(path, []byte("00010203"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := New(map[string]config.Profile{"bad": {ClientHelloFile: path}})
	if err == nil {
		t.Fatal("expected malformed ClientHello error")
	}
}
