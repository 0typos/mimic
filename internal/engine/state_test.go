package engine

import (
	"log/slog"
	"testing"

	"github.com/0typos/mimic/internal/config"
	"github.com/0typos/mimic/internal/profiles"
)

func testState(t *testing.T, mutate func(*config.Config)) *State {
	t.Helper()
	cfg := config.Defaults()
	cfg.Listeners = []config.Listener{{Name: "test", Protocol: "http", Listen: "tcp://127.0.0.1:0", Mode: "tunnel"}}
	if mutate != nil {
		mutate(&cfg)
	}
	registry, err := profiles.New(cfg.Profiles)
	if err != nil {
		t.Fatal(err)
	}
	state, err := New(cfg, registry, new(slog.LevelVar))
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func TestStateSelectRouteAndStatus(t *testing.T) {
	state := testState(t, func(cfg *config.Config) {
		cfg.Routes = []config.Route{{Host: "*.lab.test", Profile: "firefox-120"}}
	})
	if err := state.Select("safari-16"); err != nil {
		t.Fatal(err)
	}
	if err := state.Select("missing"); err == nil {
		t.Fatal("expected unknown profile error")
	}
	profile, _, ok := state.ProfileForHost("node.lab.test:443")
	if !ok || profile.Name != "firefox-120" {
		t.Fatalf("routed profile = %+v, %v", profile, ok)
	}
	profile, _, ok = state.ProfileForHostAs("node.lab.test:443", "android-11")
	if !ok || profile.Name != "android-11" {
		t.Fatalf("override profile = %+v, %v", profile, ok)
	}
	state.ConnectionOpened()
	state.RequestHandled()
	state.FallbackUsed()
	status := state.Status()
	if status.Profile != "safari-16" || status.Connections != 1 || status.Requests != 1 || status.TLSFallbacks != 1 {
		t.Fatalf("unexpected status: %+v", status)
	}
}

func TestStateReloadValidatesRoutesAndRetainsSelection(t *testing.T) {
	state := testState(t, nil)
	if err := state.Select("firefox-120"); err != nil {
		t.Fatal(err)
	}
	cfg := state.Snapshot().Config
	cfg.Routes = []config.Route{{Host: "*", Profile: "missing"}}
	registry, _ := profiles.New(cfg.Profiles)
	if err := state.Reload(cfg, registry); err == nil {
		t.Fatal("expected invalid route profile error")
	}
	cfg.Routes = nil
	if err := state.Reload(cfg, registry); err != nil {
		t.Fatal(err)
	}
	if got := state.Status().Profile; got != "firefox-120" {
		t.Fatalf("selection after reload = %q", got)
	}
}

func TestStateConstructionAndReloadFailures(t *testing.T) {
	cfg := config.Defaults()
	cfg.Listeners = []config.Listener{{Name: "test", Protocol: "http", Listen: "tcp://127.0.0.1:0", Mode: "tunnel"}}
	registry, err := profiles.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Runtime.DefaultProfile = "missing"
	if _, err := New(cfg, registry, new(slog.LevelVar)); err == nil {
		t.Fatal("expected missing default profile error")
	}
	cfg.Runtime.DefaultProfile = "chrome-133"
	cfg.Routes = []config.Route{{Host: "*", Profile: "missing"}}
	if _, err := New(cfg, registry, new(slog.LevelVar)); err == nil {
		t.Fatal("expected missing route profile error")
	}

	state := testState(t, func(cfg *config.Config) {
		cfg.Profiles["temporary"] = config.Profile{Hello: "chrome-133"}
	})
	if err := state.Select("temporary"); err != nil {
		t.Fatal(err)
	}
	replacementRegistry, err := profiles.New(map[string]config.Profile{"replacement": {Hello: "chrome-133"}})
	if err != nil {
		t.Fatal(err)
	}
	reloadConfig := state.Snapshot().Config
	reloadConfig.Runtime.DefaultProfile = "replacement"
	if err := state.Reload(reloadConfig, replacementRegistry); err != nil {
		t.Fatal(err)
	}
	if state.Status().Profile != "replacement" {
		t.Fatalf("unexpected replacement selection: %q", state.Status().Profile)
	}

	badState := testState(t, func(cfg *config.Config) {
		cfg.Profiles["temporary"] = config.Profile{Hello: "chrome-133"}
	})
	if err := badState.Select("temporary"); err != nil {
		t.Fatal(err)
	}
	reloadConfig.Runtime.DefaultProfile = "missing"
	if err := badState.Reload(reloadConfig, replacementRegistry); err == nil {
		t.Fatal("expected reload default profile error")
	}
	state.SetLogLevel(slog.LevelError)
}

func TestHostMatch(t *testing.T) {
	for _, test := range []struct {
		pattern, host string
		want          bool
	}{
		{"*.example.test", "API.EXAMPLE.TEST", true},
		{"localhost", "localhost", true},
		{"*.example.test", "example.test", false},
		{"[", "anything", false},
		{"", "anything", false},
	} {
		if got := hostMatch(test.pattern, test.host); got != test.want {
			t.Errorf("hostMatch(%q, %q) = %v", test.pattern, test.host, got)
		}
	}
}

func TestStripPort(t *testing.T) {
	for _, test := range []struct {
		raw, want string
	}{
		{"example.test:443", "example.test"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"2001:db8::1", "2001:db8::1"},
		{"[2001:db8::1]", "2001:db8::1"},
	} {
		if got := stripPort(test.raw); got != test.want {
			t.Errorf("stripPort(%q) = %q, want %q", test.raw, got, test.want)
		}
	}
}
