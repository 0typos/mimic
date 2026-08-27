package control

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/msmythe/mimic/internal/config"
	"github.com/msmythe/mimic/internal/engine"
	"github.com/msmythe/mimic/internal/profiles"
)

func newControlState(t *testing.T) *engine.State {
	t.Helper()
	cfg := config.Defaults()
	cfg.Path = "/tmp/test-config.toml"
	cfg.Listeners = []config.Listener{{Name: "test", Protocol: "http", Listen: "tcp://127.0.0.1:0", Mode: "tunnel"}}
	registry, err := profiles.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	state, err := engine.New(cfg, registry, new(slog.LevelVar))
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func TestControlServerRoundTrip(t *testing.T) {
	state := newControlState(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	shutdownCalled := make(chan struct{}, 1)
	endpoint := "unix://" + filepath.Join(t.TempDir(), "control.sock")
	server := NewServer(state, slog.New(slog.NewTextHandler(os.Stderr, nil)), func() error { return nil }, func() {
		select {
		case shutdownCalled <- struct{}{}:
		default:
		}
	})
	errCh := make(chan error, 1)
	go func() { errCh <- server.Serve(ctx, endpoint) }()
	waitForControl(t, endpoint)

	response, err := Call(context.Background(), endpoint, "status", map[string]any{})
	if err != nil || response.Error != "" {
		t.Fatalf("status: %+v, %v", response, err)
	}
	response, err = Call(context.Background(), endpoint, "protocol.info", nil)
	if err != nil || response.Error != "" {
		t.Fatalf("protocol.info: %+v, %v", response, err)
	}
	info, ok := response.Result.(map[string]any)
	if !ok || info["version"] != float64(ProtocolVersion) {
		t.Fatalf("unexpected protocol info: %#v", response.Result)
	}
	rawCapabilities, ok := info["capabilities"].([]any)
	if !ok {
		t.Fatalf("unexpected capabilities: %#v", info["capabilities"])
	}
	capabilityNames := make([]string, 0, len(rawCapabilities))
	for _, capability := range rawCapabilities {
		capabilityNames = append(capabilityNames, capability.(string))
	}
	for _, method := range []string{"ping", "protocol.info", "status", "profiles.list", "profile.use", "log.set", "config.reload", "daemon.shutdown"} {
		if !slices.Contains(capabilityNames, method) {
			t.Errorf("protocol.info omitted %q: %v", method, capabilityNames)
		}
	}
	response, err = Call(context.Background(), endpoint, "profile.use", map[string]string{"name": "firefox-120"})
	if err != nil || response.Error != "" || state.Status().Profile != "firefox-120" {
		t.Fatalf("profile.use: %+v, %v", response, err)
	}
	response, err = Call(context.Background(), endpoint, "log.set", map[string]string{"level": "debug"})
	if err != nil || response.Error != "" {
		t.Fatalf("log.set: %+v, %v", response, err)
	}
	response, err = Call(context.Background(), endpoint, "missing", nil)
	if err != nil || response.Error == "" {
		t.Fatalf("unknown method: %+v, %v", response, err)
	}
	response, err = Call(context.Background(), endpoint, "daemon.shutdown", nil)
	if err != nil || response.Error != "" {
		t.Fatalf("shutdown: %+v, %v", response, err)
	}
	select {
	case <-shutdownCalled:
	case <-time.After(time.Second):
		t.Fatal("shutdown callback not called")
	}
	cancel()
	server.Close()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("control server did not stop")
	}
}

func TestParseLevelAndTCPRestriction(t *testing.T) {
	for _, level := range []string{"debug", "info", "warning", "error"} {
		if _, err := ParseLevel(level); err != nil {
			t.Errorf("ParseLevel(%q): %v", level, err)
		}
	}
	if _, err := ParseLevel("verbose"); err == nil {
		t.Fatal("expected invalid log level")
	}
	if listener, err := listen("tcp://0.0.0.0:0"); err == nil {
		listener.Close()
		t.Fatal("expected non-loopback rejection")
	}
}

func waitForControl(t *testing.T, endpoint string) {
	t.Helper()
	address, _, _ := config.ParseEndpoint(endpoint, false)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(address); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("control socket did not appear")
}
