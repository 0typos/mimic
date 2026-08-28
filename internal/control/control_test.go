package control

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/0typos/mimic/internal/config"
	"github.com/0typos/mimic/internal/engine"
	"github.com/0typos/mimic/internal/profiles"
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
	response, err = Call(context.Background(), endpoint, "ping", nil)
	if err != nil || response.Error != "" {
		t.Fatalf("ping: %+v, %v", response, err)
	}
	response, err = Call(context.Background(), endpoint, "profiles.list", nil)
	if err != nil || response.Error != "" {
		t.Fatalf("profiles.list: %+v, %v", response, err)
	}
	response, err = Call(context.Background(), endpoint, "profile.use", map[string]string{"name": "firefox-120"})
	if err != nil || response.Error != "" || state.Status().Profile != "firefox-120" {
		t.Fatalf("profile.use: %+v, %v", response, err)
	}
	response, err = Call(context.Background(), endpoint, "log.set", map[string]string{"level": "debug"})
	if err != nil || response.Error != "" {
		t.Fatalf("log.set: %+v, %v", response, err)
	}
	response, err = Call(context.Background(), endpoint, "config.reload", nil)
	if err != nil || response.Error != "" {
		t.Fatalf("config.reload: %+v, %v", response, err)
	}

	address, network, _ := config.ParseEndpoint(endpoint, false)
	raw, err := net.Dial(network, address)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(raw, "{invalid\n"); err != nil {
		t.Fatal(err)
	}
	var malformed Response
	if err := json.NewDecoder(raw).Decode(&malformed); err != nil || !strings.Contains(malformed.Error, "invalid request") {
		t.Fatalf("malformed request response: %+v, %v", malformed, err)
	}
	raw.Close()
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

func TestDispatchValidationAndReloadFailure(t *testing.T) {
	state := newControlState(t)
	server := NewServer(state, slog.New(slog.NewTextHandler(io.Discard, nil)), func() error {
		return errors.New("reload failed")
	}, func() {})
	for name, request := range map[string]Request{
		"profile JSON":    {Method: "profile.use", Params: json.RawMessage(`{`)},
		"profile name":    {Method: "profile.use", Params: json.RawMessage(`{}`)},
		"profile unknown": {Method: "profile.use", Params: json.RawMessage(`{"name":"missing"}`)},
		"log JSON":        {Method: "log.set", Params: json.RawMessage(`{`)},
		"log level":       {Method: "log.set", Params: json.RawMessage(`{"level":"verbose"}`)},
		"reload":          {Method: "config.reload"},
	} {
		t.Run(name, func(t *testing.T) {
			if response := server.dispatch(request); response.Error == "" {
				t.Fatalf("%s unexpectedly succeeded: %+v", name, response)
			}
		})
	}
}

func TestCallFailurePaths(t *testing.T) {
	if _, err := Call(context.Background(), "invalid", "ping", nil); err == nil {
		t.Fatal("expected invalid endpoint error")
	}

	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddress := closed.Addr().String()
	closed.Close()
	if _, err := Call(context.Background(), "tcp://"+closedAddress, "ping", nil); err == nil {
		t.Fatal("expected connection error")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{})
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			close(accepted)
			defer conn.Close()
			var request Request
			_ = json.NewDecoder(conn).Decode(&request)
			_, _ = io.WriteString(conn, "not-json\n")
		}
	}()
	if _, err := Call(context.Background(), "tcp://"+listener.Addr().String(), "ping", nil); err == nil {
		t.Fatal("expected response decode error")
	}
	<-accepted

	marshalListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer marshalListener.Close()
	go func() {
		conn, acceptErr := marshalListener.Accept()
		if acceptErr == nil {
			conn.Close()
		}
	}()
	if _, err := Call(context.Background(), "tcp://"+marshalListener.Addr().String(), "ping", make(chan int)); err == nil {
		t.Fatal("expected parameter marshal error")
	}
}

func TestControlListenFailureAndSocketReplacement(t *testing.T) {
	state := newControlState(t)
	server := NewServer(state, slog.New(slog.NewTextHandler(io.Discard, nil)), func() error { return nil }, func() {})
	if err := server.Serve(context.Background(), "invalid"); err == nil {
		t.Fatal("expected invalid endpoint error")
	}

	dir := t.TempDir()
	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	if listener, err := listen("unix://" + regular); err == nil {
		listener.Close()
		t.Fatal("expected regular-file replacement refusal")
	}
	if listener, err := listen("unix://" + filepath.Join(regular, "socket")); err == nil {
		listener.Close()
		t.Fatal("expected socket directory creation error")
	}

	socket := filepath.Join(dir, "replace.sock")
	first, err := listen("unix://" + socket)
	if err != nil {
		t.Fatal(err)
	}
	first.Close()
	second, err := listen("unix://" + socket)
	if err != nil {
		t.Fatalf("replace stale socket: %v", err)
	}
	second.Close()

	tcp, err := listen("tcp://localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	tcp.Close()

	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	if duplicate, err := listen("tcp://" + occupied.Addr().String()); err == nil {
		duplicate.Close()
		t.Fatal("expected occupied TCP endpoint error")
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
