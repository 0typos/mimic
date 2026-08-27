package profiles

import (
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/msmythe/mimic/internal/config"
)

func TestRegistryIncludesBuiltinsAndCustomPreset(t *testing.T) {
	headers := map[string]string{"X-Test": "original"}
	order := []string{"host", "user-agent"}
	registry, err := New(map[string]config.Profile{
		"lab": {Hello: "firefox-99", JA4: "expected", HeaderOrder: order, Headers: headers},
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
	headers["X-Test"] = "mutated"
	order[0] = "mutated"
	if p.Headers["X-Test"] != "original" || p.HeaderOrder[0] != "host" {
		t.Fatalf("profile retained mutable config data: %+v", p)
	}
	names := registry.Names()
	if !slices.IsSorted(names) || !slices.Contains(names, "lab") {
		t.Fatalf("registry names are not sorted and complete: %v", names)
	}
	if err := builtin.Apply(nil); err != nil {
		t.Fatalf("preset profile Apply: %v", err)
	}
	infos := registry.Infos()
	if len(infos) != 11 || !slices.IsSortedFunc(infos, func(a, b Info) int { return strings.Compare(a.Name, b.Name) }) {
		t.Fatalf("profile metadata is not sorted and complete: %+v", infos)
	}
	foundCustom := false
	for _, info := range infos {
		if info.Name == "lab" {
			foundCustom = info.Lifecycle == "custom" && !info.Builtin
		}
	}
	if !foundCustom {
		t.Fatalf("custom metadata missing: %+v", infos)
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

func TestRegistryLoadsHexAndBinaryClientHellos(t *testing.T) {
	raw := capturedClientHello(t)
	dir := t.TempDir()
	hexPath := filepath.Join(dir, "hello.hex")
	encoded := hex.EncodeToString(raw)
	spaced := strings.Join(splitEvery(encoded, 8), " ")
	if err := os.WriteFile(hexPath, []byte(spaced), 0o600); err != nil {
		t.Fatal(err)
	}
	binaryPath := filepath.Join(dir, "hello.bin")
	if err := os.WriteFile(binaryPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	registry, err := New(map[string]config.Profile{
		"hex": {
			ClientHelloFile: hexPath,
			MinVersion:      "tls1.2",
			MaxVersion:      "tls1.3",
		},
		"binary": {ClientHelloFile: binaryPath},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"hex", "binary"} {
		profile, ok := registry.Get(name)
		if !ok || profile.Hello != utls.HelloCustom || len(profile.RawClientHello) == 0 {
			t.Fatalf("captured profile %q was not loaded: %+v", name, profile)
		}
		client, server := net.Pipe()
		conn := utls.UClient(client, &utls.Config{ServerName: "example.test"}, utls.HelloCustom)
		if err := profile.Apply(conn); err != nil {
			t.Fatalf("Apply(%q): %v", name, err)
		}
		client.Close()
		server.Close()
	}
	hexProfile, _ := registry.Get("hex")
	if hexProfile.MinVersion != utls.VersionTLS12 || hexProfile.MaxVersion != utls.VersionTLS13 {
		t.Fatalf("captured version bounds = %x..%x", hexProfile.MinVersion, hexProfile.MaxVersion)
	}
}

func TestCapturedProfileReadAndApplyErrors(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.bin")
	if _, err := New(map[string]config.Profile{"missing": {ClientHelloFile: missing}}); err == nil {
		t.Fatal("expected missing capture error")
	}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	conn := utls.UClient(client, &utls.Config{}, utls.HelloCustom)
	if err := (Profile{Name: "bad", RawClientHello: []byte{1, 2, 3}}).Apply(conn); err == nil {
		t.Fatal("expected malformed saved ClientHello error")
	}
}

func capturedClientHello(t *testing.T) []byte {
	t.Helper()
	client, server := net.Pipe()
	errCh := make(chan error, 1)
	go func() {
		conn := utls.UClient(client, &utls.Config{ServerName: "example.test", InsecureSkipVerify: true}, utls.HelloChrome_133)
		errCh <- conn.Handshake()
	}()
	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	header := make([]byte, 5)
	if _, err := io.ReadFull(server, header); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, int(binary.BigEndian.Uint16(header[3:5])))
	if _, err := io.ReadFull(server, payload); err != nil {
		t.Fatal(err)
	}
	server.Close()
	select {
	case <-errCh:
	case <-time.After(time.Second):
		t.Fatal("capturing ClientHello did not terminate")
	}
	return append(header, payload...)
}

func splitEvery(value string, width int) []string {
	var parts []string
	for len(value) > 0 {
		end := min(width, len(value))
		parts = append(parts, value[:end])
		value = value[end:]
	}
	return parts
}
