package proxy

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/msmythe/mimic/internal/config"
)

func TestReadSOCKSAddressVariants(t *testing.T) {
	ipv6 := net.ParseIP("2001:db8::1").To16()
	for _, test := range []struct {
		name string
		raw  []byte
		want string
	}{
		{"IPv4", []byte{1, 127, 0, 0, 1, 0, 80}, "127.0.0.1:80"},
		{"IPv6", append(append([]byte{4}, ipv6...), 1, 187), "[2001:db8::1]:443"},
		{"domain", append(append([]byte{3, 12}, []byte("example.test")...), 0, 53), "example.test:53"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := readSOCKSAddress(bytes.NewReader(test.raw))
			if err != nil || got != test.want {
				t.Fatalf("readSOCKSAddress = %q, %v; want %q", got, err, test.want)
			}
		})
	}
	for name, raw := range map[string][]byte{
		"type":          nil,
		"IPv4":          {1, 127},
		"IPv6":          {4, 1, 2},
		"domain length": {3},
		"domain":        {3, 4, 't'},
		"type unknown":  {9},
		"port":          {1, 127, 0, 0, 1, 0},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := readSOCKSAddress(bytes.NewReader(raw)); err == nil {
				t.Fatal("malformed SOCKS address unexpectedly succeeded")
			}
		})
	}
}

func TestSOCKSHandlerFailureAndCommandPaths(t *testing.T) {
	server := proxyTestServer(t)
	closed := closedTCPAddress(t)
	host, rawPort, _ := net.SplitHostPort(closed)
	port, _ := strconv.Atoi(rawPort)
	address := append([]byte{1}, net.ParseIP(host).To4()...)
	address = append(address, byte(port>>8), byte(port))
	for _, test := range []struct {
		name       string
		input      []byte
		definition config.Listener
		want       string
	}{
		{"header", nil, config.Listener{}, "EOF"},
		{"version", []byte{4, 0}, config.Listener{}, "unsupported SOCKS version"},
		{"methods", []byte{5, 1}, config.Listener{}, "EOF"},
		{"authentication", []byte{5, 1, 2}, config.Listener{}, "no-auth"},
		{"request", []byte{5, 1, 0}, config.Listener{}, "EOF"},
		{"invalid request", []byte{5, 1, 0, 4, 1, 0}, config.Listener{}, "invalid SOCKS request"},
		{"address", []byte{5, 1, 0, 5, 1, 0, 9}, config.Listener{}, "address type"},
		{"connect", append([]byte{5, 1, 0, 5, 1, 0}, address...), config.Listener{}, "connect"},
		{"UDP disabled", append([]byte{5, 1, 0, 5, 3, 0}, address...), config.Listener{}, "disabled"},
		{"command", append([]byte{5, 1, 0, 5, 9, 0}, address...), config.Listener{}, "unsupported SOCKS command"},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn := newMemoryConn(test.input)
			err := server.handleSOCKS(context.Background(), conn, test.definition)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("handleSOCKS error = %v, want %q", err, test.want)
			}
		})
	}

	input := append([]byte{5, 1, 0, 5, 3, 0}, address...)
	conn := newMemoryConn(input)
	if err := server.handleSOCKS(context.Background(), conn, config.Listener{UDPListen: "udp://127.0.0.1:0"}); err != nil {
		t.Fatalf("UDP associate: %v", err)
	}
	if output := conn.output.Bytes(); len(output) < 4 || output[1] != 0 {
		t.Fatalf("UDP associate reply = %v", output)
	}
}

func TestSOCKSReplyVariants(t *testing.T) {
	for _, address := range []net.Addr{
		nil,
		&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234},
		&net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443},
		staticAddr{network: "tcp", value: "invalid"},
	} {
		var output bytes.Buffer
		if err := writeSOCKSReply(&output, 0, address); err != nil || len(output.Bytes()) < 10 {
			t.Fatalf("writeSOCKSReply(%v) = %v, %v", address, output.Bytes(), err)
		}
	}
	if err := writeSOCKSReply(failingWriter{}, 1, nil); err == nil {
		t.Fatal("expected SOCKS reply writer error")
	}
}

func TestSOCKSUDPEdgeCases(t *testing.T) {
	for _, packet := range [][]byte{{}, {1, 0, 0, 1}, {0, 0, 1, 1}, {0, 0, 0, 9}} {
		if _, _, err := parseSOCKSUDP(packet); err == nil {
			t.Errorf("parseSOCKSUDP(%v) unexpectedly succeeded", packet)
		}
	}
	for _, source := range []*net.UDPAddr{
		{IP: net.ParseIP("127.0.0.1"), Port: 53},
		{IP: net.ParseIP("2001:db8::1"), Port: 53},
	} {
		packet, err := makeSOCKSUDP(source, []byte("payload"))
		if err != nil || len(packet) == 0 {
			t.Fatalf("makeSOCKSUDP(%v): %v", source, err)
		}
	}
	if _, err := makeSOCKSUDP(&net.UDPAddr{IP: net.IP{}}, nil); err == nil {
		t.Fatal("invalid UDP IP unexpectedly succeeded")
	}
	if _, err := newUDPRelay(config.Listener{UDPListen: "invalid"}, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("invalid UDP relay endpoint unexpectedly succeeded")
	}

	relay, err := newUDPRelay(config.Listener{Name: "coverage", UDPListen: "udp://127.0.0.1:0"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	client := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 54321}
	first, err := relay.session(client)
	if err != nil {
		t.Fatal(err)
	}
	second, err := relay.session(client)
	if err != nil || first != second {
		t.Fatal("UDP session was not reused")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	relay.reap(ctx)
	relay.Close()
}

func TestCaidoValidationAndDialFailures(t *testing.T) {
	for _, input := range []string{
		"MIMIC/1 {bad}\n",
		"MIMIC/1 {\"target\":\"missing-port\"}\n",
		"MIMIC/1 {\"target\":\"127.0.0.1:1\",\"profile\":\"missing\"}\n",
	} {
		conn := newMemoryConn([]byte(input))
		if err := proxyTestServer(t).handleCaido(context.Background(), conn); err == nil {
			t.Fatalf("Caido input %q unexpectedly succeeded", input)
		}
	}
	closed := closedTCPAddress(t)
	conn := newMemoryConn([]byte("MIMIC/1 {\"target\":\"" + closed + "\"}\n"))
	if err := proxyTestServer(t).handleCaido(context.Background(), conn); err == nil {
		t.Fatal("Caido dial failure unexpectedly succeeded")
	}
	if err := validateTarget("example.test:\n443"); err == nil {
		t.Fatal("control character target unexpectedly succeeded")
	}
	if _, err := readCaidoTarget(bufioReader("MIMIC/1 {}")); err == nil {
		t.Fatal("unterminated Caido preface unexpectedly succeeded")
	}
}

func TestServerStartAndListenFailures(t *testing.T) {
	server := proxyTestServerWith(t, nil, func(cfg *config.Config) { cfg.Listeners = nil })
	if err := server.Start(context.Background()); err == nil {
		t.Fatal("server without listeners unexpectedly started")
	}
	server = proxyTestServerWith(t, nil, func(cfg *config.Config) {
		cfg.Listeners = []config.Listener{{Name: "bad", Protocol: "http", Listen: "invalid", Mode: "tunnel"}}
	})
	if err := server.Start(context.Background()); err == nil {
		t.Fatal("invalid listener unexpectedly started")
	}

	dir := t.TempDir()
	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if listener, err := listen("unix://" + regular); err == nil {
		listener.Close()
		t.Fatal("regular file unexpectedly replaced")
	}
	if listener, err := listen("unix://" + filepath.Join(regular, "socket")); err == nil {
		listener.Close()
		t.Fatal("invalid socket parent unexpectedly accepted")
	}
	socket := filepath.Join(dir, "stale.sock")
	first, err := listen("unix://" + socket)
	if err != nil {
		t.Fatal(err)
	}
	first.Close()
	second, err := listen("unix://" + socket)
	if err != nil {
		t.Fatal(err)
	}
	second.Close()

	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	if duplicate, err := listen("tcp://" + occupied.Addr().String()); err == nil {
		duplicate.Close()
		t.Fatal("occupied listener unexpectedly succeeded")
	}
}

func TestServerStartsSOCKSUDPRelay(t *testing.T) {
	address := closedTCPAddress(t)
	server := proxyTestServerWith(t, nil, func(cfg *config.Config) {
		cfg.Listeners = []config.Listener{{
			Name: "socks", Protocol: "socks5", Listen: "tcp://" + address,
			UDPListen: "udp://127.0.0.1:0",
		}}
	})
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- server.Start(ctx) }()
	deadline := time.Now().Add(time.Second)
	started := false
	for time.Now().Before(deadline) {
		server.mu.Lock()
		started = len(server.udp) == 1
		server.mu.Unlock()
		if started {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !started {
		cancel()
		t.Fatal("SOCKS UDP relay did not start")
	}
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("SOCKS UDP server did not stop")
	}
}

type memoryConn struct {
	input  *bytes.Reader
	output bytes.Buffer
}

func newMemoryConn(input []byte) *memoryConn           { return &memoryConn{input: bytes.NewReader(input)} }
func (c *memoryConn) Read(value []byte) (int, error)   { return c.input.Read(value) }
func (c *memoryConn) Write(value []byte) (int, error)  { return c.output.Write(value) }
func (c *memoryConn) Close() error                     { return nil }
func (c *memoryConn) LocalAddr() net.Addr              { return staticAddr{network: "tcp", value: "127.0.0.1:1"} }
func (c *memoryConn) RemoteAddr() net.Addr             { return staticAddr{network: "tcp", value: "127.0.0.1:2"} }
func (c *memoryConn) SetDeadline(time.Time) error      { return nil }
func (c *memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (c *memoryConn) SetWriteDeadline(time.Time) error { return nil }

type staticAddr struct{ network, value string }

func (a staticAddr) Network() string { return a.network }
func (a staticAddr) String() string  { return a.value }

func bufioReader(value string) *bufio.Reader { return bufio.NewReader(strings.NewReader(value)) }
