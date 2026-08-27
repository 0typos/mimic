package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/msmythe/mimic/internal/config"
	"github.com/msmythe/mimic/internal/engine"
	"github.com/msmythe/mimic/internal/mitm"
	"github.com/msmythe/mimic/internal/profiles"
)

func TestHTTPProxyEndToEnd(t *testing.T) {
	seenAgent := make(chan string, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		seenAgent <- request.UserAgent()
		writer.Header().Set("X-Origin", "yes")
		_, _ = io.WriteString(writer, "proxied")
	}))
	defer origin.Close()

	server := proxyTestServer(t)
	client, proxySide := net.Pipe()
	defer client.Close()
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.handleHTTP(context.Background(), proxySide, config.Listener{Mode: "tunnel"})
		proxySide.Close()
	}()
	if _, err := fmt.Fprintf(client, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: incoming\r\nConnection: close\r\n\r\n", origin.URL, strings.TrimPrefix(origin.URL, "http://")); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "proxied" || response.Header.Get("X-Origin") != "yes" || response.Header.Get("Via") != "1.1 mimic" {
		t.Fatalf("unexpected response: status=%d headers=%v body=%q", response.StatusCode, response.Header, body)
	}
	select {
	case agent := <-seenAgent:
		if !strings.Contains(agent, "Chrome/152") {
			t.Fatalf("profile user agent not applied: %q", agent)
		}
	case <-time.After(time.Second):
		t.Fatal("origin did not receive request")
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func TestServerStartOnUnixSocket(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(writer, "unix-listener")
	}))
	defer origin.Close()
	socketPath := filepath.Join(t.TempDir(), "proxy.sock")
	cfg := config.Defaults()
	cfg.Listeners = []config.Listener{{Name: "unix", Protocol: "http", Listen: "unix://" + socketPath, Mode: "tunnel"}}
	registry, _ := profiles.New(nil)
	state, err := engine.New(cfg, registry, new(slog.LevelVar))
	if err != nil {
		t.Fatal(err)
	}
	server := New(state, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- server.Start(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Unix proxy socket did not appear")
		}
		time.Sleep(10 * time.Millisecond)
	}
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", origin.URL, strings.TrimPrefix(origin.URL, "http://")); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	conn.Close()
	if string(body) != "unix-listener" {
		t.Fatalf("body = %q", body)
	}
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("proxy server did not stop")
	}
}

func TestHTTPSAbsoluteRequestUsesHTTP2WhenNegotiated(t *testing.T) {
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Upstream-Protocol", request.Proto)
		_, _ = io.WriteString(writer, "http2")
	}))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	defer origin.Close()
	parsed, _ := url.Parse(origin.URL)
	server := proxyTestServerWith(t, nil, func(cfg *config.Config) {
		cfg.Routes = []config.Route{{Host: "127.0.0.1", Profile: "chrome-133", InsecureVerify: true}}
	})
	client, proxySide := net.Pipe()
	defer client.Close()
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.handleHTTP(context.Background(), proxySide, config.Listener{Mode: "tunnel"})
		proxySide.Close()
	}()
	if _, err := fmt.Fprintf(client, "GET %s/ HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", origin.URL, parsed.Host); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if string(body) != "http2" || response.Header.Get("X-Upstream-Protocol") != "HTTP/2.0" {
		t.Fatalf("headers=%v body=%q", response.Header, body)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func TestConnectTunnelEndToEnd(t *testing.T) {
	target := startTCPEcho(t)
	defer target.Close()
	server := proxyTestServer(t)
	client, proxySide := net.Pipe()
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.handleHTTP(ctx, proxySide, config.Listener{Mode: "tunnel"})
		proxySide.Close()
	}()
	request, _ := http.NewRequest(http.MethodConnect, "http://"+target.Addr().String(), nil)
	if _, err := fmt.Fprintf(client, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target.Addr(), target.Addr()); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(client)
	response, err := http.ReadResponse(reader, request)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT response: %+v, %v", response, err)
	}
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, 4)
	if _, err := io.ReadFull(reader, echo); err != nil {
		t.Fatal(err)
	}
	if string(echo) != "ping" {
		t.Fatalf("echo = %q", echo)
	}
	client.Close()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("CONNECT handler did not stop")
	}
}

func TestHTTPInterceptEndToEnd(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(writer, "intercepted")
	}))
	defer origin.Close()
	parsed, _ := url.Parse(origin.URL)

	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")
	if err := mitm.Generate(certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	authority, err := mitm.Load(certPath, keyPath, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	server := proxyTestServerWith(t, authority, func(cfg *config.Config) {
		cfg.Routes = []config.Route{{Host: "127.0.0.1", Profile: "chrome-133", InsecureVerify: true}}
	})
	client, proxySide := net.Pipe()
	defer client.Close()
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.handleHTTP(context.Background(), proxySide, config.Listener{Mode: "intercept"})
		proxySide.Close()
	}()
	connectRequest, _ := http.NewRequest(http.MethodConnect, "http://"+parsed.Host, nil)
	if _, err := fmt.Fprintf(client, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", parsed.Host, parsed.Host); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(client)
	response, err := http.ReadResponse(reader, connectRequest)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT response: %+v, %v", response, err)
	}
	caPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("failed to trust generated CA")
	}
	tlsClient := tls.Client(&bufferedConn{Conn: client, reader: reader}, &tls.Config{
		RootCAs:    roots,
		ServerName: "127.0.0.1",
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(tlsClient, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", parsed.Host); err != nil {
		t.Fatal(err)
	}
	response, err = http.ReadResponse(bufio.NewReader(tlsClient), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if string(body) != "intercepted" {
		t.Fatalf("body = %q", body)
	}
	client.Close()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("intercept handler did not stop")
	}
}

func TestCaidoBridgePlainHTTP(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(writer, "caido")
	}))
	defer origin.Close()
	parsed, _ := url.Parse(origin.URL)
	server := proxyTestServer(t)
	client, bridgeSide := net.Pipe()
	defer client.Close()
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.handleCaido(context.Background(), bridgeSide)
		bridgeSide.Close()
	}()
	if err := WriteCaidoPreface(client, parsed.Host, false, "firefox-120"); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(client, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", parsed.Host); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if string(body) != "caido" {
		t.Fatalf("body = %q", body)
	}
	client.Close()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Caido bridge did not stop")
	}
}

func TestSOCKSConnectEndToEnd(t *testing.T) {
	target := startTCPEcho(t)
	defer target.Close()
	host, rawPort, _ := net.SplitHostPort(target.Addr().String())
	port, _ := strconv.Atoi(rawPort)
	server := proxyTestServer(t)
	client, socksSide := net.Pipe()
	defer client.Close()
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.handleSOCKS(context.Background(), socksSide, config.Listener{})
		socksSide.Close()
	}()
	if _, err := client.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(client, method); err != nil || string(method) != string([]byte{5, 0}) {
		t.Fatalf("method response = %v, %v", method, err)
	}
	ip := net.ParseIP(host).To4()
	request := append([]byte{5, 1, 0, 1}, ip...)
	request = append(request, byte(port>>8), byte(port))
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil || reply[1] != 0 {
		t.Fatalf("SOCKS reply = %v, %v", reply, err)
	}
	if _, err := client.Write([]byte("socks")); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, 5)
	if _, err := io.ReadFull(client, echo); err != nil || string(echo) != "socks" {
		t.Fatalf("echo = %q, %v", echo, err)
	}
	client.Close()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("SOCKS handler did not stop")
	}
}

func TestSOCKSUDPRelayEndToEnd(t *testing.T) {
	origin, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	go func() {
		buffer := make([]byte, 1024)
		n, client, readErr := origin.ReadFromUDP(buffer)
		if readErr == nil {
			_, _ = origin.WriteToUDP(buffer[:n], client)
		}
	}()
	definition := config.Listener{Name: "udp-test", UDPListen: "udp://127.0.0.1:0", AllowCIDRs: []string{"127.0.0.0/8"}}
	relay, err := newUDPRelay(definition, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = relay.Serve(ctx) }()
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	packet, err := makeSOCKSUDP(origin.LocalAddr().(*net.UDPAddr), []byte("datagram"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.WriteToUDP(packet, relay.conn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 1024)
	n, _, err := client.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	target, payload, err := parseSOCKSUDP(buffer[:n])
	if err != nil {
		t.Fatal(err)
	}
	if target != origin.LocalAddr().String() || string(payload) != "datagram" {
		t.Fatalf("target=%q payload=%q", target, payload)
	}
}

func proxyTestServer(t *testing.T) *Server {
	return proxyTestServerWith(t, nil, nil)
}

func proxyTestServerWith(t *testing.T, authority *mitm.Authority, mutate func(*config.Config)) *Server {
	t.Helper()
	cfg := config.Defaults()
	cfg.Listeners = []config.Listener{{Name: "test", Protocol: "http", Listen: "tcp://127.0.0.1:0", Mode: "tunnel"}}
	if mutate != nil {
		mutate(&cfg)
	}
	registry, err := profiles.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	state, err := engine.New(cfg, registry, new(slog.LevelVar))
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(state, authority, logger)
}

func startTCPEcho(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = io.Copy(conn, conn)
				conn.Close()
			}()
		}
	}()
	return listener
}
