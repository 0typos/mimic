package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/msmythe/mimic/internal/config"
	"github.com/msmythe/mimic/internal/profiles"
)

func TestWriteProfiledRequestOrdersHeadersAndRemovesControlHeader(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "https://example.test/path?q=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "example.test"
	request.Header.Set("Accept", "text/html")
	request.Header.Set("User-Agent", "incoming")
	request.Header.Set("Connection", "keep-alive")
	profile := profiles.Profile{
		UserAgent:   "profile-agent",
		HeaderOrder: []string{"host", "user-agent", "accept"},
	}
	var output bytes.Buffer
	if err := writeProfiledRequest(&output, request, profile); err != nil {
		t.Fatal(err)
	}
	wantPrefix := "GET /path?q=1 HTTP/1.1\r\nHost: example.test\r\nUser-Agent: profile-agent\r\nAccept: text/html\r\n"
	if !strings.HasPrefix(output.String(), wantPrefix) {
		t.Fatalf("request order mismatch:\n%s", output.String())
	}
	if strings.Contains(output.String(), "Connection:") || strings.Contains(output.String(), "Content-Length:") {
		t.Fatalf("unexpected hop/content header:\n%s", output.String())
	}
}

func TestCaidoPrefaceRoundTrip(t *testing.T) {
	var output bytes.Buffer
	if err := WriteCaidoPreface(&output, "example.test:443", true, "firefox-120"); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "MIMIC/1 {\"target\":\"example.test:443\",\"tls\":true,\"profile\":\"firefox-120\"}\n" {
		t.Fatalf("preface = %q", got)
	}
}

func TestCaidoPrefaceValidation(t *testing.T) {
	if _, err := readCaidoTarget(bufio.NewReader(strings.NewReader("WRONG {}\n"))); err == nil {
		t.Fatal("expected missing preface error")
	}
	oversized := caidoPreface + strings.Repeat("x", maxCaidoPreface) + "\n"
	if _, err := readCaidoTarget(bufio.NewReaderSize(strings.NewReader(oversized), maxCaidoPreface+1)); err == nil {
		t.Fatal("expected oversized preface error")
	}
	if err := validateTarget("missing-port"); err == nil {
		t.Fatal("expected invalid target error")
	}
}

func TestSOCKSUDPPacketParsing(t *testing.T) {
	packet := append([]byte{0, 0, 0, 1, 127, 0, 0, 1, 0, 53}, []byte("dns")...)
	target, payload, err := parseSOCKSUDP(packet)
	if err != nil {
		t.Fatal(err)
	}
	if target != "127.0.0.1:53" || string(payload) != "dns" {
		t.Fatalf("target=%q payload=%q", target, payload)
	}
	if _, _, err := parseSOCKSUDP([]byte{0, 0, 1, 1}); err == nil {
		t.Fatal("expected fragment rejection")
	}
}

func TestRequestTargetRejectsUnsupportedScheme(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "ftp://example.test/file", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := requestTarget(request, "", false); err == nil {
		t.Fatal("expected unsupported scheme error")
	}
}

func TestRequestTargetVariants(t *testing.T) {
	fixed := &http.Request{}
	if target, tls, err := requestTarget(fixed, "fixed.test:8443", true); err != nil || target != "fixed.test:8443" || !tls {
		t.Fatalf("fixed target = %q, %v, %v", target, tls, err)
	}
	noHost, _ := http.NewRequest(http.MethodGet, "/", nil)
	if _, _, err := requestTarget(noHost, "", false); err == nil {
		t.Fatal("request without a host unexpectedly succeeded")
	}
	for _, test := range []struct {
		raw, want string
		tls       bool
	}{
		{"http://example.test/path", "example.test:80", false},
		{"https://example.test/path", "example.test:443", true},
		{"http://example.test:8080/path", "example.test:8080", false},
	} {
		request, err := http.NewRequest(http.MethodGet, test.raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		target, useTLS, err := requestTarget(request, "", false)
		if err != nil || target != test.want || useTLS != test.tls {
			t.Errorf("requestTarget(%q) = %q, %v, %v", test.raw, target, useTLS, err)
		}
	}
}

func TestWriteProfiledRequestBodiesAndFailures(t *testing.T) {
	profile := profiles.Profile{
		Headers:     map[string]string{"X-Profile": "yes"},
		HeaderOrder: []string{"host", "x-profile", "x-profile", "missing"},
	}
	fixed := &http.Request{
		Method:        http.MethodPost,
		URL:           &url.URL{},
		RequestURI:    "/fallback",
		Host:          "example.test",
		Header:        http.Header{"Content-Length": []string{"stale"}},
		Body:          io.NopCloser(strings.NewReader("hello")),
		ContentLength: 5,
	}
	var output bytes.Buffer
	if err := writeProfiledRequest(&output, fixed, profile); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "POST / HTTP/1.1") || !strings.HasSuffix(output.String(), "\r\n\r\nhello") {
		t.Fatalf("fixed-length request = %q", output.String())
	}

	chunked, _ := http.NewRequest(http.MethodPost, "http://example.test", io.NopCloser(strings.NewReader("chunk")))
	chunked.ContentLength = -1
	output.Reset()
	if err := writeProfiledRequest(&output, chunked, profiles.Profile{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Transfer-Encoding: chunked") || !strings.HasSuffix(output.String(), "5\r\nchunk\r\n0\r\n\r\n") {
		t.Fatalf("chunked request = %q", output.String())
	}

	empty := &http.Request{Method: http.MethodGet, URL: &url.URL{}, Header: make(http.Header)}
	output.Reset()
	if err := writeProfiledRequest(&output, empty, profiles.Profile{}); err != nil || !strings.HasPrefix(output.String(), "GET / HTTP/1.1") {
		t.Fatalf("empty target request = %q, %v", output.String(), err)
	}

	badHeader, _ := http.NewRequest(http.MethodGet, "http://example.test", nil)
	badHeader.Header["X-Bad"] = []string{"one\ntwo"}
	if err := writeProfiledRequest(io.Discard, badHeader, profiles.Profile{}); err == nil {
		t.Fatal("expected header newline rejection")
	}
	if err := writeProfiledRequest(failingWriter{}, empty, profiles.Profile{}); err == nil {
		t.Fatal("expected request writer error")
	}
	readFailure := errors.New("body failed")
	badBody, _ := http.NewRequest(http.MethodPost, "http://example.test", errorReader{err: readFailure})
	badBody.ContentLength = -1
	if err := writeProfiledRequest(io.Discard, badBody, profiles.Profile{}); !errors.Is(err, readFailure) {
		t.Fatalf("body error = %v", err)
	}
}

func TestHTTPHelpers(t *testing.T) {
	header := http.Header{
		"Connection":          []string{"X-Remove, keep-alive"},
		"X-Remove":            []string{"yes"},
		"Proxy-Authorization": []string{"secret"},
		"Upgrade":             []string{"websocket"},
	}
	removeHopHeaders(header)
	if len(header) != 0 {
		t.Fatalf("hop headers remained: %v", header)
	}
	var response bytes.Buffer
	writeProxyError(&response, http.StatusBadGateway, errors.New("private detail"))
	if !strings.Contains(response.String(), "502 Bad Gateway") || strings.Contains(response.String(), "private detail") {
		t.Fatalf("proxy error response = %q", response.String())
	}
	if got := withDefaultPort("example.test:123", "80"); got != "example.test:123" {
		t.Fatalf("explicit port changed to %q", got)
	}
	if got := withDefaultPort("2001:db8::1", "443"); got != "[2001:db8::1]:443" {
		t.Fatalf("IPv6 default port = %q", got)
	}
	if got := negotiatedProtocol(&stubConn{}); got != "" {
		t.Fatalf("non-TLS ALPN = %q", got)
	}
}

func TestHTTPHandlerErrorsAndKeepAlive(t *testing.T) {
	server := proxyTestServer(t)
	client, proxySide := net.Pipe()
	errCh := make(chan error, 1)
	go func() { errCh <- server.handleHTTP(context.Background(), proxySide, config.Listener{Mode: "tunnel"}) }()
	_, _ = io.WriteString(client, "not HTTP\r\n\r\n")
	client.Close()
	proxySide.Close()
	if err := <-errCh; err == nil {
		t.Fatal("malformed HTTP request unexpectedly succeeded")
	}

	client, proxySide = net.Pipe()
	go func() {
		errCh <- server.handleHTTP(context.Background(), proxySide, config.Listener{Mode: "intercept"})
	}()
	_, _ = io.WriteString(client, "CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n")
	client.Close()
	if err := <-errCh; err == nil || !strings.Contains(err.Error(), "loaded CA") {
		t.Fatalf("intercept without CA error = %v", err)
	}

	closed := closedTCPAddress(t)
	client, proxySide = net.Pipe()
	go func() { errCh <- server.handleHTTP(context.Background(), proxySide, config.Listener{Mode: "tunnel"}) }()
	_, _ = io.WriteString(client, "CONNECT "+closed+" HTTP/1.1\r\nHost: "+closed+"\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil || response.StatusCode != http.StatusBadGateway {
		t.Fatalf("failed CONNECT response=%+v error=%v", response, err)
	}
	response.Body.Close()
	client.Close()
	if err := <-errCh; err == nil {
		t.Fatal("failed CONNECT unexpectedly returned nil")
	}

	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(writer, request.URL.Path)
	}))
	defer origin.Close()
	client, proxySide = net.Pipe()
	go func() {
		errCh <- server.handleHTTP(context.Background(), proxySide, config.Listener{Mode: "tunnel"})
		proxySide.Close()
	}()
	host := strings.TrimPrefix(origin.URL, "http://")
	_, _ = io.WriteString(client, "GET "+origin.URL+"/one HTTP/1.1\r\nHost: "+host+"\r\n\r\n"+
		"GET "+origin.URL+"/two HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n")
	reader := bufio.NewReader(client)
	for _, want := range []string{"/one", "/two"} {
		response, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if string(body) != want {
			t.Fatalf("keep-alive response body = %q, want %q", body, want)
		}
	}
	client.Close()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("keep-alive handler did not stop")
	}
}

func TestPlainHTTPRejectsUnknownProfile(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:1/", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Mimic-Profile", "missing")
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	err = proxyTestServer(t).forwardHTTP(context.Background(), server, request, "", false, "")
	if err == nil || !strings.Contains(err.Error(), "unknown profile") {
		t.Fatalf("expected unknown profile error, got %v", err)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

type stubConn struct{ net.Conn }

func closedTCPAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	return address
}
