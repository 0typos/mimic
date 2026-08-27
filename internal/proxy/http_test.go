package proxy

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"net/http"
	"strings"
	"testing"

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
