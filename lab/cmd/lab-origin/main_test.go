//go:build lab

package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInspectHandler(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://modern-origin:8443/inspect?test=yes", nil)
	request.Header.Set("User-Agent", "Mimic-Lab-Test")
	request.Header.Set("X-Test", "value")
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS12, CipherSuite: tls.TLS_AES_128_GCM_SHA256}
	recorder := httptest.NewRecorder()

	inspectHandler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK || recorder.Header().Get("X-Mimic-Lab-Origin") != "true" {
		t.Fatalf("response = %d, headers=%v", recorder.Code, recorder.Header())
	}
	var got inspection
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Path != "/inspect?test=yes" || got.TLS != "TLS1.2" || got.UserAgent != "Mimic-Lab-Test" || got.Headers["X-Test"] != "value" {
		t.Fatalf("inspection = %+v", got)
	}
}

func TestSelfSignedCertificate(t *testing.T) {
	certificate, err := selfSignedCertificate()
	if err != nil {
		t.Fatal(err)
	}
	// X509KeyPair intentionally leaves Leaf nil; parsing validates the generated
	// certificate while keeping the production helper small.
	leaf, err := certificateLeaf(certificate)
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.VerifyHostname("legacy-origin"); err != nil {
		t.Fatal(err)
	}
}

func certificateLeaf(certificate tls.Certificate) (*x509.Certificate, error) {
	return x509.ParseCertificate(certificate.Certificate[0])
}

func TestTLSVersionName(t *testing.T) {
	for version, want := range map[uint16]string{tls.VersionTLS10: "TLS1.0", tls.VersionTLS13: "TLS1.3", 1: "0x0001"} {
		if got := tlsVersionName(version); got != want {
			t.Fatalf("tlsVersionName(%d) = %q, want %q", version, got, want)
		}
	}
}

func TestForwardConnection(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	serverDone := make(chan error, 1)
	go func() {
		connection, acceptErr := upstream.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer connection.Close()
		line, readErr := bufio.NewReader(connection).ReadString('\n')
		if readErr == nil {
			_, readErr = connection.Write([]byte(strings.ToUpper(line)))
		}
		serverDone <- readErr
	}()

	client, downstream := net.Pipe()
	forwardDone := make(chan struct{})
	go func() {
		forwardConnection(downstream, upstream.Addr().String())
		close(forwardDone)
	}()
	if _, err := client.Write([]byte("hello\n")); err != nil {
		t.Fatal(err)
	}
	response, err := bufio.NewReader(client).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if response != "HELLO\n" {
		t.Fatalf("response = %q", response)
	}
	_ = client.Close()
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	<-forwardDone
}
