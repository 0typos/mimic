//go:build lab

// The lab origin is deliberately excluded from normal production builds. It
// provides deterministic HTTP, modern-TLS, and TLS-1.0-only endpoints for the
// hands-on tutorial without adding another runtime dependency.
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	httpAddress   = environmentOr("MIMIC_LAB_HTTP", ":8080")
	modernAddress = environmentOr("MIMIC_LAB_MODERN", ":8443")
	legacyAddress = environmentOr("MIMIC_LAB_LEGACY", ":9443")
)

type inspection struct {
	Method    string            `json:"method"`
	Path      string            `json:"path"`
	Protocol  string            `json:"protocol"`
	TLS       string            `json:"tls"`
	Cipher    string            `json:"cipher,omitempty"`
	UserAgent string            `json:"user_agent"`
	Headers   map[string]string `json:"headers"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve()
	case "healthcheck":
		err = healthcheck()
	case "caido-check":
		err = caidoCheck(os.Args[2:])
	case "unix-check":
		err = unixCheck(os.Args[2:])
	case "tcp-forward":
		err = tcpForward(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		log.Fatal(err)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: lab-origin serve|healthcheck|caido-check BRIDGE TARGET [PROFILE]|unix-check SOCKET TARGET|tcp-forward LISTEN TARGET")
	os.Exit(2)
}

func environmentOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func serve() error {
	certificate, err := selfSignedCertificate()
	if err != nil {
		return err
	}
	handler := inspectHandler()
	servers := []struct {
		name      string
		address   string
		tlsConfig *tls.Config
	}{
		{name: "HTTP", address: httpAddress},
		{name: "modern TLS", address: modernAddress, tlsConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"},
		}},
		{name: "legacy TLS", address: legacyAddress, tlsConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS10,
			MaxVersion: tls.VersionTLS10, NextProtos: []string{"http/1.1"},
			CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_AES_128_CBC_SHA},
		}},
	}
	errorsChannel := make(chan error, len(servers))
	for _, definition := range servers {
		definition := definition
		go func() {
			listener, listenErr := net.Listen("tcp", definition.address)
			if listenErr != nil {
				errorsChannel <- fmt.Errorf("listen on %s: %w", definition.address, listenErr)
				return
			}
			if definition.tlsConfig != nil {
				listener = tls.NewListener(listener, definition.tlsConfig)
			}
			log.Printf("%s origin listening on %s", definition.name, definition.address)
			errorsChannel <- (&http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}).Serve(listener)
		}()
	}
	return <-errorsChannel
}

func inspectHandler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		tlsVersion, cipher := "none", ""
		if request.TLS != nil {
			tlsVersion = tlsVersionName(request.TLS.Version)
			cipher = tls.CipherSuiteName(request.TLS.CipherSuite)
		}
		headers := make(map[string]string, len(request.Header))
		for name, values := range request.Header {
			headers[name] = strings.Join(values, ", ")
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Mimic-Lab-Origin", "true")
		_ = json.NewEncoder(writer).Encode(inspection{
			Method: request.Method, Path: request.URL.RequestURI(), Protocol: request.Proto,
			TLS: tlsVersion, Cipher: cipher, UserAgent: request.UserAgent(), Headers: headers,
		})
	})
}

func selfSignedCertificate() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate lab key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate lab serial: %w", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "Mimic Lab Origin"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"modern-origin", "legacy-origin", "default-origin", "localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create lab certificate: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load lab certificate: %w", err)
	}
	return certificate, nil
}

func healthcheck() error {
	for _, address := range []string{"127.0.0.1:8080", "127.0.0.1:8443", "127.0.0.1:9443"} {
		connection, err := net.DialTimeout("tcp", address, time.Second)
		if err != nil {
			return fmt.Errorf("%s is not ready: %w", address, err)
		}
		_ = connection.Close()
	}
	return nil
}

func caidoCheck(arguments []string) error {
	if len(arguments) < 2 || len(arguments) > 3 {
		return errors.New("caido-check requires BRIDGE TARGET [PROFILE]")
	}
	profile := ""
	if len(arguments) == 3 {
		profile = arguments[2]
	}
	connection, err := net.DialTimeout("tcp", arguments[0], 5*time.Second)
	if err != nil {
		return fmt.Errorf("connect to Caido bridge: %w", err)
	}
	defer connection.Close()
	preface, _ := json.Marshal(map[string]any{"target": arguments[1], "tls": true, "profile": profile})
	if _, err := fmt.Fprintf(connection, "MIMIC/1 %s\nGET /inspect?via=caido HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", preface, arguments[1]); err != nil {
		return fmt.Errorf("write Caido bridge request: %w", err)
	}
	return printResponse(connection, "Caido bridge")
}

func unixCheck(arguments []string) error {
	if len(arguments) != 2 {
		return errors.New("unix-check requires SOCKET TARGET")
	}
	connection, err := net.DialTimeout("unix", arguments[0], 5*time.Second)
	if err != nil {
		return fmt.Errorf("connect to Unix proxy: %w", err)
	}
	defer connection.Close()
	if _, err := fmt.Fprintf(connection, "GET http://%s/inspect?via=unix HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", arguments[1], arguments[1]); err != nil {
		return fmt.Errorf("write Unix proxy request: %w", err)
	}
	return printResponse(connection, "Unix proxy")
}

func tcpForward(arguments []string) error {
	if len(arguments) != 2 {
		return errors.New("tcp-forward requires LISTEN TARGET")
	}
	listener, err := net.Listen("tcp", arguments[0])
	if err != nil {
		return fmt.Errorf("listen for TCP forwarding: %w", err)
	}
	defer listener.Close()
	log.Printf("lab-only TCP forwarder listening on %s for %s", arguments[0], arguments[1])
	for {
		downstream, acceptErr := listener.Accept()
		if acceptErr != nil {
			return fmt.Errorf("accept TCP forwarding connection: %w", acceptErr)
		}
		go forwardConnection(downstream, arguments[1])
	}
}

func forwardConnection(downstream net.Conn, target string) {
	defer downstream.Close()
	upstream, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		log.Printf("lab-only TCP forwarder could not reach %s: %v", target, err)
		return
	}
	defer upstream.Close()
	done := make(chan struct{}, 1)
	go func() {
		_, _ = io.Copy(upstream, downstream)
		if connection, ok := upstream.(*net.TCPConn); ok {
			_ = connection.CloseWrite()
		}
		done <- struct{}{}
	}()
	_, _ = io.Copy(downstream, upstream)
	<-done
}

func printResponse(connection net.Conn, label string) error {
	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodGet})
	if err != nil {
		return fmt.Errorf("read %s response: %w", label, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned %s", label, response.Status)
	}
	_, err = io.Copy(os.Stdout, response.Body)
	return err
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}
