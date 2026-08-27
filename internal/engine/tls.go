package engine

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/msmythe/mimic/internal/config"
	"github.com/msmythe/mimic/internal/fingerprint"
	"github.com/msmythe/mimic/internal/profiles"
)

const maxProbeCapture = 1 << 20

// ProbeResult describes the selected identity and every TLS attempt made by a
// conformance probe.
type ProbeResult struct {
	Target      string             `json:"target"`
	Host        string             `json:"host"`
	Profile     string             `json:"profile"`
	ExpectedJA4 string             `json:"expected_ja4,omitempty"`
	Route       string             `json:"route,omitempty"`
	Attempts    []HandshakeAttempt `json:"attempts"`
}

// HandshakeAttempt contains observable output from one modern or legacy TLS
// handshake attempt.
type HandshakeAttempt struct {
	Legacy            bool             `json:"legacy"`
	CapturedBytes     int              `json:"captured_bytes"`
	JA4               *fingerprint.JA4 `json:"ja4,omitempty"`
	FingerprintError  string           `json:"fingerprint_error,omitempty"`
	NegotiatedVersion string           `json:"negotiated_version,omitempty"`
	Cipher            string           `json:"cipher,omitempty"`
	ALPN              string           `json:"alpn,omitempty"`
	Error             string           `json:"error,omitempty"`
}

type TLSDialer struct {
	state  *State
	logger *slog.Logger
}

func NewTLSDialer(state *State, logger *slog.Logger) *TLSDialer {
	return &TLSDialer{state: state, logger: logger}
}

func (d *TLSDialer) Dial(ctx context.Context, address string) (net.Conn, profiles.Profile, error) {
	return d.DialProfile(ctx, address, "")
}

func (d *TLSDialer) DialProfile(ctx context.Context, address, profileName string) (net.Conn, profiles.Profile, error) {
	conn, profile, _, _, err := d.dialProfile(ctx, address, profileName, false)
	return conn, profile, err
}

// Probe performs the normal profiled handshake while recording the outbound
// ClientHello for JA4 calculation. It sends no application data.
func (d *TLSDialer) Probe(ctx context.Context, address, profileName string) (ProbeResult, error) {
	conn, profile, route, attempts, err := d.dialProfile(ctx, address, profileName, true)
	if conn != nil {
		_ = conn.Close()
	}
	host, _, splitErr := net.SplitHostPort(address)
	if splitErr != nil {
		return ProbeResult{Target: address}, err
	}
	return ProbeResult{
		Target:      address,
		Host:        host,
		Profile:     profile.Name,
		ExpectedJA4: profile.JA4,
		Route:       route.Host,
		Attempts:    attempts,
	}, err
}

func (d *TLSDialer) dialProfile(ctx context.Context, address, profileName string, capture bool) (net.Conn, profiles.Profile, config.Route, []HandshakeAttempt, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, profiles.Profile{}, config.Route{}, nil, fmt.Errorf("TLS target must be host:port: %w", err)
	}
	p, route, ok := d.state.ProfileForHostAs(host, profileName)
	if !ok {
		return nil, profiles.Profile{}, config.Route{}, nil, fmt.Errorf("no profile selected for %s", host)
	}
	snapshot := d.state.Snapshot()
	conn, attempt, err := d.dialAttempt(ctx, address, host, p, route.InsecureVerify || snapshot.Config.Legacy.InsecureSkipVerify, false, capture)
	var attempts []HandshakeAttempt
	if capture {
		attempts = append(attempts, attempt)
	}
	if err == nil {
		return conn, p, route, attempts, nil
	}
	legacyRetry := snapshot.Config.Legacy.Enabled && snapshot.Config.Legacy.Retry
	if route.LegacyRetry != nil {
		legacyRetry = *route.LegacyRetry
	}
	if !legacyRetry || !hostAllowed(host, snapshot.Config.Legacy.AllowHosts) || !retryable(err, snapshot.Config.Legacy.RetryOn) {
		return nil, p, route, attempts, err
	}
	d.logger.Warn("modern TLS handshake failed; retrying with the configured legacy floor",
		"host", host, "profile", p.Name, "floor", snapshot.Config.Legacy.MinVersion, "error", err)
	d.state.FallbackUsed()
	conn, fallbackAttempt, fallbackErr := d.dialAttempt(ctx, address, host, p, route.InsecureVerify || snapshot.Config.Legacy.InsecureSkipVerify, true, capture)
	if capture {
		attempts = append(attempts, fallbackAttempt)
	}
	if fallbackErr != nil {
		return nil, p, route, attempts, errors.Join(err, fmt.Errorf("legacy retry: %w", fallbackErr))
	}
	return conn, p, route, attempts, nil
}

func (d *TLSDialer) dialAttempt(ctx context.Context, address, host string, p profiles.Profile, insecure, legacy, capture bool) (net.Conn, HandshakeAttempt, error) {
	attempt := HandshakeAttempt{Legacy: legacy}
	snapshot := d.state.Snapshot()
	connectTimeout, _ := time.ParseDuration(snapshot.Config.Runtime.ConnectTimeout)
	handshakeTimeout, _ := time.ParseDuration(snapshot.Config.Runtime.HandshakeTimeout)
	dialer := net.Dialer{Timeout: connectTimeout, KeepAlive: 30 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		attempt.Error = err.Error()
		return nil, attempt, err
	}
	transport := net.Conn(raw)
	var recorder *captureConn
	if capture {
		recorder = &captureConn{Conn: raw}
		transport = recorder
	}
	deadline := time.Now().Add(handshakeTimeout)
	_ = raw.SetDeadline(deadline)
	utlsConfig := &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: insecure, // #nosec G402 -- explicit per-route compatibility option.
		RootCAs:            systemRoots(),
		NextProtos:         []string{"http/1.1"},
	}
	hello := p.Hello
	if legacy {
		// The fallback deliberately stops impersonating the modern profile. It
		// retains the profile's HTTP identity while offering TLS 1.0-era suites.
		hello = utls.HelloGolang
		floor, _ := config.TLSVersion(snapshot.Config.Legacy.MinVersion)
		utlsConfig.MinVersion = floor
		utlsConfig.MaxVersion = utls.VersionTLS12
		utlsConfig.CipherSuites = []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		}
	} else {
		if p.MinVersion != 0 {
			utlsConfig.MinVersion = p.MinVersion
		}
		if p.MaxVersion != 0 {
			utlsConfig.MaxVersion = p.MaxVersion
		}
	}
	conn := utls.UClient(transport, utlsConfig, hello)
	if !legacy {
		if err := p.Apply(conn); err != nil {
			raw.Close()
			attempt.Error = err.Error()
			populateFingerprint(&attempt, recorder)
			return nil, attempt, err
		}
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		raw.Close()
		attempt.Error = err.Error()
		populateFingerprint(&attempt, recorder)
		return nil, attempt, err
	}
	_ = raw.SetDeadline(time.Time{})
	state := conn.ConnectionState()
	populateFingerprint(&attempt, recorder)
	attempt.NegotiatedVersion = tlsVersionName(state.Version)
	attempt.Cipher = tls.CipherSuiteName(state.CipherSuite)
	attempt.ALPN = state.NegotiatedProtocol
	d.logger.Debug("upstream TLS negotiated", "host", host, "profile", p.Name,
		"legacy_retry", legacy, "version", tlsVersionName(state.Version), "cipher", tls.CipherSuiteName(state.CipherSuite))
	return conn, attempt, nil
}

func populateFingerprint(attempt *HandshakeAttempt, recorder *captureConn) {
	if recorder == nil {
		return
	}
	raw := recorder.Bytes()
	attempt.CapturedBytes = len(raw)
	result, err := fingerprint.FromClientHello(raw)
	if err != nil {
		attempt.FingerprintError = err.Error()
		return
	}
	attempt.JA4 = &result
}

type captureConn struct {
	net.Conn
	buffer bytes.Buffer
}

func (c *captureConn) Write(value []byte) (int, error) {
	n, err := c.Conn.Write(value)
	remaining := maxProbeCapture - c.buffer.Len()
	if remaining > n {
		remaining = n
	}
	if remaining > 0 {
		_, _ = c.buffer.Write(value[:remaining])
	}
	return n, err
}

func (c *captureConn) Bytes() []byte {
	return append([]byte(nil), c.buffer.Bytes()...)
}

func retryable(err error, fragments []string) bool {
	message := strings.ToLower(err.Error())
	for _, fragment := range fragments {
		if strings.Contains(message, strings.ToLower(fragment)) {
			return true
		}
	}
	return false
}

func hostAllowed(host string, patterns []string) bool {
	for _, pattern := range patterns {
		if hostMatch(pattern, host) {
			return true
		}
	}
	return false
}

func systemRoots() *x509.CertPool {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil
	}
	return roots
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
