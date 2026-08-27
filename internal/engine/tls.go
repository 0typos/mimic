package engine

import (
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
	"github.com/msmythe/mimic/internal/profiles"
)

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
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, profiles.Profile{}, fmt.Errorf("TLS target must be host:port: %w", err)
	}
	p, route, ok := d.state.ProfileForHostAs(host, profileName)
	if !ok {
		return nil, profiles.Profile{}, fmt.Errorf("no profile selected for %s", host)
	}
	snapshot := d.state.Snapshot()
	conn, err := d.dialAttempt(ctx, address, host, p, route.InsecureVerify || snapshot.Config.Legacy.InsecureSkipVerify, false)
	if err == nil {
		return conn, p, nil
	}
	legacyRetry := snapshot.Config.Legacy.Enabled && snapshot.Config.Legacy.Retry
	if route.LegacyRetry != nil {
		legacyRetry = *route.LegacyRetry
	}
	if !legacyRetry || !hostAllowed(host, snapshot.Config.Legacy.AllowHosts) || !retryable(err, snapshot.Config.Legacy.RetryOn) {
		return nil, p, err
	}
	d.logger.Warn("modern TLS handshake failed; retrying with the configured legacy floor",
		"host", host, "profile", p.Name, "floor", snapshot.Config.Legacy.MinVersion, "error", err)
	d.state.FallbackUsed()
	conn, fallbackErr := d.dialAttempt(ctx, address, host, p, route.InsecureVerify || snapshot.Config.Legacy.InsecureSkipVerify, true)
	if fallbackErr != nil {
		return nil, p, errors.Join(err, fmt.Errorf("legacy retry: %w", fallbackErr))
	}
	return conn, p, nil
}

func (d *TLSDialer) dialAttempt(ctx context.Context, address, host string, p profiles.Profile, insecure, legacy bool) (net.Conn, error) {
	snapshot := d.state.Snapshot()
	connectTimeout, _ := time.ParseDuration(snapshot.Config.Runtime.ConnectTimeout)
	handshakeTimeout, _ := time.ParseDuration(snapshot.Config.Runtime.HandshakeTimeout)
	dialer := net.Dialer{Timeout: connectTimeout, KeepAlive: 30 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
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
	conn := utls.UClient(raw, utlsConfig, hello)
	if !legacy {
		if err := p.Apply(conn); err != nil {
			raw.Close()
			return nil, err
		}
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	_ = raw.SetDeadline(time.Time{})
	state := conn.ConnectionState()
	d.logger.Debug("upstream TLS negotiated", "host", host, "profile", p.Name,
		"legacy_retry", legacy, "version", tlsVersionName(state.Version), "cipher", tls.CipherSuiteName(state.CipherSuite))
	return conn, nil
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
