package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/0typos/mimic/internal/config"
	"github.com/0typos/mimic/internal/engine"
	"github.com/0typos/mimic/internal/fingerprint"
	"github.com/0typos/mimic/internal/profiles"
)

var errProbeMismatch = errors.New("observed JA4 does not match the expected fingerprint")

type probeReport struct {
	Target      string                    `json:"target"`
	Host        string                    `json:"host"`
	Profile     string                    `json:"profile"`
	Route       string                    `json:"route,omitempty"`
	ExpectedJA4 string                    `json:"expected_ja4,omitempty"`
	ObservedJA4 string                    `json:"observed_ja4,omitempty"`
	Status      string                    `json:"status"`
	Match       *bool                     `json:"match,omitempty"`
	Attempts    []engine.HandshakeAttempt `json:"attempts"`
}

func probe(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("probe", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", defaultConfigPath(), "TOML configuration path")
	profileName := flags.String("profile", "", "profile override; empty uses normal routing")
	target := flags.String("target", "", "HTTPS URL or host[:port] to probe")
	format := flags.String("format", "text", "output format: text or json")
	expectedOverride := flags.String("expect", "", "expected JA4 override")
	showRaw := flags.Bool("raw", false, "include raw JA4 inputs in text output")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("probe accepts flags only")
	}
	if *target == "" {
		return errors.New("probe requires -target")
	}
	if *format != "text" && *format != "json" {
		return errors.New("probe -format must be text or json")
	}
	if *expectedOverride != "" {
		if err := fingerprint.ValidateJA4(*expectedOverride); err != nil {
			return fmt.Errorf("probe -expect: %w", err)
		}
		if (*expectedOverride)[0] != 't' {
			return errors.New("probe -expect must describe TLS over TCP")
		}
	}
	address, err := normalizeProbeTarget(*target)
	if err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	registry, err := profiles.New(cfg.Profiles)
	if err != nil {
		return err
	}
	state, err := engine.New(cfg, registry, new(slog.LevelVar))
	if err != nil {
		return err
	}
	connectTimeout, _ := time.ParseDuration(cfg.Runtime.ConnectTimeout)
	handshakeTimeout, _ := time.ParseDuration(cfg.Runtime.HandshakeTimeout)
	timeout := 2*(connectTimeout+handshakeTimeout) + time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	dialer := engine.NewTLSDialer(state, slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn})))
	result, probeErr := dialer.Probe(ctx, address, *profileName)
	report := newProbeReport(result, *expectedOverride, probeErr)
	if err := writeProbeReport(stdout, report, *format, *showRaw); err != nil {
		return err
	}
	if probeErr != nil {
		return fmt.Errorf("TLS probe failed: %w", probeErr)
	}
	if report.Match != nil && !*report.Match {
		return errProbeMismatch
	}
	if report.ObservedJA4 == "" {
		return errors.New("TLS probe completed without a readable ClientHello")
	}
	return nil
}

func newProbeReport(result engine.ProbeResult, expectedOverride string, probeErr error) probeReport {
	expected := result.ExpectedJA4
	if expectedOverride != "" {
		expected = expectedOverride
	}
	report := probeReport{
		Target:      result.Target,
		Host:        result.Host,
		Profile:     result.Profile,
		Route:       result.Route,
		ExpectedJA4: expected,
		Status:      "unverified",
		Attempts:    result.Attempts,
	}
	if len(result.Attempts) > 0 && result.Attempts[0].JA4 != nil {
		report.ObservedJA4 = result.Attempts[0].JA4.Fingerprint
	}
	if probeErr != nil || report.ObservedJA4 == "" {
		report.Status = "error"
		return report
	}
	if expected == "" {
		return report
	}
	match := report.ObservedJA4 == expected
	report.Match = &match
	if match {
		report.Status = "pass"
	} else {
		report.Status = "mismatch"
	}
	return report
}

func writeProbeReport(writer io.Writer, report probeReport, format string, showRaw bool) error {
	if format == "json" {
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	}
	fmt.Fprintf(writer, "target:       %s\n", report.Target)
	fmt.Fprintf(writer, "profile:      %s\n", report.Profile)
	if report.Route != "" {
		fmt.Fprintf(writer, "route:        %s\n", report.Route)
	}
	if report.ExpectedJA4 == "" {
		fmt.Fprintln(writer, "expected JA4: not configured")
	} else {
		fmt.Fprintf(writer, "expected JA4: %s\n", report.ExpectedJA4)
	}
	if report.ObservedJA4 == "" {
		fmt.Fprintln(writer, "observed JA4: unavailable")
	} else {
		fmt.Fprintf(writer, "observed JA4: %s\n", report.ObservedJA4)
	}
	fmt.Fprintf(writer, "result:       %s\n", strings.ToUpper(report.Status))
	for i, attempt := range report.Attempts {
		kind := "profile"
		if attempt.Legacy {
			kind = "legacy fallback"
		}
		fmt.Fprintf(writer, "attempt %d:    %s; captured=%d bytes", i+1, kind, attempt.CapturedBytes)
		if attempt.NegotiatedVersion != "" {
			fmt.Fprintf(writer, "; tls=%s; cipher=%s", attempt.NegotiatedVersion, attempt.Cipher)
			if attempt.ALPN != "" {
				fmt.Fprintf(writer, "; alpn=%s", attempt.ALPN)
			}
		}
		if attempt.Error != "" {
			fmt.Fprintf(writer, "; error=%s", attempt.Error)
		}
		fmt.Fprintln(writer)
		if showRaw && attempt.JA4 != nil {
			fmt.Fprintf(writer, "  JA4_r:  %s\n", attempt.JA4.Raw)
			fmt.Fprintf(writer, "  JA4_ro: %s\n", attempt.JA4.Original)
		}
	}
	return nil
}

func normalizeProbeTarget(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("probe target cannot be empty")
	}
	if strings.Contains(raw, "://") {
		parsed, err := url.Parse(raw)
		if err != nil {
			return "", fmt.Errorf("parse probe target: %w", err)
		}
		if parsed.Scheme != "https" {
			return "", errors.New("probe target URL must use https")
		}
		if parsed.User != nil || parsed.Hostname() == "" {
			return "", errors.New("probe target URL requires a host and cannot contain user information")
		}
		port := parsed.Port()
		if port == "" {
			port = "443"
		}
		return net.JoinHostPort(parsed.Hostname(), port), nil
	}
	if host, port, err := net.SplitHostPort(raw); err == nil {
		if host == "" || port == "" {
			return "", errors.New("probe target requires a host and port")
		}
		return net.JoinHostPort(strings.Trim(host, "[]"), port), nil
	}
	if parsedIP := net.ParseIP(strings.Trim(raw, "[]")); parsedIP != nil {
		return net.JoinHostPort(parsedIP.String(), "443"), nil
	}
	if strings.ContainsAny(raw, "/?#@") {
		return "", errors.New("probe target must be an HTTPS URL or host[:port]")
	}
	return net.JoinHostPort(raw, "443"), nil
}
