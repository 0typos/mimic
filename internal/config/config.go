package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"golang.org/x/net/http/httpguts"
)

type Config struct {
	Version   int                `toml:"version"`
	Control   Control            `toml:"control"`
	Logging   Logging            `toml:"logging"`
	Runtime   Runtime            `toml:"runtime"`
	MITM      MITM               `toml:"mitm"`
	Legacy    Legacy             `toml:"legacy"`
	Listeners []Listener         `toml:"listeners"`
	Profiles  map[string]Profile `toml:"profiles"`
	Routes    []Route            `toml:"routes"`
	Path      string             `toml:"-"`
}

type Control struct {
	Listen string `toml:"listen"`
}

type Logging struct {
	Level  string `toml:"level"`
	Format string `toml:"format"`
}

type Runtime struct {
	DefaultProfile   string `toml:"default_profile"`
	ConnectTimeout   string `toml:"connect_timeout"`
	HandshakeTimeout string `toml:"handshake_timeout"`
}

type MITM struct {
	Enabled bool   `toml:"enabled"`
	CACert  string `toml:"ca_cert"`
	CAKey   string `toml:"ca_key"`
	LeafTTL string `toml:"leaf_ttl"`
}

type Legacy struct {
	Enabled            bool     `toml:"enabled"`
	MinVersion         string   `toml:"min_version"`
	Retry              bool     `toml:"retry"`
	RetryOn            []string `toml:"retry_on"`
	AllowHosts         []string `toml:"allow_hosts"`
	InsecureSkipVerify bool     `toml:"insecure_skip_verify"`
}

type Listener struct {
	Name       string   `toml:"name"`
	Protocol   string   `toml:"protocol"`
	Listen     string   `toml:"listen"`
	Mode       string   `toml:"mode"`
	UDPListen  string   `toml:"udp_listen"`
	AllowCIDRs []string `toml:"allow_cidrs"`
}

type Profile struct {
	Hello           string            `toml:"hello"`
	ClientHelloFile string            `toml:"client_hello_file"`
	JA4             string            `toml:"ja4"`
	JA4H            string            `toml:"ja4h"`
	UserAgent       string            `toml:"user_agent"`
	HeaderOrder     []string          `toml:"header_order"`
	Headers         map[string]string `toml:"headers"`
	MinVersion      string            `toml:"min_version"`
	MaxVersion      string            `toml:"max_version"`
}

type Route struct {
	Host           string `toml:"host"`
	Profile        string `toml:"profile"`
	LegacyRetry    *bool  `toml:"legacy_retry"`
	InsecureVerify bool   `toml:"insecure_skip_verify"`
}

func Defaults() Config {
	return Config{
		Version: 1,
		Control: Control{Listen: "unix:///tmp/mimic/control.sock"},
		Logging: Logging{Level: "info", Format: "text"},
		Runtime: Runtime{
			DefaultProfile:   "chrome-133",
			ConnectTimeout:   "10s",
			HandshakeTimeout: "15s",
		},
		MITM: MITM{LeafTTL: "168h"},
		Legacy: Legacy{
			Enabled:    true,
			MinVersion: "tls1.0",
			Retry:      true,
			RetryOn:    []string{"protocol version", "handshake failure", "insufficient security", "no cipher suite"},
			AllowHosts: []string{"localhost", "127.0.0.1", "::1"},
		},
		Profiles: map[string]Profile{},
	}
}

func Load(path string) (Config, error) {
	cfg := Defaults()
	metadata, err := toml.DecodeFile(path, &cfg)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	if undecoded := metadata.Undecoded(); len(undecoded) > 0 {
		parts := make([]string, 0, len(undecoded))
		for _, key := range undecoded {
			parts = append(parts, key.String())
		}
		sort.Strings(parts)
		return Config{}, fmt.Errorf("unknown config keys: %s", strings.Join(parts, ", "))
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return Config{}, fmt.Errorf("resolve config path: %w", err)
	}
	cfg.Path = absolute
	cfg.resolvePaths(filepath.Dir(absolute))
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) resolvePaths(base string) {
	for _, target := range []*string{&c.MITM.CACert, &c.MITM.CAKey} {
		if *target != "" && !filepath.IsAbs(*target) {
			*target = filepath.Join(base, *target)
		}
	}
	for name, p := range c.Profiles {
		if p.ClientHelloFile != "" && !filepath.IsAbs(p.ClientHelloFile) {
			p.ClientHelloFile = filepath.Join(base, p.ClientHelloFile)
			c.Profiles[name] = p
		}
	}
}

func (c Config) Validate() error {
	var errs []error
	if c.Version != 1 {
		errs = append(errs, fmt.Errorf("version must be 1, got %d", c.Version))
	}
	if address, network, err := ParseEndpoint(c.Control.Listen, false); err != nil {
		errs = append(errs, fmt.Errorf("control.listen: %w", err))
	} else if network == "tcp" {
		host, _, _ := net.SplitHostPort(address)
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			errs = append(errs, errors.New("control.listen TCP endpoint must be loopback"))
		}
	}
	switch strings.ToLower(c.Logging.Level) {
	case "debug", "info", "warn", "warning", "error":
	default:
		errs = append(errs, errors.New("logging.level must be debug, info, warn, or error"))
	}
	switch strings.ToLower(c.Logging.Format) {
	case "text", "json":
	default:
		errs = append(errs, errors.New("logging.format must be text or json"))
	}
	if strings.TrimSpace(c.Runtime.DefaultProfile) == "" {
		errs = append(errs, errors.New("runtime.default_profile is required"))
	}
	errs = appendPositiveDuration(errs, "runtime.connect_timeout", c.Runtime.ConnectTimeout)
	errs = appendPositiveDuration(errs, "runtime.handshake_timeout", c.Runtime.HandshakeTimeout)
	if c.MITM.Enabled {
		if c.MITM.CACert == "" || c.MITM.CAKey == "" {
			errs = append(errs, errors.New("mitm.ca_cert and mitm.ca_key are required when interception is enabled"))
		} else {
			for _, path := range []string{c.MITM.CACert, c.MITM.CAKey} {
				if _, err := os.Stat(path); err != nil {
					errs = append(errs, fmt.Errorf("MITM file %q: %w", path, err))
				}
			}
		}
	}
	errs = appendPositiveDuration(errs, "mitm.leaf_ttl", c.MITM.LeafTTL)
	if version, err := TLSVersion(c.Legacy.MinVersion); err != nil {
		errs = append(errs, fmt.Errorf("legacy.min_version: %w", err))
	} else if version > 0x0303 {
		errs = append(errs, errors.New("legacy.min_version cannot be higher than tls1.2"))
	}
	for i, pattern := range c.Legacy.AllowHosts {
		if pattern == "" {
			errs = append(errs, fmt.Errorf("legacy.allow_hosts[%d] cannot be empty", i))
		} else if _, err := path.Match(pattern, "validation-host"); err != nil {
			errs = append(errs, fmt.Errorf("legacy.allow_hosts[%d]: invalid glob: %w", i, err))
		}
	}
	seen := map[string]bool{}
	if len(c.Listeners) == 0 {
		errs = append(errs, errors.New("at least one proxy listener is required"))
	}
	for i, listener := range c.Listeners {
		prefix := fmt.Sprintf("listeners[%d]", i)
		if listener.Name == "" {
			errs = append(errs, fmt.Errorf("%s.name is required", prefix))
		} else if seen[listener.Name] {
			errs = append(errs, fmt.Errorf("duplicate listener name %q", listener.Name))
		}
		seen[listener.Name] = true
		switch listener.Protocol {
		case "http", "socks5", "caido":
		default:
			errs = append(errs, fmt.Errorf("%s.protocol must be http, socks5, or caido", prefix))
		}
		if listener.Protocol == "http" {
			if listener.Mode != "tunnel" && listener.Mode != "intercept" {
				errs = append(errs, fmt.Errorf("%s.mode must be tunnel or intercept for an HTTP listener", prefix))
			}
		} else if listener.Mode != "" {
			errs = append(errs, fmt.Errorf("%s.mode is only valid for HTTP listeners", prefix))
		}
		if _, network, err := ParseEndpoint(listener.Listen, false); err != nil {
			errs = append(errs, fmt.Errorf("%s.listen: %w", prefix, err))
		} else if network == "udp" {
			errs = append(errs, fmt.Errorf("%s.listen cannot be UDP; use udp_listen on a SOCKS5 listener", prefix))
		}
		if listener.Mode == "intercept" && !c.MITM.Enabled {
			errs = append(errs, fmt.Errorf("%s requests intercept mode but mitm.enabled is false", prefix))
		}
		if listener.Protocol == "socks5" && listener.UDPListen != "" {
			if _, network, err := ParseEndpoint(listener.UDPListen, true); err != nil || network != "udp" {
				errs = append(errs, fmt.Errorf("%s.udp_listen must be a udp:// endpoint", prefix))
			}
		} else if listener.Protocol != "socks5" && listener.UDPListen != "" {
			errs = append(errs, fmt.Errorf("%s.udp_listen is only valid for SOCKS5 listeners", prefix))
		}
		for _, cidr := range listener.AllowCIDRs {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				errs = append(errs, fmt.Errorf("%s.allow_cidrs: invalid CIDR %q", prefix, cidr))
			}
		}
	}
	for name, p := range c.Profiles {
		if strings.TrimSpace(name) == "" {
			errs = append(errs, errors.New("profile name cannot be empty"))
		}
		if p.Hello == "" && p.ClientHelloFile == "" {
			errs = append(errs, fmt.Errorf("profiles.%s requires hello or client_hello_file", name))
		}
		if p.Hello != "" && p.ClientHelloFile != "" {
			errs = append(errs, fmt.Errorf("profiles.%s cannot set both hello and client_hello_file", name))
		}
		var minVersion, maxVersion uint16
		for index, version := range []string{p.MinVersion, p.MaxVersion} {
			if version != "" {
				parsed, err := TLSVersion(version)
				if err != nil {
					errs = append(errs, fmt.Errorf("profiles.%s: %w", name, err))
				} else if index == 0 {
					minVersion = parsed
				} else {
					maxVersion = parsed
				}
			}
		}
		if minVersion != 0 && maxVersion != 0 && minVersion > maxVersion {
			errs = append(errs, fmt.Errorf("profiles.%s.min_version cannot be higher than max_version", name))
		}
		if p.UserAgent != "" && !httpguts.ValidHeaderFieldValue(p.UserAgent) {
			errs = append(errs, fmt.Errorf("profiles.%s.user_agent is not a valid HTTP header value", name))
		}
		for i, headerName := range p.HeaderOrder {
			if !httpguts.ValidHeaderFieldName(headerName) {
				errs = append(errs, fmt.Errorf("profiles.%s.header_order[%d] is not a valid HTTP header name", name, i))
			}
		}
		for headerName, value := range p.Headers {
			if !httpguts.ValidHeaderFieldName(headerName) {
				errs = append(errs, fmt.Errorf("profiles.%s.headers contains invalid HTTP header name %q", name, headerName))
			}
			if !httpguts.ValidHeaderFieldValue(value) {
				errs = append(errs, fmt.Errorf("profiles.%s.headers.%s is not a valid HTTP header value", name, headerName))
			}
		}
	}
	for i, route := range c.Routes {
		prefix := fmt.Sprintf("routes[%d]", i)
		if route.Host == "" {
			errs = append(errs, fmt.Errorf("%s.host is required", prefix))
		} else if _, err := path.Match(route.Host, "validation-host"); err != nil {
			errs = append(errs, fmt.Errorf("%s.host: invalid glob: %w", prefix, err))
		}
		if route.Profile == "" {
			errs = append(errs, fmt.Errorf("%s.profile is required", prefix))
		}
	}
	return errors.Join(errs...)
}

func appendPositiveDuration(errs []error, field, raw string) []error {
	duration, err := time.ParseDuration(raw)
	if err != nil {
		return append(errs, fmt.Errorf("%s: %w", field, err))
	}
	if duration <= 0 {
		return append(errs, fmt.Errorf("%s must be greater than zero", field))
	}
	return errs
}

func ParseEndpoint(raw string, allowUDP bool) (address, network string, err error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", "", err
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", "", errors.New("endpoint cannot contain user information, a query, or a fragment")
	}
	switch parsed.Scheme {
	case "tcp":
		if parsed.Host == "" || parsed.Path != "" {
			return "", "", errors.New("tcp endpoint requires host:port")
		}
		if _, port, splitErr := net.SplitHostPort(parsed.Host); splitErr != nil || port == "" {
			return "", "", errors.New("tcp endpoint requires a valid host:port")
		}
		return parsed.Host, "tcp", nil
	case "unix":
		if parsed.Host != "" || !filepath.IsAbs(parsed.Path) {
			return "", "", errors.New("unix endpoint requires an absolute path")
		}
		return parsed.Path, "unix", nil
	case "udp":
		if !allowUDP {
			return "", "", errors.New("UDP is not supported here")
		}
		if parsed.Host == "" || parsed.Path != "" {
			return "", "", errors.New("udp endpoint requires host:port")
		}
		if _, port, splitErr := net.SplitHostPort(parsed.Host); splitErr != nil || port == "" {
			return "", "", errors.New("udp endpoint requires a valid host:port")
		}
		return parsed.Host, "udp", nil
	default:
		return "", "", fmt.Errorf("unsupported endpoint scheme %q (use tcp://, udp://, or unix://)", parsed.Scheme)
	}
}

func TLSVersion(raw string) (uint16, error) {
	switch strings.ToLower(raw) {
	case "tls1", "tls1.0", "tls10":
		return 0x0301, nil
	case "tls1.1", "tls11":
		return 0x0302, nil
	case "tls1.2", "tls12":
		return 0x0303, nil
	case "tls1.3", "tls13":
		return 0x0304, nil
	default:
		return 0, fmt.Errorf("unsupported TLS version %q (supported: tls1.0 through tls1.3)", raw)
	}
}
