package profiles

import (
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	utls "github.com/refraction-networking/utls"

	"github.com/0typos/mimic/internal/config"
	"github.com/0typos/mimic/internal/fingerprint"
)

type Profile struct {
	Name           string
	Hello          utls.ClientHelloID
	RawClientHello []byte
	JA4            string
	JA4H           string
	Browser        string
	BrowserVersion string
	Platform       string
	Lifecycle      string
	Source         string
	CapturedAt     string
	Builtin        bool
	UserAgent      string
	HeaderOrder    []string
	Headers        map[string]string
	MinVersion     uint16
	MaxVersion     uint16
}

type Registry struct {
	items map[string]Profile
}

// Info is the operator-facing identity and maintenance status of a profile.
type Info struct {
	Name           string `json:"name"`
	Browser        string `json:"browser,omitempty"`
	BrowserVersion string `json:"browser_version,omitempty"`
	Platform       string `json:"platform,omitempty"`
	Lifecycle      string `json:"lifecycle"`
	Source         string `json:"source,omitempty"`
	CapturedAt     string `json:"captured_at,omitempty"`
	JA4            string `json:"ja4,omitempty"`
	Builtin        bool   `json:"builtin"`
}

func New(custom map[string]config.Profile) (*Registry, error) {
	items := builtin()
	for name, definition := range custom {
		p, err := fromConfig(name, definition)
		if err != nil {
			return nil, err
		}
		items[name] = p
	}
	return &Registry{items: items}, nil
}

func (r *Registry) Get(name string) (Profile, bool) {
	p, ok := r.items[name]
	return p, ok
}

func (r *Registry) Names() []string {
	names := make([]string, 0, len(r.items))
	for name := range r.items {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (r *Registry) Infos() []Info {
	names := r.Names()
	infos := make([]Info, 0, len(names))
	for _, name := range names {
		profile := r.items[name]
		infos = append(infos, Info{
			Name: profile.Name, Browser: profile.Browser, BrowserVersion: profile.BrowserVersion,
			Platform: profile.Platform, Lifecycle: profile.Lifecycle, Source: profile.Source,
			CapturedAt: profile.CapturedAt, JA4: profile.JA4, Builtin: profile.Builtin,
		})
	}
	return infos
}

func (p Profile) Apply(conn *utls.UConn) error {
	if len(p.RawClientHello) == 0 {
		return nil
	}
	var spec utls.ClientHelloSpec
	if err := spec.FromRaw(p.RawClientHello, true); err != nil {
		return fmt.Errorf("parse saved ClientHello for profile %q: %w", p.Name, err)
	}
	if p.MinVersion != 0 {
		spec.TLSVersMin = p.MinVersion
	}
	if p.MaxVersion != 0 {
		spec.TLSVersMax = p.MaxVersion
	}
	if err := conn.ApplyPreset(&spec); err != nil {
		return fmt.Errorf("apply profile %q: %w", p.Name, err)
	}
	return nil
}

func fromConfig(name string, definition config.Profile) (Profile, error) {
	p := Profile{
		Name:           name,
		JA4:            definition.JA4,
		JA4H:           definition.JA4H,
		Browser:        definition.Browser,
		BrowserVersion: definition.BrowserVersion,
		Platform:       definition.Platform,
		Lifecycle:      definition.Lifecycle,
		Source:         definition.Source,
		CapturedAt:     definition.CapturedAt,
		UserAgent:      definition.UserAgent,
		HeaderOrder:    append([]string(nil), definition.HeaderOrder...),
		Headers:        cloneMap(definition.Headers),
	}
	if p.Lifecycle == "" {
		p.Lifecycle = "custom"
	}
	if definition.Hello != "" {
		hello, ok := helloIDs()[strings.ToLower(definition.Hello)]
		if !ok {
			return Profile{}, fmt.Errorf("profiles.%s.hello: unknown preset %q", name, definition.Hello)
		}
		p.Hello = hello
	} else {
		raw, err := os.ReadFile(definition.ClientHelloFile)
		if err != nil {
			return Profile{}, fmt.Errorf("profiles.%s.client_hello_file: %w", name, err)
		}
		trimmed := strings.TrimSpace(string(raw))
		if decoded, err := hex.DecodeString(strings.Join(strings.Fields(trimmed), "")); err == nil {
			raw = decoded
		}
		p.RawClientHello, err = normalizeForUTLS(raw)
		if err != nil {
			return Profile{}, fmt.Errorf("profiles.%s.client_hello_file: %w", name, err)
		}
		var spec utls.ClientHelloSpec
		if err := spec.FromRaw(p.RawClientHello, true); err != nil {
			return Profile{}, fmt.Errorf("profiles.%s.client_hello_file: invalid TLS ClientHello: %w", name, err)
		}
		p.Hello = utls.HelloCustom
	}
	if definition.MinVersion != "" {
		p.MinVersion, _ = config.TLSVersion(definition.MinVersion)
	}
	if definition.MaxVersion != "" {
		p.MaxVersion, _ = config.TLSVersion(definition.MaxVersion)
	}
	return p, nil
}

func normalizeForUTLS(raw []byte) ([]byte, error) {
	handshake, err := fingerprint.ExtractClientHello(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid TLS ClientHello: %w", err)
	}
	if len(handshake) > 0xffff {
		return nil, errors.New("ClientHello is too large for one TLS record")
	}
	version := uint16(utls.VersionTLS10)
	if len(raw) >= 3 && raw[0] == 22 {
		version = binary.BigEndian.Uint16(raw[1:3])
	}
	record := make([]byte, 5, 5+len(handshake))
	record[0] = 22
	binary.BigEndian.PutUint16(record[1:3], version)
	binary.BigEndian.PutUint16(record[3:5], uint16(len(handshake)))
	return append(record, handshake...), nil
}

//go:embed captures/chrome-152-linux.hex
var chrome152LinuxCapture string

//go:embed captures/firefox-154-linux.hex
var firefox154LinuxCapture string

//go:embed captures/chromium-151-linux.hex
var chromium151LinuxCapture string

//go:embed captures/edge-151-linux.hex
var edge151LinuxCapture string

//go:embed captures/firefox-153-esr-linux.hex
var firefox153ESRLinuxCapture string

func builtin() map[string]Profile {
	return map[string]Profile{
		"chrome-152-linux": capturedBuiltin(
			"chrome-152-linux",
			chrome152LinuxCapture,
			"Chrome",
			"152.0.7977.64",
			"Fedora 44 Linux x86_64",
			"2026-08-27T18:35:54-04:00",
			"t13d1517h2_8daaf6152771_cb7bf5808d99",
			"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36",
			[]string{"host", "connection", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "upgrade-insecure-requests", "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest", "accept-encoding", "accept-language", "cookie"},
		),
		"firefox-154-linux": capturedBuiltin(
			"firefox-154-linux",
			firefox154LinuxCapture,
			"Firefox",
			"154.0",
			"Fedora 44 Linux x86_64",
			"2026-08-27T18:54:42-04:00",
			"t13d1517h2_8daaf6152771_3e9721a6796e",
			"Mozilla/5.0 (X11; Linux x86_64; rv:154.0) Gecko/20100101 Firefox/154.0",
			[]string{"host", "user-agent", "accept", "accept-language", "accept-encoding", "connection", "upgrade-insecure-requests", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user", "cookie"},
		),
		"chromium-151-linux": capturedBuiltin(
			"chromium-151-linux",
			chromium151LinuxCapture,
			"Chromium",
			"151.0.7922.173",
			"Fedora 44 Linux x86_64",
			"2026-08-27T18:47:09-04:00",
			"t13d1516h2_8daaf6152771_806a8c22fdea",
			"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
			[]string{"host", "connection", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "upgrade-insecure-requests", "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest", "accept-encoding", "accept-language", "cookie"},
		),
		"edge-151-linux": capturedBuiltin(
			"edge-151-linux",
			edge151LinuxCapture,
			"Edge",
			"151.0.4129.101",
			"Fedora 44 Linux x86_64",
			"2026-08-27T18:45:37-04:00",
			"t13d1516h2_8daaf6152771_806a8c22fdea",
			"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36 Edg/151.0.0.0",
			[]string{"host", "connection", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "upgrade-insecure-requests", "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest", "accept-encoding", "accept-language", "cookie"},
		),
		"firefox-153-esr-linux": capturedBuiltin(
			"firefox-153-esr-linux",
			firefox153ESRLinuxCapture,
			"Firefox ESR",
			"153.1.0esr",
			"Fedora 44 Linux x86_64",
			"2026-08-27T18:55:12-04:00",
			"t13d1617h2_86a278354501_3cbfd9057e0d",
			"Mozilla/5.0 (X11; Linux x86_64; rv:153.0) Gecko/20100101 Firefox/153.0",
			[]string{"host", "user-agent", "accept", "accept-language", "accept-encoding", "connection", "upgrade-insecure-requests", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user", "cookie"},
		),
		"chrome-133": {
			Name: "chrome-133", Hello: utls.HelloChrome_133, JA4: "t13d1516h2_8daaf6152771_d8a2da3f94cd",
			Browser: "Chrome", BrowserVersion: "133", Lifecycle: "legacy", Builtin: true,
			UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
			HeaderOrder: []string{"host", "connection", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "upgrade-insecure-requests", "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest", "accept-encoding", "accept-language", "cookie"},
		},
		"firefox-120": {
			Name: "firefox-120", Hello: utls.HelloFirefox_120, JA4: "t13d1715h2_5b57614c22b0_5c2c66f702b0",
			Browser: "Firefox", BrowserVersion: "120", Lifecycle: "legacy", Builtin: true,
			UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
			HeaderOrder: []string{"host", "user-agent", "accept", "accept-language", "accept-encoding", "connection", "upgrade-insecure-requests", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user", "cookie"},
		},
		"safari-16": {
			Name: "safari-16", Hello: utls.HelloSafari_16_0, JA4: "t13d2014h2_a09f3c656075_14788d8d241b",
			Browser: "Safari", BrowserVersion: "16.0", Lifecycle: "legacy", Builtin: true,
			UserAgent:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
			HeaderOrder: []string{"host", "accept", "user-agent", "accept-language", "accept-encoding", "connection", "cookie"},
		},
		"ios-14": {
			Name: "ios-14", Hello: utls.HelloIOS_14, JA4: "t13d2613h2_2802a3db6c62_845d286b0d67",
			Browser: "Safari", BrowserVersion: "14", Platform: "iOS 14", Lifecycle: "legacy", Builtin: true,
			UserAgent:   "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
			HeaderOrder: []string{"host", "accept", "user-agent", "accept-language", "accept-encoding", "connection", "cookie"},
		},
		"android-11": {
			Name: "android-11", Hello: utls.HelloAndroid_11_OkHttp, JA4: "t12d120700_d34a8e72043a_036209cd1ead",
			Browser: "OkHttp", BrowserVersion: "4.9.3", Platform: "Android 11", Lifecycle: "legacy", Builtin: true,
			UserAgent:   "okhttp/4.9.3",
			HeaderOrder: []string{"host", "connection", "accept-encoding", "user-agent", "cookie"},
		},
	}
}

func capturedBuiltin(name, encoded, browser, browserVersion, platform, capturedAt, ja4, userAgent string, headerOrder []string) Profile {
	raw, err := hex.DecodeString(strings.Join(strings.Fields(encoded), ""))
	if err != nil {
		panic(fmt.Sprintf("decode embedded profile %s: %v", name, err))
	}
	observed, err := fingerprint.FromClientHello(raw)
	if err != nil {
		panic(fmt.Sprintf("calculate embedded profile %s JA4: %v", name, err))
	}
	if observed.Fingerprint != ja4 {
		panic(fmt.Sprintf("embedded profile %s JA4 is %s, want %s", name, observed.Fingerprint, ja4))
	}
	raw, err = normalizeForUTLS(raw)
	if err != nil {
		panic(fmt.Sprintf("normalize embedded profile %s: %v", name, err))
	}
	return Profile{
		Name: name, Hello: utls.HelloCustom, RawClientHello: raw, JA4: ja4,
		Browser: browser, BrowserVersion: browserVersion, Platform: platform,
		Lifecycle: "current", Source: "reproducible real-client capture; see docs/profile-captures.md",
		CapturedAt: capturedAt, Builtin: true, UserAgent: userAgent,
		HeaderOrder: headerOrder,
	}
}

func helloIDs() map[string]utls.ClientHelloID {
	return map[string]utls.ClientHelloID{
		"chrome-58": utls.HelloChrome_58, "chrome-62": utls.HelloChrome_62,
		"chrome-70": utls.HelloChrome_70, "chrome-83": utls.HelloChrome_83,
		"chrome-96": utls.HelloChrome_96, "chrome-120": utls.HelloChrome_120,
		"chrome-131": utls.HelloChrome_131, "chrome-133": utls.HelloChrome_133,
		"firefox-55": utls.HelloFirefox_55, "firefox-65": utls.HelloFirefox_65,
		"firefox-99": utls.HelloFirefox_99, "firefox-120": utls.HelloFirefox_120,
		"safari-16": utls.HelloSafari_16_0,
		"ios-11.1":  utls.HelloIOS_11_1, "ios-12.1": utls.HelloIOS_12_1,
		"ios-13": utls.HelloIOS_13, "ios-14": utls.HelloIOS_14,
		"android-11": utls.HelloAndroid_11_OkHttp,
		"edge-85":    utls.HelloEdge_85, "edge-106": utls.HelloEdge_106,
		"go": utls.HelloGolang,
	}
}

func cloneMap(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for k, v := range source {
		result[k] = v
	}
	return result
}
