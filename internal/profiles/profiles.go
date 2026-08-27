package profiles

import (
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"

	utls "github.com/refraction-networking/utls"

	"github.com/msmythe/mimic/internal/config"
)

type Profile struct {
	Name           string
	Hello          utls.ClientHelloID
	RawClientHello []byte
	JA4            string
	JA4H           string
	UserAgent      string
	HeaderOrder    []string
	Headers        map[string]string
	MinVersion     uint16
	MaxVersion     uint16
}

type Registry struct {
	items map[string]Profile
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

func (p Profile) Apply(conn *utls.UConn) error {
	if len(p.RawClientHello) == 0 {
		return nil
	}
	var spec utls.ClientHelloSpec
	if err := spec.FromRaw(p.RawClientHello); err != nil {
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
		Name:        name,
		JA4:         definition.JA4,
		JA4H:        definition.JA4H,
		UserAgent:   definition.UserAgent,
		HeaderOrder: append([]string(nil), definition.HeaderOrder...),
		Headers:     cloneMap(definition.Headers),
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
		if decoded, err := hex.DecodeString(strings.ReplaceAll(trimmed, " ", "")); err == nil {
			p.RawClientHello = decoded
		} else {
			p.RawClientHello = raw
		}
		var spec utls.ClientHelloSpec
		if err := spec.FromRaw(p.RawClientHello); err != nil {
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

func builtin() map[string]Profile {
	return map[string]Profile{
		"chrome-133": {
			Name: "chrome-133", Hello: utls.HelloChrome_133,
			UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
			HeaderOrder: []string{"host", "connection", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "upgrade-insecure-requests", "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest", "accept-encoding", "accept-language", "cookie"},
		},
		"firefox-120": {
			Name: "firefox-120", Hello: utls.HelloFirefox_120,
			UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
			HeaderOrder: []string{"host", "user-agent", "accept", "accept-language", "accept-encoding", "connection", "upgrade-insecure-requests", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user", "cookie"},
		},
		"safari-16": {
			Name: "safari-16", Hello: utls.HelloSafari_16_0,
			UserAgent:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
			HeaderOrder: []string{"host", "accept", "user-agent", "accept-language", "accept-encoding", "connection", "cookie"},
		},
		"ios-14": {
			Name: "ios-14", Hello: utls.HelloIOS_14,
			UserAgent:   "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
			HeaderOrder: []string{"host", "accept", "user-agent", "accept-language", "accept-encoding", "connection", "cookie"},
		},
		"android-11": {
			Name: "android-11", Hello: utls.HelloAndroid_11_OkHttp,
			UserAgent:   "okhttp/4.9.3",
			HeaderOrder: []string{"host", "connection", "accept-encoding", "user-agent", "cookie"},
		},
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
