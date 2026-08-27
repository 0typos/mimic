package profilecapture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"

	"github.com/msmythe/mimic/internal/config"
)

func TestWriteProfileCreatesLoadableFiles(t *testing.T) {
	raw := capturedClientHello(t)
	result, err := analyze(raw, "192.0.2.10:50000 -> 192.0.2.20:443")
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "profiles", "chrome.toml")
	written, err := WriteProfile(result, ProfileOptions{
		Name:           "chrome-152-linux",
		Output:         output,
		Browser:        "Chrome",
		BrowserVersion: "152",
		Platform:       "Fedora Linux",
		Lifecycle:      "custom",
		Source:         "controlled capture",
		CapturedAt:     "2026-08-27T18:35:54-04:00",
		UserAgent:      "Chrome/152",
		JA4H:           "metadata",
		HeaderOrder:    []string{"host", "user-agent"},
		Headers:        map[string]string{"Accept-Language": "en-US"},
		MinVersion:     "tls1.2",
		MaxVersion:     "tls1.3",
	})
	if err != nil {
		t.Fatal(err)
	}
	if written.ProfilePath != output || !strings.HasSuffix(written.CapturePath, ".clienthello.hex") {
		t.Fatalf("unexpected paths: %+v", written)
	}
	body, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `platform = "Fedora Linux"`) || !strings.Contains(string(body), `ja4 = "`+result.JA4.Fingerprint+`"`) {
		t.Fatalf("unexpected profile body:\n%s", body)
	}
	var decoded struct {
		Profiles map[string]config.Profile `toml:"profiles"`
	}
	if _, err := toml.Decode(string(body), &decoded); err != nil {
		t.Fatal(err)
	}
	profile := decoded.Profiles["chrome-152-linux"]
	if profile.ClientHelloFile != filepath.Base(written.CapturePath) || profile.UserAgent != "Chrome/152" || profile.Lifecycle != "custom" {
		t.Fatalf("decoded profile = %+v", profile)
	}
	if _, err := Import(written.CapturePath); err != nil {
		t.Fatalf("generated capture cannot be imported: %v", err)
	}
}

func TestWriteProfileRefusesInvalidAndExistingOutputs(t *testing.T) {
	result, err := analyze(capturedClientHello(t), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := WriteProfile(result, ProfileOptions{Name: "bad.name"}); err == nil {
		t.Fatal("invalid profile name unexpectedly succeeded")
	}
	if _, err := WriteProfile(Result{}, ProfileOptions{Name: "valid"}); err == nil {
		t.Fatal("empty profile unexpectedly succeeded")
	}
	output := filepath.Join(t.TempDir(), "profile.toml")
	options := ProfileOptions{Name: "valid", Output: output}
	if _, err := WriteProfile(result, options); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteProfile(result, options); err == nil || !strings.Contains(err.Error(), "overwrite") {
		t.Fatalf("existing output error = %v", err)
	}
	options.Force = true
	if _, err := WriteProfile(result, options); err != nil {
		t.Fatalf("forced overwrite: %v", err)
	}
}

func TestWriteProfileValidatesMetadataAndHTTPIdentity(t *testing.T) {
	result, err := analyze(capturedClientHello(t), "")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*ProfileOptions)
		want   string
	}{
		{"lifecycle", func(o *ProfileOptions) { o.Lifecycle = "stale" }, "lifecycle"},
		{"captured at", func(o *ProfileOptions) { o.CapturedAt = "yesterday" }, "RFC3339"},
		{"metadata newline", func(o *ProfileOptions) { o.Source = "one\ntwo" }, "newlines"},
		{"user agent", func(o *ProfileOptions) { o.UserAgent = "one\ntwo" }, "user-agent"},
		{"header order", func(o *ProfileOptions) { o.HeaderOrder = []string{"Bad Header"} }, "header-order"},
		{"header name", func(o *ProfileOptions) { o.Headers = map[string]string{"Bad Header": "value"} }, "header name"},
		{"header value", func(o *ProfileOptions) { o.Headers = map[string]string{"X-Test": "one\ntwo"} }, "header value"},
		{"minimum TLS", func(o *ProfileOptions) { o.MinVersion = "ssl3" }, "min-version"},
		{"maximum TLS", func(o *ProfileOptions) { o.MaxVersion = "ssl3" }, "max-version"},
		{"TLS bounds", func(o *ProfileOptions) { o.MinVersion, o.MaxVersion = "tls1.3", "tls1.2" }, "higher"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := ProfileOptions{Name: "valid", Output: filepath.Join(t.TempDir(), "profile.toml")}
			test.mutate(&options)
			if _, err := WriteProfile(result, options); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected %q, got %v", test.want, err)
			}
		})
	}
}
