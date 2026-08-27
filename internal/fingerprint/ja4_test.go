package fingerprint

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type ja4Fixture struct {
	LegacyVersion       string   `json:"legacy_version"`
	SupportedVersions   []string `json:"supported_versions"`
	Ciphers             []string `json:"ciphers"`
	Extensions          []string `json:"extensions"`
	SignatureAlgorithms []string `json:"signature_algorithms"`
	ALPN                string   `json:"alpn"`
	Expected            string   `json:"expected"`
	ExpectedRaw         string   `json:"expected_raw"`
	ExpectedOriginal    string   `json:"expected_original"`
}

func TestCalculateJA4FoxIOVector(t *testing.T) {
	fixture := loadFixture(t)
	hello := fixtureHello(t, fixture)
	result := CalculateJA4(hello)
	if result.Fingerprint != fixture.Expected {
		t.Fatalf("JA4 = %q, want %q", result.Fingerprint, fixture.Expected)
	}
	if result.Raw != fixture.ExpectedRaw {
		t.Fatalf("JA4_r = %q, want %q", result.Raw, fixture.ExpectedRaw)
	}
	if result.Original != fixture.ExpectedOriginal {
		t.Fatalf("JA4_ro = %q, want %q", result.Original, fixture.ExpectedOriginal)
	}
}

func TestParseTLSRecordAndBareHandshake(t *testing.T) {
	fixture := loadFixture(t)
	record := fixtureRecord(t, fixture)
	for _, raw := range [][]byte{record, record[5:]} {
		result, err := FromClientHello(raw)
		if err != nil {
			t.Fatal(err)
		}
		if result.Fingerprint != fixture.Expected {
			t.Fatalf("JA4 = %q, want %q", result.Fingerprint, fixture.Expected)
		}
	}
}

func TestParseClientHelloAcrossTLSRecords(t *testing.T) {
	fixture := loadFixture(t)
	handshake := fixtureRecord(t, fixture)[5:]
	split := len(handshake) / 2
	records := appendTLSRecord(nil, handshake[:split])
	records = appendTLSRecord(records, handshake[split:])
	result, err := FromClientHello(records)
	if err != nil {
		t.Fatal(err)
	}
	if result.Fingerprint != fixture.Expected {
		t.Fatalf("JA4 = %q, want %q", result.Fingerprint, fixture.Expected)
	}
}

func TestParseRejectsMalformedClientHello(t *testing.T) {
	for _, raw := range [][]byte{
		nil,
		{22, 3, 1, 0, 10, 1},
		{1, 0, 0, 4, 3, 3},
		{2, 0, 0, 0},
	} {
		if _, err := ParseClientHello(raw); err == nil {
			t.Errorf("ParseClientHello(%x) unexpectedly succeeded", raw)
		}
	}
	if _, err := FromClientHello(nil); err == nil {
		t.Fatal("FromClientHello unexpectedly accepted empty input")
	}
}

func TestParseMinimalClientHelloWithoutExtensions(t *testing.T) {
	body := append(uint16Bytes(0x0303), make([]byte, 32)...)
	body = append(body, 0)
	body = appendVector16(body, uint16Bytes(0x1301))
	body = append(body, 1, 0)
	result, err := FromClientHello(wrapHandshake(body))
	if err != nil {
		t.Fatal(err)
	}
	if result.Version != "12" || result.SNI || result.ALPN != "00" {
		t.Fatalf("unexpected minimal result: %+v", result)
	}
}

func TestParseRejectsMalformedClientHelloFields(t *testing.T) {
	validPrefix := append(uint16Bytes(0x0303), make([]byte, 32)...)
	tests := map[string][]byte{
		"random":              {3, 3},
		"session length":      validPrefix,
		"session":             append(append([]byte(nil), validPrefix...), 2, 1),
		"cipher length":       append(append([]byte(nil), validPrefix...), 0, 0),
		"odd ciphers":         append(append([]byte(nil), validPrefix...), 0, 0, 1, 1),
		"compression length":  append(append([]byte(nil), validPrefix...), 0, 0, 2, 0x13, 0x01),
		"compression methods": append(append([]byte(nil), validPrefix...), 0, 0, 2, 0x13, 0x01, 2, 0),
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseClientHello(wrapHandshake(body)); err == nil {
				t.Fatalf("malformed %s unexpectedly succeeded", name)
			}
		})
	}

	base := append(append([]byte(nil), validPrefix...), 0, 0, 2, 0x13, 0x01, 1, 0)
	for name, suffix := range map[string][]byte{
		"extensions length": {0},
		"extensions trailing": {
			0, 0, 1,
		},
		"extension header": {0, 2, 0, 1},
		"extension body":   {0, 4, 0, 13, 0, 2},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseClientHello(wrapHandshake(append(append([]byte(nil), base...), suffix...))); err == nil {
				t.Fatalf("malformed %s unexpectedly succeeded", name)
			}
		})
	}
}

func TestTLSRecordStreamErrors(t *testing.T) {
	for name, raw := range map[string][]byte{
		"header":           {22, 3},
		"non-handshake":    {23, 3, 3, 0, 0},
		"interrupted":      {22, 3, 3, 0, 2, 1, 0, 23, 3, 3, 0, 0},
		"oversized length": {22, 3, 3, 0, 4, 1, 0x10, 0, 1},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseClientHello(raw); err == nil {
				t.Fatal("malformed TLS record stream unexpectedly succeeded")
			}
		})
	}
}

func TestALPNCode(t *testing.T) {
	for _, test := range []struct {
		value []byte
		want  string
	}{
		{nil, "00"},
		{[]byte("h2"), "h2"},
		{[]byte("http/1.1"), "h1"},
		{[]byte("x"), "xx"},
		{[]byte{0xab}, "ab"},
		{[]byte{0x20}, "20"},
		{[]byte{0xab, 0xcd}, "ad"},
		{[]byte{0x20, 0x61}, "21"},
		{[]byte{0x30, 0xab}, "3b"},
		{[]byte{0x61, 0x20}, "60"},
	} {
		protocols := [][]byte(nil)
		if test.value != nil {
			protocols = [][]byte{test.value}
		}
		if got := alpnCode(protocols); got != test.want {
			t.Errorf("alpnCode(%x) = %q, want %q", test.value, got, test.want)
		}
	}
}

func TestGREASEIsExcludedEverywhere(t *testing.T) {
	hello := ClientHello{
		LegacyVersion:       0x0303,
		SupportedVersions:   []uint16{0x1a1a, 0x0304},
		CipherSuites:        []uint16{0x0a0a, 0x1301},
		ExtensionIDs:        []uint16{0x2a2a, 0x0000, 0x0010, 0x000d},
		SignatureAlgorithms: []uint16{0x3a3a, 0x0403},
		ALPNProtocols:       [][]byte{[]byte("h2")},
		HasSNI:              true,
	}
	result := CalculateJA4(hello)
	if result.CipherCount != 1 || result.ExtensionCount != 3 || result.Version != "13" {
		t.Fatalf("GREASE affected result: %+v", result)
	}
	if result.CipherHashInput != "1301" || result.ExtensionHashInput != "000d_0403" {
		t.Fatalf("GREASE remained in hash input: %+v", result)
	}
}

func TestJA4EmptyFieldsAndCountCaps(t *testing.T) {
	values := make([]uint16, 100)
	for i := range values {
		values[i] = uint16(i + 1)
	}
	result := CalculateJA4(ClientHello{LegacyVersion: 0x0301, CipherSuites: values, ExtensionIDs: values})
	if !strings.HasPrefix(result.Fingerprint, "t10i999900_") {
		t.Fatalf("counts were not capped: %s", result.Fingerprint)
	}
	empty := CalculateJA4(ClientHello{LegacyVersion: 0xffff})
	if empty.Fingerprint != "t00i000000_000000000000_000000000000" {
		t.Fatalf("empty JA4 = %q", empty.Fingerprint)
	}
}

func TestVersionCodes(t *testing.T) {
	for _, test := range []struct {
		legacy    uint16
		supported []uint16
		want      string
	}{
		{0x0002, nil, "s2"},
		{0x0300, nil, "s3"},
		{0x0301, nil, "10"},
		{0x0302, nil, "11"},
		{0x0303, nil, "12"},
		{0x0304, nil, "13"},
		{0xfeff, nil, "d1"},
		{0xfefd, nil, "d2"},
		{0xfefc, nil, "d3"},
		{0xffff, nil, "00"},
		{0x0301, []uint16{0x0a0a, 0x0303, 0x0304}, "13"},
		{0x0302, []uint16{0x1a1a}, "11"},
	} {
		if got := versionCode(test.legacy, test.supported); got != test.want {
			t.Errorf("versionCode(%04x, %04x) = %q, want %q", test.legacy, test.supported, got, test.want)
		}
	}
}

func TestExtensionVectorErrors(t *testing.T) {
	for name, test := range map[string]func() error{
		"signature length": func() error { _, err := parseVector16Values(nil, "signatures"); return err },
		"signature vector": func() error { _, err := parseVector16Values([]byte{0, 1, 4}, "signatures"); return err },
		"versions length":  func() error { _, err := parseSupportedVersions(nil); return err },
		"versions vector":  func() error { _, err := parseSupportedVersions([]byte{1, 3}); return err },
		"ALPN length":      func() error { _, err := parseALPN(nil); return err },
		"ALPN vector":      func() error { _, err := parseALPN([]byte{0, 2, 1}); return err },
		"ALPN protocol":    func() error { _, err := parseALPN([]byte{0, 2, 2, 'h'}); return err },
	} {
		t.Run(name, func(t *testing.T) {
			if err := test(); err == nil {
				t.Fatal("invalid extension vector unexpectedly succeeded")
			}
		})
	}
}

func TestValidateJA4(t *testing.T) {
	if err := ValidateJA4("t13d1516h2_8daaf6152771_d8a2da3f94cd"); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"", "expected", "tzzd1516h2_000000000000_000000000000", "t13d1516h2_UPPERCASE000_000000000000"} {
		if err := ValidateJA4(value); err == nil {
			t.Errorf("ValidateJA4(%q) unexpectedly succeeded", value)
		}
	}
}

func loadFixture(t *testing.T) ja4Fixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/foxio-ja4.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture ja4Fixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func fixtureHello(t *testing.T, fixture ja4Fixture) ClientHello {
	t.Helper()
	return ClientHello{
		LegacyVersion:       hexValue(t, fixture.LegacyVersion),
		SupportedVersions:   hexValues(t, fixture.SupportedVersions),
		CipherSuites:        hexValues(t, fixture.Ciphers),
		ExtensionIDs:        hexValues(t, fixture.Extensions),
		SignatureAlgorithms: hexValues(t, fixture.SignatureAlgorithms),
		ALPNProtocols:       [][]byte{[]byte(fixture.ALPN)},
		HasSNI:              true,
	}
}

func fixtureRecord(t *testing.T, fixture ja4Fixture) []byte {
	t.Helper()
	hello := fixtureHello(t, fixture)
	body := uint16Bytes(hello.LegacyVersion)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)
	body = appendVector16(body, valuesBytes(hello.CipherSuites))
	body = append(body, 1, 0)
	var extensions []byte
	for _, id := range hello.ExtensionIDs {
		var data []byte
		switch id {
		case 0x000d:
			data = appendVector16(nil, valuesBytes(hello.SignatureAlgorithms))
		case 0x0010:
			protocol := hello.ALPNProtocols[0]
			data = appendVector16(nil, append([]byte{byte(len(protocol))}, protocol...))
		case 0x002b:
			versions := valuesBytes(hello.SupportedVersions)
			data = append([]byte{byte(len(versions))}, versions...)
		}
		extensions = append(extensions, uint16Bytes(id)...)
		extensions = appendVector16(extensions, data)
	}
	body = appendVector16(body, extensions)
	handshake := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	handshake = append(handshake, body...)
	record := []byte{22, 3, 1, byte(len(handshake) >> 8), byte(len(handshake))}
	return append(record, handshake...)
}

func appendVector16(destination, value []byte) []byte {
	destination = append(destination, byte(len(value)>>8), byte(len(value)))
	return append(destination, value...)
}

func appendTLSRecord(destination, handshake []byte) []byte {
	destination = append(destination, 22, 3, 1, byte(len(handshake)>>8), byte(len(handshake)))
	return append(destination, handshake...)
}

func wrapHandshake(body []byte) []byte {
	handshake := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(handshake, body...)
}

func valuesBytes(values []uint16) []byte {
	raw := make([]byte, len(values)*2)
	for i, value := range values {
		binary.BigEndian.PutUint16(raw[i*2:], value)
	}
	return raw
}

func uint16Bytes(value uint16) []byte {
	return []byte{byte(value >> 8), byte(value)}
}

func hexValues(t *testing.T, values []string) []uint16 {
	t.Helper()
	result := make([]uint16, len(values))
	for i, value := range values {
		result[i] = hexValue(t, value)
	}
	return result
}

func hexValue(t *testing.T, value string) uint16 {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 2 {
		t.Fatalf("invalid fixture hex %q", value)
	}
	return binary.BigEndian.Uint16(raw)
}
