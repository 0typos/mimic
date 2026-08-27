// Package fingerprint parses TLS ClientHello messages and calculates JA4 TLS
// client fingerprints. JA4 was created by FoxIO and is licensed separately;
// see LICENSE-JA4 in the repository root.
package fingerprint

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const maxClientHello = 1 << 20

var ja4Pattern = regexp.MustCompile(`^[tqd](?:00|10|11|12|13|s2|s3|d1|d2|d3)[di][0-9]{4}[0-9A-Za-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$`)

// ClientHello contains only the fields used by the JA4 TLS client algorithm.
type ClientHello struct {
	LegacyVersion       uint16
	CipherSuites        []uint16
	ExtensionIDs        []uint16
	SupportedVersions   []uint16
	SignatureAlgorithms []uint16
	ALPNProtocols       [][]byte
	HasSNI              bool
}

// JA4 contains the hashed fingerprint and the sorted and original-order raw
// forms used to explain or independently verify it.
type JA4 struct {
	Fingerprint        string `json:"fingerprint"`
	Raw                string `json:"raw"`
	Original           string `json:"original"`
	Version            string `json:"version"`
	SNI                bool   `json:"sni"`
	CipherCount        int    `json:"cipher_count"`
	ExtensionCount     int    `json:"extension_count"`
	ALPN               string `json:"alpn"`
	CipherHashInput    string `json:"cipher_hash_input"`
	ExtensionHashInput string `json:"extension_hash_input"`
}

// ValidateJA4 checks the normalized, hashed JA4 representation accepted as a
// conformance expectation.
func ValidateJA4(value string) error {
	if !ja4Pattern.MatchString(value) {
		return errors.New("must be a normalized JA4 fingerprint such as t13d1516h2_8daaf6152771_d8a2da3f94cd")
	}
	return nil
}

// FromClientHello parses a TLS record or bare ClientHello handshake and
// calculates its JA4 fingerprint for TLS over TCP.
func FromClientHello(raw []byte) (JA4, error) {
	hello, err := ParseClientHello(raw)
	if err != nil {
		return JA4{}, err
	}
	return CalculateJA4(hello), nil
}

// ParseClientHello parses a TLS record stream or a bare TLS handshake message.
func ParseClientHello(raw []byte) (ClientHello, error) {
	handshake, err := clientHelloHandshake(raw)
	if err != nil {
		return ClientHello{}, err
	}
	if len(handshake) < 4 || handshake[0] != 1 {
		return ClientHello{}, errors.New("TLS handshake is not a ClientHello")
	}
	length := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if length > maxClientHello {
		return ClientHello{}, errors.New("ClientHello exceeds 1 MiB")
	}
	if len(handshake)-4 < length {
		return ClientHello{}, errors.New("truncated ClientHello handshake")
	}
	body := handshake[4 : 4+length]
	cursor := helloCursor{data: body}
	legacyVersion, err := cursor.uint16("legacy version")
	if err != nil {
		return ClientHello{}, err
	}
	if _, err := cursor.take(32, "random"); err != nil {
		return ClientHello{}, err
	}
	sessionLength, err := cursor.uint8("session ID length")
	if err != nil {
		return ClientHello{}, err
	}
	if _, err := cursor.take(int(sessionLength), "session ID"); err != nil {
		return ClientHello{}, err
	}
	cipherBytes, err := cursor.vector16("cipher suites")
	if err != nil {
		return ClientHello{}, err
	}
	if len(cipherBytes)%2 != 0 {
		return ClientHello{}, errors.New("cipher suite vector has an odd length")
	}
	compressionLength, err := cursor.uint8("compression methods length")
	if err != nil {
		return ClientHello{}, err
	}
	if _, err := cursor.take(int(compressionLength), "compression methods"); err != nil {
		return ClientHello{}, err
	}

	hello := ClientHello{LegacyVersion: legacyVersion, CipherSuites: uint16Values(cipherBytes)}
	if cursor.remaining() == 0 {
		return hello, nil
	}
	extensions, err := cursor.vector16("extensions")
	if err != nil {
		return ClientHello{}, err
	}
	if cursor.remaining() != 0 {
		return ClientHello{}, errors.New("unexpected data after ClientHello extensions")
	}
	for len(extensions) > 0 {
		if len(extensions) < 4 {
			return ClientHello{}, errors.New("truncated ClientHello extension header")
		}
		id := binary.BigEndian.Uint16(extensions[:2])
		extensionLength := int(binary.BigEndian.Uint16(extensions[2:4]))
		extensions = extensions[4:]
		if extensionLength > len(extensions) {
			return ClientHello{}, fmt.Errorf("truncated ClientHello extension 0x%04x", id)
		}
		data := extensions[:extensionLength]
		extensions = extensions[extensionLength:]
		hello.ExtensionIDs = append(hello.ExtensionIDs, id)
		switch id {
		case 0x0000:
			hello.HasSNI = true
		case 0x000d:
			hello.SignatureAlgorithms, err = parseVector16Values(data, "signature algorithms")
		case 0x0010:
			hello.ALPNProtocols, err = parseALPN(data)
		case 0x002b:
			hello.SupportedVersions, err = parseSupportedVersions(data)
		}
		if err != nil {
			return ClientHello{}, fmt.Errorf("extension 0x%04x: %w", id, err)
		}
	}
	return hello, nil
}

// CalculateJA4 calculates the JA4 TLS-over-TCP fingerprint defined by FoxIO.
func CalculateJA4(hello ClientHello) JA4 {
	ciphersOriginal := withoutGREASE(hello.CipherSuites)
	extensionsOriginal := withoutGREASE(hello.ExtensionIDs)
	signatures := withoutGREASE(hello.SignatureAlgorithms)

	ciphersSorted := append([]uint16(nil), ciphersOriginal...)
	sort.Slice(ciphersSorted, func(i, j int) bool { return ciphersSorted[i] < ciphersSorted[j] })
	extensionsSorted := make([]uint16, 0, len(extensionsOriginal))
	for _, id := range extensionsOriginal {
		if id != 0x0000 && id != 0x0010 {
			extensionsSorted = append(extensionsSorted, id)
		}
	}
	sort.Slice(extensionsSorted, func(i, j int) bool { return extensionsSorted[i] < extensionsSorted[j] })

	version := versionCode(hello.LegacyVersion, hello.SupportedVersions)
	alpn := alpnCode(hello.ALPNProtocols)
	prefix := fmt.Sprintf("t%s%s%02d%02d%s", version, sniCode(hello.HasSNI), cappedCount(len(ciphersOriginal)), cappedCount(len(extensionsOriginal)), alpn)
	cipherInput := hexList(ciphersSorted)
	extensionInput := hexList(extensionsSorted)
	if len(signatures) > 0 {
		extensionInput += "_" + hexList(signatures)
	}
	cipherHash := truncatedHash(cipherInput, len(ciphersSorted) == 0)
	extensionHash := truncatedHash(extensionInput, len(extensionsSorted) == 0)

	originalExtensionInput := hexList(extensionsOriginal)
	if len(signatures) > 0 {
		originalExtensionInput += "_" + hexList(signatures)
	}
	return JA4{
		Fingerprint:        prefix + "_" + cipherHash + "_" + extensionHash,
		Raw:                prefix + "_" + cipherInput + "_" + extensionInput,
		Original:           prefix + "_" + hexList(ciphersOriginal) + "_" + originalExtensionInput,
		Version:            version,
		SNI:                hello.HasSNI,
		CipherCount:        len(ciphersOriginal),
		ExtensionCount:     len(extensionsOriginal),
		ALPN:               alpn,
		CipherHashInput:    cipherInput,
		ExtensionHashInput: extensionInput,
	}
}

func clientHelloHandshake(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("empty ClientHello input")
	}
	if raw[0] == 1 {
		return raw, nil
	}
	var payload []byte
	for offset := 0; offset < len(raw); {
		if len(raw)-offset < 5 {
			return nil, errors.New("truncated TLS record header")
		}
		recordType := raw[offset]
		recordLength := int(binary.BigEndian.Uint16(raw[offset+3 : offset+5]))
		offset += 5
		if recordLength > len(raw)-offset {
			return nil, errors.New("truncated TLS record")
		}
		if recordType != 22 {
			if len(payload) == 0 {
				return nil, fmt.Errorf("TLS record type %d does not contain a handshake", recordType)
			}
			break
		}
		payload = append(payload, raw[offset:offset+recordLength]...)
		offset += recordLength
		if len(payload) >= 4 {
			length := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
			if length > maxClientHello {
				return nil, errors.New("ClientHello exceeds 1 MiB")
			}
			if len(payload) >= 4+length {
				return payload[:4+length], nil
			}
		}
	}
	return nil, errors.New("TLS records do not contain a complete ClientHello")
}

func parseVector16Values(data []byte, name string) ([]uint16, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("truncated %s length", name)
	}
	length := int(binary.BigEndian.Uint16(data[:2]))
	if length != len(data)-2 || length%2 != 0 {
		return nil, fmt.Errorf("invalid %s vector", name)
	}
	return uint16Values(data[2:]), nil
}

func parseSupportedVersions(data []byte) ([]uint16, error) {
	if len(data) < 1 {
		return nil, errors.New("truncated supported versions length")
	}
	length := int(data[0])
	if length != len(data)-1 || length%2 != 0 {
		return nil, errors.New("invalid supported versions vector")
	}
	return uint16Values(data[1:]), nil
}

func parseALPN(data []byte) ([][]byte, error) {
	if len(data) < 2 {
		return nil, errors.New("truncated ALPN length")
	}
	length := int(binary.BigEndian.Uint16(data[:2]))
	if length != len(data)-2 {
		return nil, errors.New("invalid ALPN vector")
	}
	data = data[2:]
	var protocols [][]byte
	for len(data) > 0 {
		itemLength := int(data[0])
		data = data[1:]
		if itemLength > len(data) {
			return nil, errors.New("truncated ALPN protocol")
		}
		protocols = append(protocols, append([]byte(nil), data[:itemLength]...))
		data = data[itemLength:]
	}
	return protocols, nil
}

func versionCode(legacy uint16, supported []uint16) string {
	version := legacy
	values := withoutGREASE(supported)
	if len(values) > 0 {
		version = values[0]
		for _, candidate := range values[1:] {
			if candidate > version {
				version = candidate
			}
		}
	}
	switch version {
	case 0x0002:
		return "s2"
	case 0x0300:
		return "s3"
	case 0x0301:
		return "10"
	case 0x0302:
		return "11"
	case 0x0303:
		return "12"
	case 0x0304:
		return "13"
	case 0xfeff:
		return "d1"
	case 0xfefd:
		return "d2"
	case 0xfefc:
		return "d3"
	default:
		return "00"
	}
}

func alpnCode(protocols [][]byte) string {
	if len(protocols) == 0 || len(protocols[0]) == 0 {
		return "00"
	}
	first := protocols[0]
	left, right := first[0], first[len(first)-1]
	if asciiAlphaNumeric(left) && asciiAlphaNumeric(right) {
		if len(first) == 1 {
			return string([]byte{left, left})
		}
		return string([]byte{left, right})
	}
	encoded := hex.EncodeToString(first)
	return string([]byte{encoded[0], encoded[len(encoded)-1]})
}

func asciiAlphaNumeric(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

func withoutGREASE(values []uint16) []uint16 {
	result := make([]uint16, 0, len(values))
	for _, value := range values {
		if !isGREASE(value) {
			result = append(result, value)
		}
	}
	return result
}

func isGREASE(value uint16) bool {
	return value&0x0f0f == 0x0a0a && byte(value>>8) == byte(value)
}

func hexList(values []uint16) string {
	parts := make([]string, len(values))
	for i, value := range values {
		parts[i] = fmt.Sprintf("%04x", value)
	}
	return strings.Join(parts, ",")
}

func truncatedHash(input string, empty bool) string {
	if empty {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])[:12]
}

func cappedCount(count int) int {
	if count > 99 {
		return 99
	}
	return count
}

func sniCode(hasSNI bool) string {
	if hasSNI {
		return "d"
	}
	return "i"
}

func uint16Values(raw []byte) []uint16 {
	values := make([]uint16, 0, len(raw)/2)
	for len(raw) >= 2 {
		values = append(values, binary.BigEndian.Uint16(raw[:2]))
		raw = raw[2:]
	}
	return values
}

type helloCursor struct {
	data   []byte
	offset int
}

func (c *helloCursor) remaining() int { return len(c.data) - c.offset }

func (c *helloCursor) take(length int, name string) ([]byte, error) {
	if length < 0 || length > c.remaining() {
		return nil, fmt.Errorf("truncated ClientHello %s", name)
	}
	value := c.data[c.offset : c.offset+length]
	c.offset += length
	return value, nil
}

func (c *helloCursor) uint8(name string) (byte, error) {
	raw, err := c.take(1, name)
	if err != nil {
		return 0, err
	}
	return raw[0], nil
}

func (c *helloCursor) uint16(name string) (uint16, error) {
	raw, err := c.take(2, name)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(raw), nil
}

func (c *helloCursor) vector16(name string) ([]byte, error) {
	length, err := c.uint16(name + " length")
	if err != nil {
		return nil, err
	}
	return c.take(int(length), name)
}
