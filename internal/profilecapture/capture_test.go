package profilecapture

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	utls "github.com/refraction-networking/utls"
)

func TestImportBinaryAndHex(t *testing.T) {
	raw := capturedClientHello(t)
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "hello.bin")
	if err := os.WriteFile(binaryPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	hexPath := filepath.Join(dir, "hello.hex")
	encoded := hex.EncodeToString(raw)
	if err := os.WriteFile(hexPath, []byte(strings.Join(splitEvery(encoded, 16), "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{binaryPath, hexPath} {
		result, err := Import(path)
		if err != nil {
			t.Fatalf("Import(%s): %v", path, err)
		}
		if len(result.ClientHello) == 0 || result.ClientHello[0] != 1 || result.JA4.Fingerprint == "" {
			t.Fatalf("invalid imported capture: %+v", result)
		}
	}
}

func TestImportFailures(t *testing.T) {
	if _, err := Import(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing input unexpectedly succeeded")
	}
	path := filepath.Join(t.TempDir(), "odd.hex")
	if err := os.WriteFile(path, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Import(path); err == nil || !strings.Contains(err.Error(), "hexadecimal") {
		t.Fatalf("odd hexadecimal error = %v", err)
	}
	path = filepath.Join(t.TempDir(), "text")
	if err := os.WriteFile(path, []byte("not a hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Import(path); err == nil {
		t.Fatal("text input unexpectedly succeeded")
	}
}

func TestReadConnection(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	raw := capturedClientHello(t)
	resultCh := make(chan Result, 1)
	errCh := make(chan error, 1)
	go func() {
		result, err := ReadConnection(context.Background(), server)
		resultCh <- result
		errCh <- err
	}()
	for _, part := range [][]byte{raw[:17], raw[17:]} {
		if _, err := client.Write(part); err != nil {
			t.Fatal(err)
		}
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if result := <-resultCh; result.JA4.Fingerprint == "" {
		t.Fatal("captured connection has no JA4")
	}
}

func TestReadConnectionCancellationAndMalformedInput(t *testing.T) {
	client, server := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := ReadConnection(ctx, server)
		errCh <- err
	}()
	cancel()
	if err := <-errCh; err == nil {
		t.Fatal("canceled capture unexpectedly succeeded")
	}
	client.Close()
	server.Close()

	client, server = net.Pipe()
	go func() {
		_, _ = client.Write([]byte("not TLS"))
		client.Close()
	}()
	if _, err := ReadConnection(context.Background(), server); err == nil {
		t.Fatal("malformed connection unexpectedly succeeded")
	}
	server.Close()
}

func TestImportPCAPAndPCAPNG(t *testing.T) {
	raw := capturedClientHello(t)
	split := len(raw) / 2
	if _, ok := analyzeSegments([]flowSegment{
		{sequence: 1000 + uint32(split), payload: raw[split:]},
		{sequence: 1000, payload: raw[:split]},
	}, "test flow"); !ok {
		t.Fatal("direct TCP segment reassembly failed")
	}
	for _, format := range []string{"pcap", "pcapng"} {
		t.Run(format, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "capture."+format)
			writePacketCapture(t, path, format, raw)
			result, err := ImportPCAP(path)
			if err != nil {
				t.Fatal(err)
			}
			if result.JA4.Fingerprint == "" || !strings.Contains(result.Flow, "192.0.2.10") {
				t.Fatalf("unexpected PCAP result: %+v", result)
			}
		})
	}
}

func TestImportPCAPFailures(t *testing.T) {
	if _, err := ImportPCAP(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing PCAP unexpectedly succeeded")
	}
	short := filepath.Join(t.TempDir(), "short.pcap")
	if err := os.WriteFile(short, []byte{1, 2, 3}, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ImportPCAP(short); err == nil {
		t.Fatal("short PCAP unexpectedly succeeded")
	}
	empty := filepath.Join(t.TempDir(), "empty.pcap")
	file, err := os.Create(empty)
	if err != nil {
		t.Fatal(err)
	}
	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	file.Close()
	if _, err := ImportPCAP(empty); err == nil || !strings.Contains(err.Error(), "complete TCP ClientHello") {
		t.Fatalf("empty PCAP error = %v", err)
	}
}

func writePacketCapture(t *testing.T, path, format string, raw []byte) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	var write func(gopacket.CaptureInfo, []byte) error
	var flush func() error
	if format == "pcapng" {
		writer, err := pcapgo.NewNgWriter(file, layers.LinkTypeEthernet)
		if err != nil {
			t.Fatal(err)
		}
		write = writer.WritePacket
		flush = writer.Flush
	} else {
		writer := pcapgo.NewWriter(file)
		if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
			t.Fatal(err)
		}
		write = writer.WritePacket
		flush = func() error { return nil }
	}

	split := len(raw) / 2
	parts := []struct {
		seq     uint32
		payload []byte
	}{
		{1000 + uint32(split), raw[split:]},
		{1000, raw[:split]},
		{1000, raw[:split]},
	}
	for _, part := range parts {
		packet := serializeTCPPacket(t, part.seq, part.payload)
		info := gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(packet), Length: len(packet)}
		if err := write(info, packet); err != nil {
			t.Fatal(err)
		}
	}
	if err := flush(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func serializeTCPPacket(t *testing.T, sequence uint32, payload []byte) []byte {
	t.Helper()
	ethernet := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 5},
		DstMAC:       net.HardwareAddr{6, 7, 8, 9, 10, 11},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipv4 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.ParseIP("192.0.2.10"),
		DstIP:    net.ParseIP("192.0.2.20"),
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{SrcPort: 50000, DstPort: 443, Seq: sequence, ACK: true}
	if err := tcp.SetNetworkLayerForChecksum(ipv4); err != nil {
		t.Fatal(err)
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ethernet, ipv4, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func capturedClientHello(t *testing.T) []byte {
	t.Helper()
	client, server := net.Pipe()
	errCh := make(chan error, 1)
	go func() {
		conn := utls.UClient(client, &utls.Config{ServerName: "example.test", InsecureSkipVerify: true}, utls.HelloChrome_133)
		errCh <- conn.Handshake()
	}()
	header := make([]byte, 5)
	if _, err := io.ReadFull(server, header); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, int(binary.BigEndian.Uint16(header[3:5])))
	if _, err := io.ReadFull(server, payload); err != nil {
		t.Fatal(err)
	}
	server.Close()
	<-errCh
	return append(header, payload...)
}

func splitEvery(value string, width int) []string {
	var parts []string
	for len(value) > 0 {
		end := min(width, len(value))
		parts = append(parts, value[:end])
		value = value[end:]
	}
	return parts
}
