// Package profilecapture imports and normalizes TLS ClientHello captures for
// use as Mimic profiles.
package profilecapture

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/msmythe/mimic/internal/fingerprint"
)

const (
	maxCaptureBytes = 64 << 20
	maxFlowBytes    = 4 << 20
	maxFlows        = 4096
)

// Result is a normalized bare ClientHello and its calculated JA4 evidence.
type Result struct {
	ClientHello []byte
	JA4         fingerprint.JA4
	Flow        string
}

// Import reads a binary or hexadecimal ClientHello, normalizes it to a bare
// handshake, and calculates JA4.
func Import(path string) (Result, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Result{}, fmt.Errorf("read ClientHello capture: %w", err)
	}
	decoded, err := decodeHex(raw)
	if err != nil {
		return Result{}, err
	}
	return analyze(decoded, "")
}

// ImportPCAP extracts the first complete TCP ClientHello from a PCAP or
// PCAPNG capture. Captures should be narrowed to one client connection.
func ImportPCAP(path string) (Result, error) {
	file, err := os.Open(path)
	if err != nil {
		return Result{}, fmt.Errorf("open packet capture: %w", err)
	}
	defer file.Close()

	var magic [4]byte
	if _, err := io.ReadFull(file, magic[:]); err != nil {
		return Result{}, fmt.Errorf("read packet capture header: %w", err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return Result{}, fmt.Errorf("rewind packet capture: %w", err)
	}

	var reader packetReader
	if bytes.Equal(magic[:], []byte{0x0a, 0x0d, 0x0d, 0x0a}) {
		reader, err = pcapgo.NewNgReader(file, pcapgo.NgReaderOptions{
			ErrorOnMismatchingLinkType: true,
			SkipUnknownVersion:         true,
		})
	} else {
		reader, err = pcapgo.NewReader(file)
	}
	if err != nil {
		return Result{}, fmt.Errorf("parse packet capture: %w", err)
	}
	return importPackets(reader)
}

// ReadConnection captures one ClientHello from an accepted connection.
func ReadConnection(ctx context.Context, conn net.Conn) (Result, error) {
	closed := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetReadDeadline(now())
		case <-closed:
		}
	}()
	defer close(closed)

	buffer := make([]byte, 0, 4096)
	chunk := make([]byte, 32*1024)
	var lastErr error
	for len(buffer) <= maxFlowBytes {
		n, err := conn.Read(chunk)
		if n > 0 {
			buffer = append(buffer, chunk[:n]...)
			if result, analyzeErr := analyze(buffer, conn.RemoteAddr().String()); analyzeErr == nil {
				return result, nil
			} else {
				lastErr = analyzeErr
			}
		}
		if err != nil {
			if ctx.Err() != nil {
				return Result{}, ctx.Err()
			}
			if errors.Is(err, io.EOF) && lastErr != nil {
				return Result{}, lastErr
			}
			return Result{}, fmt.Errorf("read capture connection: %w", err)
		}
	}
	return Result{}, fmt.Errorf("ClientHello exceeds %d bytes", maxFlowBytes)
}

// now is replaceable in tests that need to unblock a connection deadline.
var now = func() time.Time { return time.Now() }

type packetReader interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	LinkType() layers.LinkType
}

type flowSegment struct {
	sequence uint32
	payload  []byte
}

func importPackets(reader packetReader) (Result, error) {
	flows := make(map[string][]flowSegment)
	flowSizes := make(map[string]int)
	total := 0
	for {
		data, _, err := reader.ReadPacketData()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Result{}, fmt.Errorf("read packet: %w", err)
		}
		packet := gopacket.NewPacket(data, reader.LinkType(), gopacket.DecodeOptions{
			Lazy:   true,
			NoCopy: true,
		})
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		networkLayer := packet.NetworkLayer()
		if tcpLayer == nil || networkLayer == nil {
			continue
		}
		tcp := tcpLayer.(*layers.TCP)
		if len(tcp.Payload) == 0 {
			continue
		}
		flow := fmt.Sprintf(
			"%s:%d -> %s:%d",
			networkLayer.NetworkFlow().Src(),
			tcp.SrcPort,
			networkLayer.NetworkFlow().Dst(),
			tcp.DstPort,
		)
		if _, ok := flows[flow]; !ok && len(flows) >= maxFlows {
			return Result{}, fmt.Errorf("packet capture contains more than %d TCP flows", maxFlows)
		}
		payload := append([]byte(nil), tcp.Payload...)
		flows[flow] = append(flows[flow], flowSegment{sequence: tcp.Seq, payload: payload})
		flowSizes[flow] += len(payload)
		total += len(payload)
		if flowSizes[flow] > maxFlowBytes {
			return Result{}, fmt.Errorf("TCP flow %s exceeds %d captured bytes", flow, maxFlowBytes)
		}
		if total > maxCaptureBytes {
			return Result{}, fmt.Errorf("packet capture exceeds %d TCP payload bytes", maxCaptureBytes)
		}
		if result, ok := analyzeSegments(flows[flow], flow); ok {
			return result, nil
		}
	}
	return Result{}, errors.New("packet capture does not contain a complete TCP ClientHello")
}

func analyzeSegments(segments []flowSegment, flow string) (Result, bool) {
	sorted := append([]flowSegment(nil), segments...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].sequence < sorted[j].sequence })
	var spans [][]byte
	var end uint64
	for _, segment := range sorted {
		start := uint64(segment.sequence)
		segmentEnd := start + uint64(len(segment.payload))
		if len(spans) == 0 || start > end {
			spans = append(spans, append([]byte(nil), segment.payload...))
			end = segmentEnd
			continue
		}
		if segmentEnd <= end {
			continue
		}
		overlap := int(end - start)
		spans[len(spans)-1] = append(spans[len(spans)-1], segment.payload[overlap:]...)
		end = segmentEnd
	}
	for _, span := range spans {
		for offset := 0; offset+9 <= len(span); offset++ {
			if span[offset] != 22 || span[offset+1] != 3 {
				continue
			}
			result, err := analyze(span[offset:], flow)
			if err == nil {
				return result, true
			}
		}
	}
	return Result{}, false
}

func analyze(raw []byte, flow string) (Result, error) {
	handshake, err := fingerprint.ExtractClientHello(raw)
	if err != nil {
		return Result{}, err
	}
	ja4, err := fingerprint.FromClientHello(handshake)
	if err != nil {
		return Result{}, err
	}
	return Result{ClientHello: handshake, JA4: ja4, Flow: flow}, nil
}

func decodeHex(raw []byte) ([]byte, error) {
	trimmed := strings.TrimSpace(string(raw))
	compact := strings.Join(strings.Fields(trimmed), "")
	if compact == "" {
		return raw, nil
	}
	for _, char := range compact {
		if !strings.ContainsRune("0123456789abcdefABCDEF", char) {
			return raw, nil
		}
	}
	decoded, err := hex.DecodeString(compact)
	if err != nil {
		return nil, fmt.Errorf("decode hexadecimal ClientHello: %w", err)
	}
	return decoded, nil
}
