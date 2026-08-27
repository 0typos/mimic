package proxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/msmythe/mimic/internal/config"
)

type udpRelay struct {
	conn       *net.UDPConn
	definition config.Listener
	logger     *slog.Logger
	mu         sync.Mutex
	sessions   map[string]*udpSession
}

type udpSession struct {
	client   *net.UDPAddr
	outbound *net.UDPConn
	lastUsed time.Time
}

func newUDPRelay(definition config.Listener, logger *slog.Logger) (*udpRelay, error) {
	address, _, err := config.ParseEndpoint(definition.UDPListen, true)
	if err != nil {
		return nil, err
	}
	udpAddress, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", udpAddress)
	if err != nil {
		return nil, err
	}
	logger.Info("SOCKS5 UDP relay started", "name", definition.Name, "address", definition.UDPListen)
	return &udpRelay{conn: conn, definition: definition, logger: logger, sessions: map[string]*udpSession{}}, nil
}

func (r *udpRelay) Serve(ctx context.Context) error {
	go r.reap(ctx)
	buffer := make([]byte, 64*1024)
	for {
		n, client, err := r.conn.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if !allowed(client, r.definition.AllowCIDRs) {
			r.logger.Warn("UDP packet rejected by allowlist", "remote", client)
			continue
		}
		target, payload, err := parseSOCKSUDP(buffer[:n])
		if err != nil {
			r.logger.Debug("invalid SOCKS UDP packet", "remote", client, "error", err)
			continue
		}
		session, err := r.session(client)
		if err != nil {
			continue
		}
		resolved, err := net.ResolveUDPAddr("udp", target)
		if err != nil {
			continue
		}
		if _, err := session.outbound.WriteToUDP(payload, resolved); err != nil {
			r.logger.Debug("UDP relay send failed", "target", target, "error", err)
		}
	}
}

func (r *udpRelay) session(client *net.UDPAddr) (*udpSession, error) {
	key := client.String()
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing := r.sessions[key]; existing != nil {
		existing.lastUsed = time.Now()
		return existing, nil
	}
	outbound, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	session := &udpSession{client: client, outbound: outbound, lastUsed: time.Now()}
	r.sessions[key] = session
	go r.readResponses(key, session)
	return session, nil
}

func (r *udpRelay) readResponses(key string, session *udpSession) {
	buffer := make([]byte, 64*1024)
	for {
		n, source, err := session.outbound.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		r.mu.Lock()
		session.lastUsed = time.Now()
		r.mu.Unlock()
		packet, err := makeSOCKSUDP(source, buffer[:n])
		if err == nil {
			_, _ = r.conn.WriteToUDP(packet, session.client)
		}
	}
}

func (r *udpRelay) reap(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-2 * time.Minute)
			r.mu.Lock()
			for key, session := range r.sessions {
				if session.lastUsed.Before(cutoff) {
					session.outbound.Close()
					delete(r.sessions, key)
				}
			}
			r.mu.Unlock()
		}
	}
}

func (r *udpRelay) Close() {
	_ = r.conn.Close()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, session := range r.sessions {
		_ = session.outbound.Close()
	}
	clear(r.sessions)
}

func parseSOCKSUDP(packet []byte) (string, []byte, error) {
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 {
		return "", nil, errors.New("invalid SOCKS UDP reserved bytes")
	}
	if packet[2] != 0 {
		return "", nil, errors.New("fragmented SOCKS UDP packets are unsupported")
	}
	reader := bytes.NewReader(packet[3:])
	target, err := readSOCKSAddress(reader)
	if err != nil {
		return "", nil, err
	}
	payload := make([]byte, reader.Len())
	_, _ = reader.Read(payload)
	return target, payload, nil
}

func makeSOCKSUDP(source *net.UDPAddr, payload []byte) ([]byte, error) {
	packet := []byte{0, 0, 0}
	if v4 := source.IP.To4(); v4 != nil {
		packet = append(packet, 1)
		packet = append(packet, v4...)
	} else if v6 := source.IP.To16(); v6 != nil {
		packet = append(packet, 4)
		packet = append(packet, v6...)
	} else {
		return nil, fmt.Errorf("invalid UDP source IP %s", source.IP)
	}
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(source.Port))
	packet = append(packet, port...)
	return append(packet, payload...), nil
}
