package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/msmythe/mimic/internal/config"
	"github.com/msmythe/mimic/internal/engine"
	"github.com/msmythe/mimic/internal/mitm"
)

type Server struct {
	state     *engine.State
	dialer    *engine.TLSDialer
	authority *mitm.Authority
	logger    *slog.Logger
	mu        sync.Mutex
	listeners []net.Listener
	udp       []*udpRelay
}

func New(state *engine.State, authority *mitm.Authority, logger *slog.Logger) *Server {
	return &Server{state: state, dialer: engine.NewTLSDialer(state, logger), authority: authority, logger: logger}
}

func (s *Server) Start(ctx context.Context) error {
	snapshot := s.state.Snapshot()
	if len(snapshot.Config.Listeners) == 0 {
		return errors.New("no proxy listeners configured")
	}
	errCh := make(chan error, len(snapshot.Config.Listeners)*2)
	for _, definition := range snapshot.Config.Listeners {
		definition := definition
		listener, err := listen(definition.Listen)
		if err != nil {
			s.Close()
			return fmt.Errorf("start listener %q: %w", definition.Name, err)
		}
		s.mu.Lock()
		s.listeners = append(s.listeners, listener)
		s.mu.Unlock()
		s.logger.Info("proxy listener started", "name", definition.Name, "protocol", definition.Protocol,
			"mode", definition.Mode, "address", definition.Listen)
		go s.acceptLoop(ctx, definition, listener, errCh)
		if definition.Protocol == "socks5" && definition.UDPListen != "" {
			relay, err := newUDPRelay(definition, s.logger)
			if err != nil {
				s.Close()
				return fmt.Errorf("start UDP relay %q: %w", definition.Name, err)
			}
			s.mu.Lock()
			s.udp = append(s.udp, relay)
			s.mu.Unlock()
			go func() { errCh <- relay.Serve(ctx) }()
		}
	}
	select {
	case <-ctx.Done():
		s.Close()
		return nil
	case err := <-errCh:
		s.Close()
		if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	}
}

func (s *Server) acceptLoop(ctx context.Context, definition config.Listener, listener net.Listener, errCh chan<- error) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			errCh <- err
			return
		}
		if !allowed(conn.RemoteAddr(), definition.AllowCIDRs) {
			s.logger.Warn("proxy connection rejected by allowlist", "listener", definition.Name, "remote", conn.RemoteAddr())
			conn.Close()
			continue
		}
		s.state.ConnectionOpened()
		go func() {
			defer conn.Close()
			var err error
			switch definition.Protocol {
			case "http":
				err = s.handleHTTP(ctx, conn, definition)
			case "socks5":
				err = s.handleSOCKS(ctx, conn, definition)
			case "caido":
				err = s.handleCaido(ctx, conn)
			}
			if err != nil && !errors.Is(err, context.Canceled) {
				s.logger.Debug("proxy connection ended", "listener", definition.Name, "remote", conn.RemoteAddr(), "error", err)
			}
		}()
	}
}

func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, listener := range s.listeners {
		_ = listener.Close()
	}
	for _, relay := range s.udp {
		relay.Close()
	}
}

func listen(endpoint string) (net.Listener, error) {
	address, network, err := config.ParseEndpoint(endpoint, false)
	if err != nil {
		return nil, err
	}
	if network == "unix" {
		if err := os.MkdirAll(filepath.Dir(address), 0o700); err != nil {
			return nil, err
		}
		if info, statErr := os.Lstat(address); statErr == nil {
			if info.Mode()&os.ModeSocket == 0 {
				return nil, fmt.Errorf("refusing to replace non-socket path %s", address)
			}
			if err := os.Remove(address); err != nil {
				return nil, err
			}
		}
	}
	listener, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	if network == "unix" {
		if err := os.Chmod(address, 0o600); err != nil {
			listener.Close()
			return nil, err
		}
	}
	return listener, nil
}
