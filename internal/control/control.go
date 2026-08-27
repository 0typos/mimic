package control

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/msmythe/mimic/internal/config"
	"github.com/msmythe/mimic/internal/engine"
)

const ProtocolVersion = 1

var capabilities = []string{
	"config.reload",
	"daemon.shutdown",
	"log.set",
	"ping",
	"profile.use",
	"profiles.list",
	"protocol.info",
	"status",
}

type Request struct {
	ID     int64           `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	ID     int64  `json:"id"`
	Result any    `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
}

type Server struct {
	state    *engine.State
	logger   *slog.Logger
	reload   func() error
	shutdown context.CancelFunc
	mu       sync.Mutex
	listener net.Listener
}

func NewServer(state *engine.State, logger *slog.Logger, reload func() error, shutdown context.CancelFunc) *Server {
	return &Server{state: state, logger: logger, reload: reload, shutdown: shutdown}
}

func (s *Server) Serve(ctx context.Context, endpoint string) error {
	listener, err := listen(endpoint)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.listener = listener
	s.mu.Unlock()
	s.logger.Info("control endpoint started", "address", endpoint)
	go func() {
		<-ctx.Done()
		listener.Close()
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	encoder := json.NewEncoder(conn)
	for scanner.Scan() {
		var request Request
		if err := json.Unmarshal(scanner.Bytes(), &request); err != nil {
			_ = encoder.Encode(Response{Error: "invalid request: " + err.Error()})
			continue
		}
		response := s.dispatch(request)
		if err := encoder.Encode(response); err != nil {
			return
		}
	}
}

func (s *Server) dispatch(request Request) Response {
	response := Response{ID: request.ID}
	switch request.Method {
	case "ping":
		response.Result = map[string]bool{"ok": true}
	case "protocol.info":
		response.Result = map[string]any{"version": ProtocolVersion, "capabilities": capabilities}
	case "status", "profiles.list":
		response.Result = s.state.Status()
	case "profile.use":
		var params struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(request.Params, &params); err != nil || params.Name == "" {
			response.Error = "profile.use requires {\"name\":\"...\"}"
		} else if err := s.state.Select(params.Name); err != nil {
			response.Error = err.Error()
		} else {
			s.logger.Info("active profile changed", "profile", params.Name)
			response.Result = s.state.Status()
		}
	case "log.set":
		var params struct {
			Level string `json:"level"`
		}
		if err := json.Unmarshal(request.Params, &params); err != nil {
			response.Error = err.Error()
		} else if level, err := ParseLevel(params.Level); err != nil {
			response.Error = err.Error()
		} else {
			s.state.SetLogLevel(level)
			s.logger.Info("log level changed", "level", params.Level)
			response.Result = map[string]string{"level": strings.ToLower(params.Level)}
		}
	case "config.reload":
		if err := s.reload(); err != nil {
			response.Error = err.Error()
		} else {
			response.Result = s.state.Status()
		}
	case "daemon.shutdown":
		response.Result = map[string]bool{"stopping": true}
		go func() {
			time.Sleep(50 * time.Millisecond)
			s.shutdown()
		}()
	default:
		response.Error = fmt.Sprintf("unknown method %q", request.Method)
	}
	return response
}

func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		_ = s.listener.Close()
	}
}

func Call(ctx context.Context, endpoint, method string, params any) (Response, error) {
	address, network, err := config.ParseEndpoint(endpoint, false)
	if err != nil {
		return Response{}, err
	}
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return Response{}, fmt.Errorf("connect to daemon: %w", err)
	}
	defer conn.Close()
	rawParams, err := json.Marshal(params)
	if err != nil {
		return Response{}, err
	}
	request := Request{ID: time.Now().UnixNano(), Method: method, Params: rawParams}
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return Response{}, err
	}
	var response Response
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		return Response{}, err
	}
	return response, nil
}

func ParseLevel(raw string) (slog.Level, error) {
	switch strings.ToLower(raw) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unknown log level %q (use debug, info, warn, or error)", raw)
	}
}

func listen(endpoint string) (net.Listener, error) {
	address, network, err := config.ParseEndpoint(endpoint, false)
	if err != nil {
		return nil, err
	}
	if network == "tcp" {
		host, _, splitErr := net.SplitHostPort(address)
		if splitErr != nil {
			return nil, splitErr
		}
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return nil, errors.New("control TCP endpoint must be loopback; use a Unix socket for local control")
		}
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
