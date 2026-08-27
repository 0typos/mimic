package engine

import (
	"fmt"
	"log/slog"
	"net"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/msmythe/mimic/internal/config"
	"github.com/msmythe/mimic/internal/profiles"
)

type Snapshot struct {
	Config          config.Config
	Profiles        *profiles.Registry
	SelectedProfile string
	StartedAt       time.Time
}

type State struct {
	mu           sync.RWMutex
	snapshot     Snapshot
	level        *slog.LevelVar
	connections  atomic.Uint64
	requests     atomic.Uint64
	tlsFallbacks atomic.Uint64
}

type Status struct {
	StartedAt     time.Time `json:"started_at"`
	UptimeSeconds int64     `json:"uptime_seconds"`
	Profile       string    `json:"profile"`
	Profiles      []string  `json:"profiles"`
	Connections   uint64    `json:"connections"`
	Requests      uint64    `json:"requests"`
	TLSFallbacks  uint64    `json:"tls_fallbacks"`
	ConfigPath    string    `json:"config_path"`
}

func New(cfg config.Config, registry *profiles.Registry, level *slog.LevelVar) (*State, error) {
	if _, ok := registry.Get(cfg.Runtime.DefaultProfile); !ok {
		return nil, fmt.Errorf("runtime.default_profile %q does not exist", cfg.Runtime.DefaultProfile)
	}
	for i, route := range cfg.Routes {
		if _, ok := registry.Get(route.Profile); !ok {
			return nil, fmt.Errorf("routes[%d].profile %q does not exist", i, route.Profile)
		}
	}
	return &State{
		snapshot: Snapshot{
			Config: cfg, Profiles: registry,
			SelectedProfile: cfg.Runtime.DefaultProfile,
			StartedAt:       time.Now(),
		},
		level: level,
	}, nil
}

func (s *State) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snapshot
}

func (s *State) Select(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.snapshot.Profiles.Get(name); !ok {
		return fmt.Errorf("unknown profile %q", name)
	}
	s.snapshot.SelectedProfile = name
	return nil
}

func (s *State) Reload(cfg config.Config, registry *profiles.Registry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	selected := s.snapshot.SelectedProfile
	if _, ok := registry.Get(selected); !ok {
		selected = cfg.Runtime.DefaultProfile
	}
	if _, ok := registry.Get(selected); !ok {
		return fmt.Errorf("runtime.default_profile %q does not exist", selected)
	}
	for i, route := range cfg.Routes {
		if _, ok := registry.Get(route.Profile); !ok {
			return fmt.Errorf("routes[%d].profile %q does not exist", i, route.Profile)
		}
	}
	started := s.snapshot.StartedAt
	s.snapshot = Snapshot{Config: cfg, Profiles: registry, SelectedProfile: selected, StartedAt: started}
	return nil
}

func (s *State) ProfileForHost(host string) (profiles.Profile, config.Route, bool) {
	return s.ProfileForHostAs(host, "")
}

func (s *State) ProfileForHostAs(host, override string) (profiles.Profile, config.Route, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	host = stripPort(host)
	name := override
	if name == "" {
		name = s.snapshot.SelectedProfile
	}
	var matched config.Route
	if override == "" {
		for _, route := range s.snapshot.Config.Routes {
			if hostMatch(route.Host, host) {
				name = route.Profile
				matched = route
				break
			}
		}
	}
	p, ok := s.snapshot.Profiles.Get(name)
	return p, matched, ok
}

func (s *State) Status() Status {
	s.mu.RLock()
	snapshot := s.snapshot
	s.mu.RUnlock()
	return Status{
		StartedAt:     snapshot.StartedAt,
		UptimeSeconds: int64(time.Since(snapshot.StartedAt).Seconds()),
		Profile:       snapshot.SelectedProfile,
		Profiles:      snapshot.Profiles.Names(),
		Connections:   s.connections.Load(),
		Requests:      s.requests.Load(),
		TLSFallbacks:  s.tlsFallbacks.Load(),
		ConfigPath:    snapshot.Config.Path,
	}
}

func (s *State) ConnectionOpened() { s.connections.Add(1) }
func (s *State) RequestHandled()   { s.requests.Add(1) }
func (s *State) FallbackUsed()     { s.tlsFallbacks.Add(1) }

func (s *State) SetLogLevel(level slog.Level) { s.level.Set(level) }

func stripPort(host string) string {
	if parsed := net.ParseIP(strings.Trim(host, "[]")); parsed != nil {
		return parsed.String()
	}
	if hostname, _, err := net.SplitHostPort(host); err == nil {
		return strings.Trim(hostname, "[]")
	}
	return strings.Trim(host, "[]")
}

func hostMatch(pattern, host string) bool {
	if pattern == "" {
		return false
	}
	matched, err := path.Match(strings.ToLower(pattern), strings.ToLower(host))
	return err == nil && matched
}
