package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"syscall"
	"time"

	"github.com/msmythe/mimic/internal/config"
	"github.com/msmythe/mimic/internal/control"
	"github.com/msmythe/mimic/internal/engine"
	"github.com/msmythe/mimic/internal/mitm"
	"github.com/msmythe/mimic/internal/profiles"
	"github.com/msmythe/mimic/internal/proxy"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "mimic:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		usage(stderr)
		return flag.ErrHelp
	}
	switch args[0] {
	case "daemon":
		return daemon(args[1:], stderr)
	case "ctl":
		return ctl(args[1:], stdout)
	case "validate":
		return validate(args[1:], stdout)
	case "init-ca":
		return initCA(args[1:], stdout)
	case "version", "--version", "-version":
		fmt.Fprintln(stdout, version)
		return nil
	case "help", "--help", "-h":
		usage(stdout)
		return nil
	default:
		usage(stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func daemon(args []string, stderr io.Writer) error {
	flags := flag.NewFlagSet("daemon", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", defaultConfigPath(), "TOML configuration path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	registry, err := profiles.New(cfg.Profiles)
	if err != nil {
		return err
	}
	level, err := control.ParseLevel(cfg.Logging.Level)
	if err != nil {
		return err
	}
	levelVar := new(slog.LevelVar)
	levelVar.Set(level)
	var handler slog.Handler
	options := &slog.HandlerOptions{Level: levelVar}
	if cfg.Logging.Format == "json" {
		handler = slog.NewJSONHandler(stderr, options)
	} else if cfg.Logging.Format == "text" {
		handler = slog.NewTextHandler(stderr, options)
	} else {
		return fmt.Errorf("logging.format must be text or json")
	}
	logger := slog.New(handler)
	state, err := engine.New(cfg, registry, levelVar)
	if err != nil {
		return err
	}
	var authority *mitm.Authority
	if cfg.MITM.Enabled {
		ttl, _ := time.ParseDuration(cfg.MITM.LeafTTL)
		authority, err = mitm.Load(cfg.MITM.CACert, cfg.MITM.CAKey, ttl)
		if err != nil {
			return err
		}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	reload := func() error {
		updated, err := config.Load(*configPath)
		if err != nil {
			return err
		}
		current := state.Snapshot().Config
		if !reflect.DeepEqual(current.Listeners, updated.Listeners) || current.Control != updated.Control || current.MITM != updated.MITM {
			return errors.New("listener, control, and MITM endpoint changes require a daemon restart")
		}
		updatedRegistry, err := profiles.New(updated.Profiles)
		if err != nil {
			return err
		}
		if err := state.Reload(updated, updatedRegistry); err != nil {
			return err
		}
		newLevel, err := control.ParseLevel(updated.Logging.Level)
		if err == nil {
			levelVar.Set(newLevel)
		}
		logger.Info("configuration reloaded", "path", updated.Path)
		return nil
	}
	controlServer := control.NewServer(state, logger, reload, cancel)
	proxyServer := proxy.New(state, authority, logger)
	errCh := make(chan error, 2)
	go func() { errCh <- controlServer.Serve(ctx, cfg.Control.Listen) }()
	go func() { errCh <- proxyServer.Start(ctx) }()
	logger.Info("mimic daemon started", "version", version, "config", cfg.Path, "profile", cfg.Runtime.DefaultProfile)
	select {
	case <-ctx.Done():
		proxyServer.Close()
		controlServer.Close()
		return nil
	case err := <-errCh:
		cancel()
		proxyServer.Close()
		controlServer.Close()
		return err
	}
}

func ctl(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("ctl", flag.ContinueOnError)
	configPath := flags.String("config", defaultConfigPath(), "TOML configuration path")
	socket := flags.String("socket", "", "override control endpoint")
	if err := flags.Parse(args); err != nil {
		return err
	}
	rest := flags.Args()
	if len(rest) == 0 {
		return errors.New("ctl requires info, status, profiles, use, log-level, reload, or shutdown")
	}
	endpoint := *socket
	if endpoint == "" {
		cfg, err := config.Load(*configPath)
		if err != nil {
			return err
		}
		endpoint = cfg.Control.Listen
	}
	method := ""
	params := map[string]any{}
	switch rest[0] {
	case "info":
		method = "protocol.info"
	case "status":
		method = "status"
	case "profiles":
		method = "profiles.list"
	case "use":
		if len(rest) != 2 {
			return errors.New("usage: mimic ctl use PROFILE")
		}
		method, params = "profile.use", map[string]any{"name": rest[1]}
	case "log-level":
		if len(rest) != 2 {
			return errors.New("usage: mimic ctl log-level LEVEL")
		}
		method, params = "log.set", map[string]any{"level": rest[1]}
	case "reload":
		method = "config.reload"
	case "shutdown":
		method = "daemon.shutdown"
	default:
		return fmt.Errorf("unknown ctl command %q", rest[0])
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	response, err := control.Call(ctx, endpoint, method, params)
	if err != nil {
		return err
	}
	if response.Error != "" {
		return errors.New(response.Error)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(response.Result)
}

func validate(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("validate", flag.ContinueOnError)
	configPath := flags.String("config", defaultConfigPath(), "TOML configuration path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	registry, err := profiles.New(cfg.Profiles)
	if err != nil {
		return err
	}
	if _, err := engine.New(cfg, registry, new(slog.LevelVar)); err != nil {
		return err
	}
	if cfg.MITM.Enabled {
		ttl, _ := time.ParseDuration(cfg.MITM.LeafTTL)
		if _, err := mitm.Load(cfg.MITM.CACert, cfg.MITM.CAKey, ttl); err != nil {
			return err
		}
	}
	fmt.Fprintf(stdout, "valid: %s (%d profiles, %d listeners)\n", cfg.Path, len(registry.Names()), len(cfg.Listeners))
	return nil
}

func initCA(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("init-ca", flag.ContinueOnError)
	cert := flags.String("cert", "mimic-ca.pem", "CA certificate path")
	key := flags.String("key", "mimic-ca-key.pem", "CA private key path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := mitm.Generate(*cert, *key); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "created CA certificate %s and private key %s\n", *cert, *key)
	return nil
}

func defaultConfigPath() string {
	if value := os.Getenv("MIMIC_CONFIG"); value != "" {
		return value
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "mimic.toml"
	}
	return filepath.Join(base, "mimic", "config.toml")
}

func usage(writer io.Writer) {
	fmt.Fprintln(writer, `mimic - fingerprint-aware HTTP/TLS compatibility proxy

Usage:
  mimic daemon [-config PATH]
  mimic ctl [-config PATH] info|status|profiles|use PROFILE|log-level LEVEL|reload|shutdown
  mimic validate [-config PATH]
  mimic init-ca [-cert PATH] [-key PATH]
  mimic version`)
}
