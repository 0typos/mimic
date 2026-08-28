package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"time"

	"github.com/0typos/mimic/internal/config"
	"github.com/0typos/mimic/internal/control"
	"github.com/0typos/mimic/internal/engine"
	"github.com/0typos/mimic/internal/mitm"
	"github.com/0typos/mimic/internal/profilecapture"
	"github.com/0typos/mimic/internal/profiles"
	"github.com/0typos/mimic/internal/proxy"
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
	case "probe":
		return probe(args[1:], stdout, stderr)
	case "ctl":
		return ctl(args[1:], stdout)
	case "validate":
		return validate(args[1:], stdout)
	case "init-ca":
		return initCA(args[1:], stdout)
	case "profile":
		return profile(args[1:], stdout, stderr)
	case "profiles":
		return listProfiles(args[1:], stdout, stderr)
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

type profileFlags struct {
	name           string
	output         string
	force          bool
	browser        string
	browserVersion string
	platform       string
	lifecycle      string
	source         string
	capturedAt     string
	userAgent      string
	ja4h           string
	headerOrder    string
	headers        stringListFlag
	minVersion     string
	maxVersion     string
}

func (options *profileFlags) bind(flags *flag.FlagSet) {
	flags.StringVar(&options.name, "name", "", "profile name (letters, numbers, underscores, and hyphens)")
	flags.StringVar(&options.output, "output", "", "generated TOML snippet path (default NAME.toml)")
	flags.BoolVar(&options.force, "force", false, "replace existing generated files")
	flags.StringVar(&options.browser, "browser", "", "browser or client family")
	flags.StringVar(&options.browserVersion, "browser-version", "", "browser or client version")
	flags.StringVar(&options.platform, "platform", "", "capture platform")
	flags.StringVar(&options.lifecycle, "lifecycle", "custom", "profile lifecycle: current, legacy, or custom")
	flags.StringVar(&options.source, "source", "", "capture provenance")
	flags.StringVar(&options.capturedAt, "captured-at", "", "capture time in RFC3339 format")
	flags.StringVar(&options.userAgent, "user-agent", "", "matching HTTP User-Agent")
	flags.StringVar(&options.ja4h, "ja4h", "", "expected JA4H operator metadata")
	flags.StringVar(&options.headerOrder, "header-order", "", "comma-separated HTTP/1.1 header order")
	flags.Var(&options.headers, "header", "default HTTP header as 'Name: value' (repeatable)")
	flags.StringVar(&options.minVersion, "min-version", "", "optional minimum TLS version")
	flags.StringVar(&options.maxVersion, "max-version", "", "optional maximum TLS version")
}

func (options profileFlags) profileOptions() (profilecapture.ProfileOptions, error) {
	if options.name == "" {
		return profilecapture.ProfileOptions{}, errors.New("-name is required")
	}
	headers := make(map[string]string, len(options.headers))
	for _, raw := range options.headers {
		name, value, ok := strings.Cut(raw, ":")
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if !ok || name == "" {
			return profilecapture.ProfileOptions{}, fmt.Errorf("invalid -header %q; expected 'Name: value'", raw)
		}
		headers[name] = value
	}
	var order []string
	for _, name := range strings.Split(options.headerOrder, ",") {
		if trimmed := strings.TrimSpace(name); trimmed != "" {
			order = append(order, trimmed)
		}
	}
	result := profilecapture.ProfileOptions{
		Name:           options.name,
		Output:         options.output,
		Force:          options.force,
		Browser:        options.browser,
		BrowserVersion: options.browserVersion,
		Platform:       options.platform,
		Lifecycle:      options.lifecycle,
		Source:         options.source,
		CapturedAt:     options.capturedAt,
		UserAgent:      options.userAgent,
		JA4H:           options.ja4h,
		HeaderOrder:    order,
		Headers:        headers,
		MinVersion:     options.minVersion,
		MaxVersion:     options.maxVersion,
	}
	if err := profilecapture.ValidateOptions(result); err != nil {
		return profilecapture.ProfileOptions{}, err
	}
	return result, nil
}

type stringListFlag []string

func (values *stringListFlag) String() string { return strings.Join(*values, ", ") }

func (values *stringListFlag) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func profile(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("profile requires import or capture")
	}
	switch args[0] {
	case "import":
		return importProfile(args[1:], stdout, stderr)
	case "capture":
		return captureProfile(args[1:], stdout, stderr)
	default:
		return fmt.Errorf("unknown profile command %q", args[0])
	}
}

func importProfile(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("profile import", flag.ContinueOnError)
	flags.SetOutput(stderr)
	input := flags.String("input", "", "binary or hexadecimal ClientHello path")
	pcap := flags.String("pcap", "", "PCAP or PCAPNG path containing a TCP ClientHello")
	var options profileFlags
	options.bind(flags)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("profile import does not accept positional arguments")
	}
	if (*input == "") == (*pcap == "") {
		return errors.New("profile import requires exactly one of -input or -pcap")
	}
	profileOptions, err := options.profileOptions()
	if err != nil {
		return err
	}
	var result profilecapture.Result
	if *pcap != "" {
		result, err = profilecapture.ImportPCAP(*pcap)
	} else {
		result, err = profilecapture.Import(*input)
	}
	if err != nil {
		return err
	}
	return writeImportedProfile(stdout, result, profileOptions)
}

func captureProfile(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("profile capture", flag.ContinueOnError)
	flags.SetOutput(stderr)
	listen := flags.String("listen", "tcp://127.0.0.1:8443", "temporary TCP or Unix capture endpoint")
	timeout := flags.Duration("timeout", time.Minute, "maximum time to wait for a ClientHello")
	var options profileFlags
	options.bind(flags)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("profile capture does not accept positional arguments")
	}
	if *timeout <= 0 {
		return errors.New("profile capture timeout must be greater than zero")
	}
	profileOptions, err := options.profileOptions()
	if err != nil {
		return err
	}
	address, network, err := config.ParseEndpoint(*listen, false)
	if err != nil {
		return fmt.Errorf("capture listen endpoint: %w", err)
	}
	listener, err := net.Listen(network, address)
	if err != nil {
		return fmt.Errorf("start capture listener: %w", err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	fmt.Fprintf(stdout, "listening for one TLS ClientHello on %s://%s\n", network, listener.Addr())
	fmt.Fprintln(stdout, "open an HTTPS URL on that endpoint with the browser or client being captured")
	conn, err := listener.Accept()
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("wait for ClientHello: %w", ctx.Err())
		}
		return fmt.Errorf("accept capture connection: %w", err)
	}
	defer conn.Close()
	result, err := profilecapture.ReadConnection(ctx, conn)
	if err != nil {
		return err
	}
	if profileOptions.CapturedAt == "" {
		profileOptions.CapturedAt = time.Now().Format(time.RFC3339)
	}
	return writeImportedProfile(stdout, result, profileOptions)
}

func writeImportedProfile(stdout io.Writer, result profilecapture.Result, options profilecapture.ProfileOptions) error {
	written, err := profilecapture.WriteProfile(result, options)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "profile:      %s\n", written.ProfilePath)
	fmt.Fprintf(stdout, "ClientHello:  %s (%d bytes)\n", written.CapturePath, len(result.ClientHello))
	if result.Flow != "" {
		fmt.Fprintf(stdout, "capture flow: %s\n", result.Flow)
	}
	fmt.Fprintf(stdout, "JA4:          %s\n", result.JA4.Fingerprint)
	fmt.Fprintf(stdout, "JA4_r:        %s\n", result.JA4.Raw)
	fmt.Fprintln(stdout, "next: review the TOML snippet, add it to your config, validate, and probe a controlled target")
	return nil
}

func listProfiles(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("profiles", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "", "optional TOML configuration path for custom profiles")
	format := flags.String("format", "text", "output format: text or json")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("profiles does not accept positional arguments")
	}
	custom := map[string]config.Profile(nil)
	if *configPath != "" {
		cfg, err := config.Load(*configPath)
		if err != nil {
			return err
		}
		custom = cfg.Profiles
	}
	registry, err := profiles.New(custom)
	if err != nil {
		return err
	}
	infos := registry.Infos()
	switch *format {
	case "json":
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(infos)
	case "text":
		fmt.Fprintln(stdout, "NAME\tLIFECYCLE\tBROWSER\tPLATFORM\tJA4")
		for _, info := range infos {
			browser := strings.TrimSpace(info.Browser + " " + info.BrowserVersion)
			fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\t%s\n", info.Name, info.Lifecycle, browser, info.Platform, info.JA4)
		}
		return nil
	default:
		return fmt.Errorf("profiles format must be text or json, got %q", *format)
	}
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
  mimic probe [-config PATH] -target HTTPS_URL [-profile NAME] [-expect JA4] [-format text|json] [-raw]
  mimic ctl [-config PATH] info|status|profiles|use PROFILE|log-level LEVEL|reload|shutdown
  mimic validate [-config PATH]
  mimic init-ca [-cert PATH] [-key PATH]
  mimic profile import (-input CLIENTHELLO | -pcap CAPTURE) -name NAME [-output PATH]
  mimic profile capture -listen ENDPOINT -name NAME [-output PATH]
  mimic profiles [-config PATH] [-format text|json]
  mimic version`)
}
