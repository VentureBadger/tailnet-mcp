package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/VentureBadger/tailnet-mcp/internal/mcp"
	"github.com/VentureBadger/tailnet-mcp/internal/tailscale"
	"github.com/VentureBadger/tailnet-mcp/internal/tools"
)

const instructions = `Tools for inspecting a Tailscale tailnet: devices, device health, and the access policy.
Use preview_access to answer "who can reach X" or "what can Y reach" questions rather than reading the policy by hand.
Before proposing a policy change, run validate_policy on the full proposed file and preview_access to show its effect.`

func main() {
	if err := run(os.Args[1:], os.Getenv, os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "tailnet-mcp:", err)
		os.Exit(1)
	}
}

func run(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("tailnet-mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	tailnet := fs.String("tailnet", envOr(getenv, "TAILSCALE_TAILNET", "-"), "tailnet ID; - means the credential's own tailnet")
	allowWrites := fs.Bool("allow-writes", envBool(getenv, "TAILNET_MCP_ALLOW_WRITES"), "expose tools that change devices")
	logLevel := fs.String("log-level", envOr(getenv, "TAILNET_MCP_LOG_LEVEL", "info"), "debug, info, warn, or error")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *showVersion {
		fmt.Fprintln(stdout, version())
		return nil
	}

	var level slog.Level
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		return fmt.Errorf("invalid -log-level %q", *logLevel)
	}
	logger := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: level}))

	creds, err := credentials(getenv)
	if err != nil {
		return err
	}
	client, err := tailscale.New(tailscale.Config{
		BaseURL:     getenv("TAILSCALE_BASE_URL"),
		Tailnet:     *tailnet,
		Credentials: creds,
		MaxRetries:  3,
		Logger:      logger,
	})
	if err != nil {
		return err
	}

	server, err := mcp.NewServer(
		mcp.Implementation{Name: "tailnet-mcp", Version: version()},
		instructions,
		tools.New(client, tools.Options{AllowWrites: *allowWrites}),
		logger,
	)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Info("serving on stdio", "tailnet", *tailnet, "writes", *allowWrites)
	start := time.Now()
	err = server.Serve(ctx, stdin, stdout)
	logger.Info("stopped", "uptime", time.Since(start).Round(time.Second).String())
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func credentials(getenv func(string) string) (tailscale.Credentials, error) {
	key := getenv("TAILSCALE_API_KEY")
	id, secret := getenv("TAILSCALE_OAUTH_CLIENT_ID"), getenv("TAILSCALE_OAUTH_CLIENT_SECRET")

	switch {
	case key != "" && (id != "" || secret != ""):
		return nil, errors.New("set either TAILSCALE_API_KEY or the TAILSCALE_OAUTH_CLIENT_* variables, not both")
	case key != "":
		return tailscale.APIKey(key), nil
	case id != "" || secret != "":
		base := strings.TrimRight(envOr(getenv, "TAILSCALE_BASE_URL", tailscale.DefaultBaseURL), "/")
		return tailscale.NewOAuth(tailscale.OAuthConfig{
			ClientID:     id,
			ClientSecret: secret,
			Scopes:       strings.Fields(getenv("TAILSCALE_OAUTH_SCOPES")),
			TokenURL:     base + "/api/v2/oauth/token",
		})
	default:
		return nil, errors.New("no credentials: set TAILSCALE_API_KEY, or TAILSCALE_OAUTH_CLIENT_ID and TAILSCALE_OAUTH_CLIENT_SECRET")
	}
}

func envOr(getenv func(string) string, key, fallback string) string {
	if v := getenv(key); v != "" {
		return v
	}
	return fallback
}

func envBool(getenv func(string) string, key string) bool {
	v, _ := strconv.ParseBool(getenv(key))
	return v
}

func version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" || info.Main.Version == "(devel)" {
		return "dev"
	}
	return info.Main.Version
}
