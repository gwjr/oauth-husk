package main

import (
	"bufio"
	"context"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/gwjr/oauth-husk/internal/database"
	"github.com/gwjr/oauth-husk/internal/oauth"
	"github.com/gwjr/oauth-husk/internal/server"
)

func main() {
	cli := &CLI{
		In:  os.Stdin,
		Out: os.Stdout,
		Err: os.Stderr,
	}
	os.Exit(cli.Run(os.Args))
}

type CLI struct {
	In  io.Reader
	Out io.Writer
	Err io.Writer
}

func (c *CLI) Run(args []string) int {
	if len(args) < 2 {
		c.printUsage()
		return 1
	}

	switch args[1] {
	case "serve":
		if err := c.cmdServe(args[2:]); err != nil {
			fmt.Fprintln(c.Err, err)
			return 1
		}
	case "install":
		if err := c.cmdInstall(args[2:]); err != nil {
			fmt.Fprintln(c.Err, err)
			return 1
		}
	case "uninstall":
		if err := c.cmdUninstall(); err != nil {
			fmt.Fprintln(c.Err, err)
			return 1
		}
	case "client":
		if len(args) < 3 {
			fmt.Fprintln(c.Err, "Usage: oauth-husk client <add|list|revoke>")
			return 1
		}
		switch args[2] {
		case "add":
			if err := c.cmdClientAdd(args[3:]); err != nil {
				fmt.Fprintln(c.Err, err)
				return 1
			}
		case "list":
			if err := c.cmdClientList(args[3:]); err != nil {
				fmt.Fprintln(c.Err, err)
				return 1
			}
		case "revoke":
			if err := c.cmdClientRevoke(args[3:]); err != nil {
				fmt.Fprintln(c.Err, err)
				return 1
			}
		default:
			fmt.Fprintf(c.Err, "Unknown client subcommand: %s\n", args[2])
			return 1
		}
	default:
		fmt.Fprintf(c.Err, "Unknown command: %s\n", args[1])
		c.printUsage()
		return 1
	}
	return 0
}

func (c *CLI) printUsage() {
	fmt.Fprintln(c.Err, `Usage: oauth-husk <command>

Commands:
  serve             Start the OAuth server
  install           Install and start as a launchd service
  uninstall         Stop and remove the launchd service
  client add        Add a client (generates and prints secret once)
  client list       List clients
  client revoke     Revoke all tokens for a client`)
}

type serveConfig struct {
	host              string
	port              int
	dbPath            string
	allowFrom         []string
	cleanupFreq       time.Duration
	allowInsecureHTTP bool
	allowPublicCIDRs  bool
}

type installConfig struct {
	port              int
	dbPath            string
	allowFrom         []string
	allowInsecureHTTP bool
	allowPublicCIDRs  bool
}

func (c *CLI) parseServeConfig(args []string) (serveConfig, error) {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(c.Err)
	host := fs.String("host", "127.0.0.1", "listen host")
	port := fs.Int("port", 8200, "listen port")
	dbPath := fs.String("db", defaultDBPath(), "SQLite database path")
	allowFrom := fs.String("allow-from", "", "comma-separated CIDRs/IPs allowed to access (default loopback only)")
	allowInsecureHTTP := fs.Bool("allow-insecure-http", false, "allow HTTP (no TLS) for local testing")
	allowPublicCIDRs := fs.Bool("allow-public-cidrs", false, "allow 0.0.0.0/0 or ::/0 in --allow-from")
	if err := fs.Parse(args); err != nil {
		return serveConfig{}, err
	}

	cfg := serveConfig{
		host:              *host,
		port:              *port,
		dbPath:            expandTilde(*dbPath),
		allowFrom:         defaultAllowedCIDRs(),
		cleanupFreq:       time.Hour,
		allowInsecureHTTP: *allowInsecureHTTP,
		allowPublicCIDRs:  *allowPublicCIDRs,
	}
	if *allowFrom != "" {
		cfg.allowFrom = strings.Split(*allowFrom, ",")
	}
	if err := validateAllowFrom(cfg.allowFrom, cfg.allowPublicCIDRs); err != nil {
		return serveConfig{}, err
	}
	return cfg, nil
}

func (c *CLI) cmdServe(args []string) error {
	cfg, err := c.parseServeConfig(args)
	if err != nil {
		return err
	}

	addr := listenAddr(cfg.host, cfg.port)
	logger := slog.New(slog.NewJSONHandler(c.Out, &slog.HandlerOptions{Level: slog.LevelDebug}))

	db, err := database.Open(cfg.dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database at %s: %w", cfg.dbPath, err)
	}
	defer db.Close()

	svc, err := server.New(server.Config{
		ListenAddr:        addr,
		AllowedCIDRs:      cfg.allowFrom,
		AllowInsecureHTTP: cfg.allowInsecureHTTP,
		Logger:            logger,
	}, db)
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server.StartCleanup(ctx, db, svc.Limiter, logger, cfg.cleanupFreq)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		logger.Info("server starting", "addr", addr)
		if err := svc.HTTP.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server error", "error", err)
		}
	}()

	sig := <-sigCh
	logger.Info("shutting down", "signal", sig)
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := svc.HTTP.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown error", "error", err)
	}
	logger.Info("server stopped")
	return nil
}

func (c *CLI) parseInstallConfig(args []string) (installConfig, error) {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(c.Err)
	port := fs.Int("port", 8200, "listen port")
	dbPath := fs.String("db", defaultDBPath(), "SQLite database path")
	allowFrom := fs.String("allow-from", "", "comma-separated CIDRs/IPs allowed to access (default loopback only)")
	allowInsecureHTTP := fs.Bool("allow-insecure-http", false, "allow HTTP (no TLS) for local testing")
	allowPublicCIDRs := fs.Bool("allow-public-cidrs", false, "allow 0.0.0.0/0 or ::/0 in --allow-from")
	if err := fs.Parse(args); err != nil {
		return installConfig{}, err
	}

	cfg := installConfig{
		port:              *port,
		dbPath:            expandTilde(*dbPath),
		allowFrom:         defaultAllowedCIDRs(),
		allowInsecureHTTP: *allowInsecureHTTP,
		allowPublicCIDRs:  *allowPublicCIDRs,
	}
	if *allowFrom != "" {
		cfg.allowFrom = strings.Split(*allowFrom, ",")
	}
	if err := validateAllowFrom(cfg.allowFrom, cfg.allowPublicCIDRs); err != nil {
		return installConfig{}, err
	}
	return cfg, nil
}

func (c *CLI) cmdClientAdd(args []string) error {
	if err := c.promptInstall(); err != nil {
		return err
	}

	fs := flag.NewFlagSet("client add", flag.ContinueOnError)
	fs.SetOutput(c.Err)
	dbPath := fs.String("db", defaultDBPath(), "SQLite database path")
	redirectURI := fs.String("redirect-uri", "", "redirect URI (locked on first auth if omitted)")
	description := fs.String("description", "", "description")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() < 1 {
		return fmt.Errorf("usage: oauth-husk client add <client-id> [--redirect-uri URI] [--description TEXT]")
	}
	clientID := fs.Arg(0)

	db, err := database.Open(expandTilde(*dbPath))
	if err != nil {
		return fmt.Errorf("error opening database: %w", err)
	}
	defer db.Close()

	secret, err := oauth.GenerateSecret()
	if err != nil {
		return fmt.Errorf("error generating secret: %w", err)
	}

	hash, err := oauth.HashSecret(secret)
	if err != nil {
		return fmt.Errorf("error hashing secret: %w", err)
	}

	if err := db.CreateClient(clientID, hash, *redirectURI, *description); err != nil {
		return fmt.Errorf("error creating client: %w", err)
	}

	fmt.Fprintf(c.Out, "Client created: %s\n", clientID)
	fmt.Fprintf(c.Out, "Secret:         %s\n", secret)
	fmt.Fprintln(c.Out)
	fmt.Fprintln(c.Out, "Save this secret now — it cannot be recovered.")
	return nil
}

func (c *CLI) cmdClientList(args []string) error {
	if err := c.promptInstall(); err != nil {
		return err
	}

	fs := flag.NewFlagSet("client list", flag.ContinueOnError)
	fs.SetOutput(c.Err)
	dbPath := fs.String("db", defaultDBPath(), "SQLite database path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	db, err := database.Open(expandTilde(*dbPath))
	if err != nil {
		return fmt.Errorf("error opening database: %w", err)
	}
	defer db.Close()

	clients, err := db.ListClients()
	if err != nil {
		return fmt.Errorf("error listing clients: %w", err)
	}

	if len(clients) == 0 {
		fmt.Fprintln(c.Out, "No clients registered")
		return nil
	}

	tw := tabwriter.NewWriter(c.Out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "CLIENT ID\tREDIRECT URI\tCREATED\tDESCRIPTION")
	for _, c := range clients {
		uri := c.RedirectURI
		if uri == "" {
			uri = "(locked on first auth)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", c.ClientID, uri, c.CreatedAt.Format(time.RFC3339), c.Description)
	}
	tw.Flush()
	return nil
}

func (c *CLI) cmdClientRevoke(args []string) error {
	if err := c.promptInstall(); err != nil {
		return err
	}

	fs := flag.NewFlagSet("client revoke", flag.ContinueOnError)
	fs.SetOutput(c.Err)
	dbPath := fs.String("db", defaultDBPath(), "SQLite database path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() < 1 {
		return fmt.Errorf("usage: oauth-husk client revoke <client-id>")
	}
	clientID := fs.Arg(0)

	db, err := database.Open(expandTilde(*dbPath))
	if err != nil {
		return fmt.Errorf("error opening database: %w", err)
	}
	defer db.Close()

	n, err := db.RevokeClientTokens(clientID)
	if err != nil {
		return fmt.Errorf("error revoking tokens: %w", err)
	}

	fmt.Fprintf(c.Out, "Revoked %d token(s) for client '%s'\n", n, clientID)
	return nil
}

// isInstalled checks whether the launchd plist exists.
func isInstalled() bool {
	_, err := os.Stat(plistPath())
	return err == nil
}

// promptInstall checks if the service is installed and, if not, asks the user
// whether to install it now. Returns true if the user declined (caller should exit).
func (c *CLI) promptInstall() error {
	if isInstalled() {
		return nil
	}
	fmt.Fprintln(c.Err, "The oauth-husk service is not installed as a launchd agent.")
	fmt.Fprint(c.Err, "Install and start it now? [y/N] ")
	reader := bufio.NewReader(c.In)
	answer, err := reader.ReadString('\n')
	if err != nil {
		// EOF or pipe — don't auto-install
		fmt.Fprintln(c.Err, "\nSkipping install. Run 'oauth-husk install' when ready.")
		return nil
	}
	answer = strings.TrimSpace(strings.ToLower(answer))
	if answer == "y" || answer == "yes" {
		return c.cmdInstall(nil)
	} else {
		fmt.Fprintln(c.Err, "Skipping install. Run 'oauth-husk install' when ready.")
	}
	return nil
}

const launchdLabel = "uk.gwjr.oauth-husk"

func plistPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", launchdLabel+".plist")
}

// xmlEscape returns an XML-safe string for use inside plist <string> elements.
func xmlEscape(s string) string {
	var b strings.Builder
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

func (c *CLI) cmdInstall(args []string) error {
	cfg, err := c.parseInstallConfig(args)
	if err != nil {
		return err
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("error finding executable path: %w", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return fmt.Errorf("error resolving executable path: %w", err)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("error finding home directory: %w", err)
	}
	logDir := filepath.Join(home, "Library", "Logs", "oauth-husk")
	if err := os.MkdirAll(logDir, 0700); err != nil {
		return fmt.Errorf("error creating log directory: %w", err)
	}

	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>serve</string>
		<string>--port</string>
		<string>%d</string>
		<string>--db</string>
		<string>%s</string>
		<string>--allow-from</string>
		<string>%s</string>
		<string>--allow-insecure-http</string>
		<string>%t</string>
		<string>--allow-public-cidrs</string>
		<string>%t</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>%s</string>
	<key>StandardErrorPath</key>
	<string>%s</string>
</dict>
</plist>
`, launchdLabel, xmlEscape(exe), cfg.port, xmlEscape(cfg.dbPath), xmlEscape(strings.Join(cfg.allowFrom, ",")),
		cfg.allowInsecureHTTP, cfg.allowPublicCIDRs,
		xmlEscape(filepath.Join(logDir, "oauth-husk.out")),
		xmlEscape(filepath.Join(logDir, "oauth-husk.err")))

	dest := plistPath()

	// Unload if already installed
	exec.Command("launchctl", "unload", dest).Run()

	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return fmt.Errorf("error creating LaunchAgents directory: %w", err)
	}

	if err := os.WriteFile(dest, []byte(plist), 0644); err != nil {
		return fmt.Errorf("error writing plist: %w", err)
	}

	if out, err := exec.Command("launchctl", "load", dest).CombinedOutput(); err != nil {
		return fmt.Errorf("error loading plist: %v\n%s", err, out)
	}

	fmt.Fprintf(c.Out, "Installed and started %s\n", launchdLabel)
	fmt.Fprintf(c.Out, "  Plist:  %s\n", dest)
	fmt.Fprintf(c.Out, "  Binary: %s\n", exe)
	fmt.Fprintf(c.Out, "  Port:   %d\n", cfg.port)
	return nil
}

func (c *CLI) cmdUninstall() error {
	dest := plistPath()

	if _, err := os.Stat(dest); os.IsNotExist(err) {
		fmt.Fprintln(c.Out, "Not installed")
		return nil
	}

	if out, err := exec.Command("launchctl", "unload", dest).CombinedOutput(); err != nil {
		fmt.Fprintf(c.Err, "Error unloading plist: %v\n%s\n", err, out)
	}

	if err := os.Remove(dest); err != nil {
		return fmt.Errorf("error removing plist: %w", err)
	}

	fmt.Fprintf(c.Out, "Uninstalled %s\n", launchdLabel)
	return nil
}

func listenAddr(host string, port int) string {
	return fmt.Sprintf("%s:%d", host, port)
}

func defaultDBPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".oauth-husk.db"
	}
	return filepath.Join(home, ".config", "oauth-husk", "oauth.db")
}

func expandTilde(path string) string {
	if !strings.HasPrefix(path, "~") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	if path == "~" {
		return home
	}
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(home, path[2:])
	}
	return path
}

func defaultAllowedCIDRs() []string {
	return []string{"127.0.0.0/8", "::1/128"}
}

func validateAllowFrom(cidrs []string, allowPublic bool) error {
	if allowPublic {
		return nil
	}
	for _, raw := range cidrs {
		clean := strings.TrimSpace(raw)
		if clean == "0.0.0.0/0" || clean == "::/0" {
			return fmt.Errorf("refusing to allow public CIDR %q; if you really want this, pass --allow-public-cidrs", clean)
		}
	}
	return nil
}
