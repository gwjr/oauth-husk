package main

import (
	"bufio"
	"context"
	"encoding/xml"
	"flag"
	"fmt"
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

	"github.com/gwjr/oauth-husk/internal/config"
	"github.com/gwjr/oauth-husk/internal/database"
	"github.com/gwjr/oauth-husk/internal/oauth"
	"github.com/gwjr/oauth-husk/internal/server"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "serve":
		cmdServe(os.Args[2:])
	case "install":
		cmdInstall(os.Args[2:])
	case "uninstall":
		cmdUninstall()
	case "client":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: oauth-husk client <add|list|revoke>")
			os.Exit(1)
		}
		switch os.Args[2] {
		case "add":
			cmdClientAdd(os.Args[3:])
		case "list":
			cmdClientList(os.Args[3:])
		case "revoke":
			cmdClientRevoke(os.Args[3:])
		default:
			fmt.Fprintf(os.Stderr, "Unknown client subcommand: %s\n", os.Args[2])
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `Usage: oauth-husk <command>

Commands:
  serve             Start the OAuth server
  install           Install and start as a launchd service
  uninstall         Stop and remove the launchd service
  client add        Add a client (generates and prints secret once)
  client list       List clients
  client revoke     Revoke all tokens for a client`)
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	host := fs.String("host", "127.0.0.1", "listen host")
	port := fs.Int("port", 8200, "listen port")
	dbPath := fs.String("db", config.DefaultDBPath(), "SQLite database path")
	allowFrom := fs.String("allow-from", "", "comma-separated CIDRs/IPs allowed to access (default loopback only)")
	fs.Parse(args)

	*dbPath = config.ExpandTilde(*dbPath)
	addr := config.ListenAddr(*host, *port)

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	db, err := database.Open(*dbPath)
	if err != nil {
		logger.Error("failed to open database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	var allowedCIDRs []string
	if *allowFrom != "" {
		allowedCIDRs = strings.Split(*allowFrom, ",")
	}
	srv, limiter, err := server.New(addr, db, logger, allowedCIDRs)
	if err != nil {
		logger.Error("failed to create server", "error", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server.StartCleanup(ctx, db, limiter, logger)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		logger.Info("server starting", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	sig := <-sigCh
	logger.Info("shutting down", "signal", sig)
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown error", "error", err)
	}
	logger.Info("server stopped")
}

func cmdClientAdd(args []string) {
	promptInstall()

	fs := flag.NewFlagSet("client add", flag.ExitOnError)
	dbPath := fs.String("db", config.DefaultDBPath(), "SQLite database path")
	redirectURI := fs.String("redirect-uri", "", "redirect URI (locked on first auth if omitted)")
	description := fs.String("description", "", "description")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Usage: oauth-husk client add <client-id> [--redirect-uri URI] [--description TEXT]")
		os.Exit(1)
	}
	clientID := fs.Arg(0)

	db, err := database.Open(config.ExpandTilde(*dbPath))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	secret, err := oauth.GenerateSecret()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating secret: %v\n", err)
		os.Exit(1)
	}

	hash, err := oauth.HashSecret(secret)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error hashing secret: %v\n", err)
		os.Exit(1)
	}

	if err := db.CreateClient(clientID, hash, *redirectURI, *description); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating client: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Client created: %s\n", clientID)
	fmt.Printf("Secret:         %s\n", secret)
	fmt.Println()
	fmt.Println("Save this secret now — it cannot be recovered.")
}

func cmdClientList(args []string) {
	promptInstall()

	fs := flag.NewFlagSet("client list", flag.ExitOnError)
	dbPath := fs.String("db", config.DefaultDBPath(), "SQLite database path")
	fs.Parse(args)

	db, err := database.Open(config.ExpandTilde(*dbPath))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	clients, err := db.ListClients()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing clients: %v\n", err)
		os.Exit(1)
	}

	if len(clients) == 0 {
		fmt.Println("No clients registered")
		return
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "CLIENT ID\tREDIRECT URI\tCREATED\tDESCRIPTION")
	for _, c := range clients {
		uri := c.RedirectURI
		if uri == "" {
			uri = "(locked on first auth)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", c.ClientID, uri, c.CreatedAt.Format(time.RFC3339), c.Description)
	}
	tw.Flush()
}

func cmdClientRevoke(args []string) {
	promptInstall()

	fs := flag.NewFlagSet("client revoke", flag.ExitOnError)
	dbPath := fs.String("db", config.DefaultDBPath(), "SQLite database path")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Usage: oauth-husk client revoke <client-id>")
		os.Exit(1)
	}
	clientID := fs.Arg(0)

	db, err := database.Open(config.ExpandTilde(*dbPath))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	n, err := db.RevokeClientTokens(clientID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error revoking tokens: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Revoked %d token(s) for client '%s'\n", n, clientID)
}

// isInstalled checks whether the launchd plist exists.
func isInstalled() bool {
	_, err := os.Stat(plistPath())
	return err == nil
}

// promptInstall checks if the service is installed and, if not, asks the user
// whether to install it now. Returns true if the user declined (caller should exit).
func promptInstall() {
	if isInstalled() {
		return
	}
	fmt.Fprintln(os.Stderr, "The oauth-husk service is not installed as a launchd agent.")
	fmt.Fprint(os.Stderr, "Install and start it now? [y/N] ")
	reader := bufio.NewReader(os.Stdin)
	answer, err := reader.ReadString('\n')
	if err != nil {
		// EOF or pipe — don't auto-install
		fmt.Fprintln(os.Stderr, "\nSkipping install. Run 'oauth-husk install' when ready.")
		return
	}
	answer = strings.TrimSpace(strings.ToLower(answer))
	if answer == "y" || answer == "yes" {
		cmdInstall(nil)
	} else {
		fmt.Fprintln(os.Stderr, "Skipping install. Run 'oauth-husk install' when ready.")
	}
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

func cmdInstall(args []string) {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	port := fs.Int("port", 8200, "listen port")
	dbPath := fs.String("db", config.DefaultDBPath(), "SQLite database path")
	allowFrom := fs.String("allow-from", "", "comma-separated CIDRs/IPs allowed to access (default loopback only)")
	fs.Parse(args)

	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding executable path: %v\n", err)
		os.Exit(1)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving executable path: %v\n", err)
		os.Exit(1)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding home directory: %v\n", err)
		os.Exit(1)
	}
	logDir := filepath.Join(home, "Library", "Logs", "oauth-husk")
	if err := os.MkdirAll(logDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating log directory: %v\n", err)
		os.Exit(1)
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
`, launchdLabel, xmlEscape(exe), *port, xmlEscape(*dbPath), xmlEscape(*allowFrom),
		xmlEscape(filepath.Join(logDir, "oauth-husk.out")),
		xmlEscape(filepath.Join(logDir, "oauth-husk.err")))

	dest := plistPath()

	// Unload if already installed
	exec.Command("launchctl", "unload", dest).Run()

	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating LaunchAgents directory: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(dest, []byte(plist), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing plist: %v\n", err)
		os.Exit(1)
	}

	if out, err := exec.Command("launchctl", "load", dest).CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "Error loading plist: %v\n%s\n", err, out)
		os.Exit(1)
	}

	fmt.Printf("Installed and started %s\n", launchdLabel)
	fmt.Printf("  Plist:  %s\n", dest)
	fmt.Printf("  Binary: %s\n", exe)
	fmt.Printf("  Port:   %d\n", *port)
}

func cmdUninstall() {
	dest := plistPath()

	if _, err := os.Stat(dest); os.IsNotExist(err) {
		fmt.Println("Not installed")
		return
	}

	if out, err := exec.Command("launchctl", "unload", dest).CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "Error unloading plist: %v\n%s\n", err, out)
	}

	if err := os.Remove(dest); err != nil {
		fmt.Fprintf(os.Stderr, "Error removing plist: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Uninstalled %s\n", launchdLabel)
}
