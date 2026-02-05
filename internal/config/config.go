package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func DefaultDBPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "oauth.db"
	}
	return filepath.Join(home, ".config", "oauth-husk", "oauth.db")
}

func ListenAddr(host string, port int) string {
	return fmt.Sprintf("%s:%d", host, port)
}

func ExpandTilde(path string) string {
	if !strings.HasPrefix(path, "~") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return filepath.Join(home, path[1:])
}
