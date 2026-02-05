package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultDBPath(t *testing.T) {
	p := DefaultDBPath()
	if p == "" {
		t.Error("expected non-empty default DB path")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home dir")
	}
	expected := filepath.Join(home, ".config", "oauth-husk", "oauth.db")
	if p != expected {
		t.Errorf("expected %s, got %s", expected, p)
	}
}

func TestListenAddr(t *testing.T) {
	if got := ListenAddr("127.0.0.1", 8200); got != "127.0.0.1:8200" {
		t.Errorf("expected 127.0.0.1:8200, got %s", got)
	}
	if got := ListenAddr("0.0.0.0", 9000); got != "0.0.0.0:9000" {
		t.Errorf("expected 0.0.0.0:9000, got %s", got)
	}
}

func TestExpandTilde(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home dir")
	}

	got := ExpandTilde("~/test.db")
	expected := filepath.Join(home, "test.db")
	if got != expected {
		t.Errorf("expected %s, got %s", expected, got)
	}

	// Non-tilde path unchanged
	got = ExpandTilde("/absolute/path.db")
	if got != "/absolute/path.db" {
		t.Errorf("expected unchanged path, got %s", got)
	}
}
