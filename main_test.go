package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLI_NoArgs(t *testing.T) {
	cli := &CLI{In: strings.NewReader(""), Out: &bytes.Buffer{}, Err: &bytes.Buffer{}}
	code := cli.Run([]string{"oauth-husk"})
	if code == 0 {
		t.Fatal("expected non-zero exit code for missing args")
	}
}

func TestCLI_ClientList_Empty(t *testing.T) {
	var out bytes.Buffer
	cli := &CLI{In: strings.NewReader(""), Out: &out, Err: &bytes.Buffer{}}

	dbPath := filepath.Join(t.TempDir(), "test.db")
	code := cli.Run([]string{"oauth-husk", "client", "list", "--db", dbPath})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(out.String(), "No clients registered") {
		t.Fatalf("unexpected output: %s", out.String())
	}
}

func TestCLI_RejectPublicCIDR(t *testing.T) {
	cli := &CLI{In: strings.NewReader(""), Out: &bytes.Buffer{}, Err: &bytes.Buffer{}}
	code := cli.Run([]string{"oauth-husk", "serve", "--allow-from", "0.0.0.0/0"})
	if code == 0 {
		t.Fatal("expected non-zero exit code for public allow-from without override")
	}
}
