package fsconfig

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/federiconbaez/nginx-h2-hardening-audit/internal/ports"
	"github.com/federiconbaez/nginx-h2-hardening-audit/internal/ports/porttest"
)

func TestFSContract(t *testing.T) {
	porttest.ConfigSourceContract(t, func(t *testing.T, files map[string]string) ports.ConfigSource {
		dir := t.TempDir()
		for p, c := range files {
			full := filepath.Join(dir, filepath.FromSlash(p))
			if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		s, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Close() })
		return s
	})
}

func TestSymlinkEscapeBlocked(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.conf"), []byte("x;"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Symlink(filepath.Join(outside, "secret.conf"), filepath.Join(dir, "link.conf")); err != nil {
		t.Skip("symlinks unsupported:", err)
	}
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if _, err := s.ReadFile("link.conf"); err == nil {
		t.Fatal("expected symlink escape to be rejected")
	}
}

func TestOpenMissingDir(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("expected error")
	}
}
