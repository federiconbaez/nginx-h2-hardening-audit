package textversion

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSources(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "v.txt")
	if err := os.WriteFile(f, []byte("nginx version: nginx/1.30.6\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := New(Spec{InstalledFile: f, RunningString: "nginx/1.30.5"})
	if txt, ok, err := s.Installed(); err != nil || !ok || !strings.Contains(txt, "1.30.6") {
		t.Fatalf("installed: %q %v %v", txt, ok, err)
	}
	if txt, ok, err := s.Running(); err != nil || !ok || txt != "nginx/1.30.5" {
		t.Fatalf("running: %q %v %v", txt, ok, err)
	}
	empty := New(Spec{})
	if _, ok, err := empty.Running(); ok || err != nil {
		t.Fatal("expected not provided")
	}
	stdin := New(Spec{RunningFile: "-", Stdin: strings.NewReader("Server: nginx/1.31.9")})
	if txt, ok, _ := stdin.Running(); !ok || txt != "Server: nginx/1.31.9" {
		t.Fatalf("stdin: %q", txt)
	}
	if _, _, err := New(Spec{InstalledFile: filepath.Join(dir, "missing")}).Installed(); err == nil {
		t.Fatal("expected error")
	}
}
