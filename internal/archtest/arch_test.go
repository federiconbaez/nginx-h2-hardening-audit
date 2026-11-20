// Package archtest verifica la regla de dependencias hexagonal (invariante I1).
package archtest

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const module = "github.com/federiconbaez/nginx-h2-hardening-audit"

// imports devuelve los imports de los archivos no-test de un directorio.
func imports(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, n), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range f.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			out[p] = n
		}
	}
	return out
}

func TestDomainIsPure(t *testing.T) {
	forbidden := []string{"os", "os/exec", "io/fs", "io/ioutil", "net", "net/http", "path/filepath", "syscall", "unsafe"}
	for p, file := range imports(t, "../domain") {
		for _, f := range forbidden {
			if p == f || strings.HasPrefix(p, f+"/") {
				t.Errorf("domain/%s imports forbidden %q", file, p)
			}
		}
		if strings.HasPrefix(p, module+"/") {
			t.Errorf("domain/%s imports internal package %q", file, p)
		}
	}
}

func TestLayering(t *testing.T) {
	rules := map[string][]string{
		"../ports": {module + "/internal/app", module + "/internal/adapters"},
		"../app":   {module + "/internal/adapters", "os", "net", "net/http", "os/exec"},
	}
	for dir, bad := range rules {
		for p, file := range imports(t, dir) {
			for _, b := range bad {
				if p == b || strings.HasPrefix(p, b+"/") {
					t.Errorf("%s/%s imports forbidden %q", dir, file, p)
				}
			}
		}
	}
}

// Ningún paquete del módulo importa red (no-objetivo "sin red").
func TestNoNetworkAnywhere(t *testing.T) {
	err := filepath.WalkDir("../..", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "testdata") {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(path, ".go") {
			dir := filepath.Dir(path)
			for p, file := range imports(t, dir) {
				if p == "net" || strings.HasPrefix(p, "net/") || p == "os/exec" {
					t.Errorf("%s/%s imports %q", dir, file, p)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
