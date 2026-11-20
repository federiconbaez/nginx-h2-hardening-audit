// Package porttest contiene la suite de contrato que todo ConfigSource debe pasar.
package porttest

import (
	"errors"
	"io/fs"
	"reflect"
	"testing"

	"github.com/federiconbaez/nginx-h2-hardening-audit/internal/ports"
)

// Factory crea un ConfigSource con los archivos dados (ruta relativa -> contenido).
type Factory func(t *testing.T, files map[string]string) ports.ConfigSource

// ConfigSourceContract verifica el comportamiento exigido por el puerto.
func ConfigSourceContract(t *testing.T, newSource Factory) {
	files := map[string]string{
		"nginx.conf":         "events {}\n",
		"conf.d/a.conf":      "server {}\n",
		"conf.d/b.conf":      "server {}\n",
		"conf.d/skip.txt":    "x",
		"sites/default.conf": "server {}\n",
	}
	t.Run("ReadFile existing", func(t *testing.T) {
		src := newSource(t, files)
		b, err := src.ReadFile("nginx.conf")
		if err != nil || string(b) != "events {}\n" {
			t.Fatalf("got %q, %v", b, err)
		}
	})
	t.Run("ReadFile missing is ErrNotExist", func(t *testing.T) {
		src := newSource(t, files)
		_, err := src.ReadFile("nope.conf")
		if !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("want ErrNotExist, got %v", err)
		}
	})
	t.Run("ReadFile rejects escaping paths", func(t *testing.T) {
		src := newSource(t, files)
		for _, p := range []string{"../etc/passwd", "/etc/passwd", "conf.d/../../x"} {
			if _, err := src.ReadFile(p); err == nil {
				t.Fatalf("%s: expected error", p)
			}
		}
	})
	t.Run("Glob sorted matches", func(t *testing.T) {
		src := newSource(t, files)
		got, err := src.Glob("conf.d/*.conf")
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"conf.d/a.conf", "conf.d/b.conf"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v want %v", got, want)
		}
	})
	t.Run("Glob no match is empty, not error", func(t *testing.T) {
		src := newSource(t, files)
		got, err := src.Glob("none/*.conf")
		if err != nil || len(got) != 0 {
			t.Fatalf("got %v, %v", got, err)
		}
	})
	t.Run("Glob bad pattern errors", func(t *testing.T) {
		src := newSource(t, files)
		if _, err := src.Glob("conf.d/[.conf"); err == nil {
			t.Fatal("expected error")
		}
	})
}
