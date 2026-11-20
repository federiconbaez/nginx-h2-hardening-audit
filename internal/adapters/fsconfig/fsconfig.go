// Package fsconfig implementa ports.ConfigSource sobre el sistema de archivos,
// confinado a una raíz con os.Root (no sigue symlinks fuera de ella). Solo lectura.
package fsconfig

import (
	"io/fs"
	"os"
	"sort"
)

// Source lee archivos bajo una raíz.
type Source struct {
	fsys fs.FS
	root *os.Root
}

// Open abre la raíz. Llamar Close al terminar.
func Open(dir string) (*Source, error) {
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &Source{fsys: r.FS(), root: r}, nil
}

// Close libera la raíz.
func (s *Source) Close() error { return s.root.Close() }

// ReadFile implementa ports.ConfigSource.
func (s *Source) ReadFile(p string) ([]byte, error) {
	if !fs.ValidPath(p) {
		return nil, &fs.PathError{Op: "read", Path: p, Err: fs.ErrInvalid}
	}
	return fs.ReadFile(s.fsys, p)
}

// Glob implementa ports.ConfigSource.
func (s *Source) Glob(pattern string) ([]string, error) {
	m, err := fs.Glob(s.fsys, pattern)
	if err != nil {
		return nil, err
	}
	sort.Strings(m)
	return m, nil
}
