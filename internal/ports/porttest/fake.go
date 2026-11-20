package porttest

import (
	"io/fs"
	"path"
	"sort"
)

// MemSource es un ConfigSource en memoria para tests.
type MemSource map[string]string

// ReadFile implementa ports.ConfigSource.
func (m MemSource) ReadFile(p string) ([]byte, error) {
	if !fs.ValidPath(p) {
		return nil, &fs.PathError{Op: "read", Path: p, Err: fs.ErrInvalid}
	}
	s, ok := m[p]
	if !ok {
		return nil, &fs.PathError{Op: "read", Path: p, Err: fs.ErrNotExist}
	}
	return []byte(s), nil
}

// Glob implementa ports.ConfigSource.
func (m MemSource) Glob(pattern string) ([]string, error) {
	if _, err := path.Match(pattern, ""); err != nil {
		return nil, err
	}
	var out []string
	for k := range m {
		if ok, _ := path.Match(pattern, k); ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, nil
}
