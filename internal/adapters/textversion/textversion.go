// Package textversion implementa ports.VersionSource a partir de strings o
// archivos provistos por el usuario (nunca ejecuta nginx ni usa la red).
package textversion

import (
	"io"
	"os"
	"strings"
)

const maxBytes = 1 << 20

// Spec describe de dónde salen los textos. "-" en un archivo significa stdin.
type Spec struct {
	InstalledFile, InstalledString string
	RunningFile, RunningString     string
	Stdin                          io.Reader
}

// Source implementa ports.VersionSource.
type Source struct{ spec Spec }

// New crea la fuente.
func New(s Spec) *Source {
	if s.Stdin == nil {
		s.Stdin = os.Stdin
	}
	return &Source{spec: s}
}

// Installed implementa ports.VersionSource.
func (s *Source) Installed() (string, bool, error) {
	return s.read(s.spec.InstalledFile, s.spec.InstalledString)
}

// Running implementa ports.VersionSource.
func (s *Source) Running() (string, bool, error) {
	return s.read(s.spec.RunningFile, s.spec.RunningString)
}

func (s *Source) read(file, str string) (string, bool, error) {
	if file == "" {
		if strings.TrimSpace(str) == "" {
			return "", false, nil
		}
		return str, true, nil
	}
	var r io.Reader
	if file == "-" {
		r = s.spec.Stdin
	} else {
		f, err := os.Open(file)
		if err != nil {
			return "", false, err
		}
		defer func() { _ = f.Close() }()
		r = f
	}
	b, err := io.ReadAll(io.LimitReader(r, maxBytes))
	if err != nil {
		return "", false, err
	}
	return string(b), true, nil
}
