// Package app orquesta la auditoría: carga la configuración por el puerto
// ConfigSource (resolviendo includes), obtiene versiones por VersionSource y
// delega la evaluación al dominio.
package app

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"

	"github.com/federiconbaez/nginx-h2-hardening-audit/internal/domain"
	"github.com/federiconbaez/nginx-h2-hardening-audit/internal/ports"
)

// MaxIncludeDepth limita la anidación de includes (invariante I5).
const MaxIncludeDepth = 32

// Options configura la auditoría.
type Options struct {
	Config      ports.ConfigSource // nil = sin configuración
	MainFile    string             // relativo a la raíz; por defecto nginx.conf
	StripPrefix string             // prefijo absoluto que mapea a la raíz; por defecto /etc/nginx
	Versions    ports.VersionSource
	WCThreshold int
}

// Result es el reporte más avisos no fatales (includes ignorados).
type Result struct {
	Report   domain.Report `json:"report"`
	Warnings []string      `json:"warnings"`
}

// Run ejecuta la auditoría.
func Run(o Options) (Result, error) {
	in := domain.Input{WCThreshold: o.WCThreshold}
	var res Result
	provided := false
	if o.Versions != nil {
		txt, ok, err := o.Versions.Installed()
		if err != nil {
			return res, fmt.Errorf("reading installed version: %w", err)
		}
		if ok {
			v, err := domain.ParseVersion(txt)
			if err != nil {
				return res, err
			}
			in.Installed, in.InstalledRaw, provided = &v, txt, true
		}
		txt, ok, err = o.Versions.Running()
		if err != nil {
			return res, fmt.Errorf("reading running version: %w", err)
		}
		if ok {
			v, hidden, err := domain.ParseRunning(txt)
			if err != nil {
				return res, err
			}
			provided = true
			if hidden {
				in.RunningHidden = true
			} else {
				in.Running = &v
			}
		}
	}
	if o.Config != nil {
		l := &loader{src: o.Config, strip: o.StripPrefix, stack: map[string]bool{}}
		if l.strip == "" {
			l.strip = "/etc/nginx"
		}
		main := o.MainFile
		if main == "" {
			main = "nginx.conf"
		}
		ds, err := l.load(main, 0)
		if err != nil {
			return res, err
		}
		in.Config, in.ConfigProvided, provided = ds, true, true
		res.Warnings = l.warnings
	}
	if !provided {
		return res, domain.ErrNoInput
	}
	res.Report = domain.Evaluate(in)
	if res.Warnings == nil {
		res.Warnings = []string{}
	}
	return res, nil
}

type loader struct {
	src      ports.ConfigSource
	strip    string
	stack    map[string]bool
	warnings []string
}

func (l *loader) load(file string, depth int) ([]domain.Directive, error) {
	b, err := l.src.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", file, err)
	}
	ds, err := domain.ParseConfig(file, b)
	if err != nil {
		return nil, err
	}
	l.stack[file] = true
	defer delete(l.stack, file)
	return l.expand(ds, depth)
}

func (l *loader) expand(ds []domain.Directive, depth int) ([]domain.Directive, error) {
	out := make([]domain.Directive, 0, len(ds))
	for _, d := range ds {
		if d.Name == "include" && d.Block == nil {
			inc, err := l.include(d, depth)
			if err != nil {
				return nil, err
			}
			out = append(out, inc...)
			continue
		}
		if d.Block != nil {
			nb, err := l.expand(d.Block, depth)
			if err != nil {
				return nil, err
			}
			d.Block = nb
		}
		out = append(out, d)
	}
	return out, nil
}

func (l *loader) include(d domain.Directive, depth int) ([]domain.Directive, error) {
	if len(d.Args) != 1 {
		return nil, &domain.IncludeError{File: d.File, Line: d.Line, Reason: "expects exactly one argument"}
	}
	pat := d.Args[0]
	rel, ok := l.rebase(pat)
	if !ok {
		l.warnings = append(l.warnings, fmt.Sprintf("%s: include %q outside config root, skipped", d.Location(), pat))
		return nil, nil
	}
	if depth+1 > MaxIncludeDepth {
		return nil, &domain.IncludeError{File: d.File, Line: d.Line, Pattern: pat, Reason: "include depth exceeded"}
	}
	var files []string
	if strings.ContainsAny(rel, "*?[") {
		m, err := l.src.Glob(rel)
		if err != nil {
			return nil, &domain.IncludeError{File: d.File, Line: d.Line, Pattern: pat, Reason: err.Error()}
		}
		files = m
	} else {
		files = []string{rel}
	}
	var out []domain.Directive
	for _, f := range files {
		if l.stack[f] {
			return nil, &domain.IncludeError{File: d.File, Line: d.Line, Pattern: pat, Reason: "include cycle via " + f}
		}
		inc, err := l.load(f, depth+1)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil, &domain.IncludeError{File: d.File, Line: d.Line, Pattern: pat, Reason: "file not found"}
			}
			return nil, err
		}
		out = append(out, inc...)
	}
	return out, nil
}

// rebase convierte el patrón de include en una ruta relativa a la raíz.
func (l *loader) rebase(p string) (string, bool) {
	if strings.HasPrefix(p, "/") {
		pre := strings.TrimSuffix(l.strip, "/") + "/"
		if !strings.HasPrefix(p, pre) {
			return "", false
		}
		p = strings.TrimPrefix(p, pre)
	}
	c := path.Clean(p)
	if c == "." || c == ".." || strings.HasPrefix(c, "../") || strings.HasPrefix(c, "/") {
		return "", false
	}
	return c, true
}
