// Package domain contiene la lógica pura del auditor: versiones, rangos de
// vulnerabilidad, parser de configuración y evaluación de reglas. No hace I/O.
package domain

import (
	"errors"
	"fmt"
)

// ErrInvalidVersion se devuelve (envuelto en *VersionError) cuando no se puede
// interpretar una versión de nginx.
var ErrInvalidVersion = errors.New("invalid nginx version")

// ErrNoInput indica que no se proveyó ni versión ni configuración.
var ErrNoInput = errors.New("no input: provide a version and/or a config root")

// VersionError describe una versión no interpretable.
type VersionError struct{ Input string }

func (e *VersionError) Error() string {
	return fmt.Sprintf("invalid nginx version: %q", truncate(e.Input, 80))
}

// Unwrap permite errors.Is(err, ErrInvalidVersion).
func (e *VersionError) Unwrap() error { return ErrInvalidVersion }

// ParseError es un error de sintaxis en la configuración.
type ParseError struct {
	File string
	Line int
	Msg  string
}

func (e *ParseError) Error() string { return fmt.Sprintf("%s:%d: %s", e.File, e.Line, e.Msg) }

// IncludeError es un include inválido (ciclo, profundidad, fuera de la raíz).
type IncludeError struct {
	File    string
	Line    int
	Pattern string
	Reason  string
}

func (e *IncludeError) Error() string {
	return fmt.Sprintf("%s:%d: include %q: %s", e.File, e.Line, e.Pattern, e.Reason)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
