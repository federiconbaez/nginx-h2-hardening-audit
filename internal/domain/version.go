package domain

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Version es una versión upstream de nginx (major.minor.patch).
type Version struct {
	Major, Minor, Patch int
	// Suffix guarda texto extra como "(Ubuntu)"; sugiere un paquete de distro.
	Suffix string
}

var (
	reVersionLine = regexp.MustCompile(`nginx/(\d+)\.(\d+)\.(\d+)(?:\s*\(([^)]{0,64})\))?`)
	reBare        = regexp.MustCompile(`^\s*v?(\d+)\.(\d+)\.(\d+)\s*$`)
)

// ParseVersion interpreta la salida de `nginx -V`/`nginx -v`, un header Server
// ("nginx/1.30.6") o un string "1.30.6".
func ParseVersion(s string) (Version, error) {
	if m := reVersionLine.FindStringSubmatch(s); m != nil {
		v, err := fromParts(s, m[1], m[2], m[3])
		if err != nil {
			return Version{}, err
		}
		v.Suffix = strings.TrimSpace(m[4])
		return v, nil
	}
	if m := reBare.FindStringSubmatch(s); m != nil {
		return fromParts(s, m[1], m[2], m[3])
	}
	return Version{}, &VersionError{Input: s}
}

func fromParts(in, a, b, c string) (Version, error) {
	var out [3]int
	for i, p := range []string{a, b, c} {
		if len(p) > 6 {
			return Version{}, &VersionError{Input: in}
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return Version{}, &VersionError{Input: in}
		}
		out[i] = n
	}
	return Version{Major: out[0], Minor: out[1], Patch: out[2]}, nil
}

// String devuelve "major.minor.patch".
func (v Version) String() string { return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch) }

// Compare devuelve -1, 0 o 1 (ignora Suffix).
func (v Version) Compare(o Version) int {
	for _, d := range [3]int{v.Major - o.Major, v.Minor - o.Minor, v.Patch - o.Patch} {
		if d < 0 {
			return -1
		}
		if d > 0 {
			return 1
		}
	}
	return 0
}

// SameBranch indica si comparten major.minor.
func (v Version) SameBranch(o Version) bool { return v.Major == o.Major && v.Minor == o.Minor }

// Branch devuelve "stable" (minor par) o "mainline" (minor impar), la
// convención de numeración de nginx.org.
func (v Version) Branch() string {
	if v.Minor%2 == 0 {
		return "stable"
	}
	return "mainline"
}

// HasHTTP2Module indica si la salida de `nginx -V` declara
// --with-http_v2_module. Devuelve (presente, sabemos) — sabemos=false si el
// texto no trae "configure arguments".
func HasHTTP2Module(nginxV string) (present, known bool) {
	if !strings.Contains(nginxV, "configure arguments:") {
		return false, false
	}
	return strings.Contains(nginxV, "--with-http_v2_module"), true
}

// ParseRunning interpreta la versión en ejecución (p. ej. un header
// "Server: nginx/1.30.6"). hidden=true si dice "nginx" sin número
// (server_tokens off).
func ParseRunning(s string) (ver Version, hidden bool, err error) {
	ver, err = ParseVersion(s)
	if err == nil {
		return ver, false, nil
	}
	t := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s), "Server:"))
	if strings.EqualFold(t, "nginx") {
		return Version{}, true, nil
	}
	return Version{}, false, err
}
