package domain

// Advisory describe un CVE de nginx con su rango vulnerable y ramas corregidas,
// tal como lo publica https://nginx.org/en/security_advisories.html.
type Advisory struct {
	ID          string
	Title       string
	NginxRating string  // severidad según nginx.org
	CVSSv4      float64 // puntaje del CNA (F5) en NVD
	CWE         string
	F5Article   string
	From, To    Version   // rango vulnerable inclusivo
	Fixed       []Version // "Not vulnerable: X+" por rama
	NeedsProxy  bool      // requiere proxy a backend (y worker_connections bajo)
	Sources     []string
}

func v(a, b, c int) Version { return Version{Major: a, Minor: b, Patch: c} }

// Advisories devuelve los CVE cubiertos (copia; el llamador puede mutarla).
func Advisories() []Advisory {
	return []Advisory{
		{
			ID:          "CVE-2026-123007",
			Title:       "Memory corruption in HTTP/2 flow control",
			NginxRating: "major",
			CVSSv4:      9.2,
			CWE:         "CWE-191",
			F5Article:   "https://my.f5.com/manage/s/article/K000163926",
			From:        v(1, 9, 5),
			To:          v(1, 31, 8),
			Fixed:       []Version{v(1, 31, 9), v(1, 30, 7)},
			Sources: []string{
				"https://nginx.org/en/security_advisories.html",
				"https://nvd.nist.gov/vuln/detail/CVE-2026-123007",
			},
		},
		{
			ID:          "CVE-2026-123633",
			Title:       "Use-after-free in HTTP/2",
			NginxRating: "medium",
			CVSSv4:      9.2,
			CWE:         "CWE-416",
			F5Article:   "https://my.f5.com/manage/s/article/K000163928",
			From:        v(1, 19, 7),
			To:          v(1, 31, 8),
			Fixed:       []Version{v(1, 31, 9), v(1, 30, 7)},
			NeedsProxy:  true,
			Sources: []string{
				"https://nginx.org/en/security_advisories.html",
				"https://nvd.nist.gov/vuln/detail/CVE-2026-123633",
			},
		},
	}
}

// Affects implementa el invariante I2.
func (a Advisory) Affects(x Version) bool {
	if x.Compare(a.From) < 0 || x.Compare(a.To) > 0 {
		return false
	}
	for _, f := range a.Fixed {
		if x.SameBranch(f) && x.Compare(f) >= 0 {
			return false
		}
	}
	return true
}

// FixFor devuelve la versión corregida de la misma rama, o ok=false si la rama
// de x no recibió corrección (hay que migrar a una rama soportada).
func (a Advisory) FixFor(x Version) (Version, bool) {
	for _, f := range a.Fixed {
		if x.SameBranch(f) {
			return f, true
		}
	}
	return Version{}, false
}
