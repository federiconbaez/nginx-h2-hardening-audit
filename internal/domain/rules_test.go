package domain

import (
	"strings"
	"testing"
)

func mustCfg(t *testing.T, s string) []Directive {
	t.Helper()
	ds, err := ParseConfig("nginx.conf", []byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return ds
}

func pv(s string) *Version {
	x, err := ParseVersion(s)
	if err != nil {
		panic(err)
	}
	return &x
}

func sevOf(r Report, rule, cve string) (Severity, bool) {
	for _, f := range r.Findings {
		if f.Rule == rule && (cve == "" || (len(f.CVEs) > 0 && f.CVEs[0] == cve)) {
			return f.Severity, true
		}
	}
	return 0, false
}

const (
	cfgH2Proxy   = "events { worker_connections 256; } http { server { listen 443 ssl http2; location / { proxy_pass http://b; } } }"
	cfgH2ProxyOK = "events { worker_connections 4096; } http { server { http2 on; location / { grpc_pass grpc://b; } } }"
	cfgH2Static  = "events {} http { server { listen 443 ssl; http2 on; } }"
	cfgNoH2      = "events {} http { server { listen 443 ssl; http2 off; location / { proxy_pass http://b; } } }"
	cfgDefaultWC = "http { server { listen 443 http2; location / { proxy_pass http://b; } } }"
)

func TestEvaluateTable(t *testing.T) {
	type want struct {
		rule, cve string
		sev       Severity
	}
	cases := []struct {
		name    string
		in      Input
		want    []want
		noFinds bool
	}{
		{name: "no config: version only", in: Input{Installed: pv("1.30.6")},
			want: []want{{"VULNERABLE-VERSION", "CVE-2026-123007", High}, {"VULNERABLE-VERSION", "CVE-2026-123633", High}}},
		{name: "patched any config", in: Input{Installed: pv("1.30.7")}, noFinds: true},
		{name: "mainline patched", in: Input{Installed: pv("1.31.9")}, noFinds: true},
		{name: "old 1.19.6 only 123007", in: Input{Installed: pv("1.19.6")},
			want: []want{{"VULNERABLE-VERSION", "CVE-2026-123007", High}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := Evaluate(c.in)
			if c.noFinds && len(r.Findings) != 0 {
				t.Fatalf("expected no findings, got %+v", r.Findings)
			}
			for _, w := range c.want {
				s, ok := sevOf(r, w.rule, w.cve)
				if !ok || s != w.sev {
					t.Fatalf("%s %s: got %v ok=%v, want %v", w.rule, w.cve, s, ok, w.sev)
				}
			}
		})
	}
}

func TestEvaluateWithConfig(t *testing.T) {
	cases := []struct {
		name     string
		ver      string
		cfg      string
		s007     Severity
		s633     Severity
		lowWC    bool
		wcSev    Severity
		wantNone bool
	}{
		{"h2+proxy+low", "1.30.6", cfgH2Proxy, Critical, Critical, true, Medium, false},
		{"h2+proxy default 512", "1.31.8", cfgDefaultWC, Critical, Critical, true, Medium, false},
		{"h2+proxy high wc", "1.24.0", cfgH2ProxyOK, Critical, High, false, 0, false},
		{"h2 static", "1.30.0", cfgH2Static, Critical, Low, false, 0, false},
		{"no h2", "1.30.0", cfgNoH2, Low, Low, false, 0, false},
		{"patched h2+proxy+low", "1.30.7", cfgH2Proxy, 0, 0, true, Info, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := Evaluate(Input{Installed: pv(c.ver), Config: mustCfg(t, c.cfg), ConfigProvided: true})
			if c.wantNone {
				if m, _ := r.MaxSeverity(); m >= Low {
					t.Fatalf("expected nothing >= low, got %+v", r.Findings)
				}
			} else {
				if s, _ := sevOf(r, "VULNERABLE-VERSION", "CVE-2026-123007"); s != c.s007 {
					t.Fatalf("007 got %v", s)
				}
				if s, _ := sevOf(r, "VULNERABLE-VERSION", "CVE-2026-123633"); s != c.s633 {
					t.Fatalf("633 got %v", s)
				}
			}
			s, ok := sevOf(r, "LOW-WORKER-CONNECTIONS", "")
			if ok != c.lowWC || (ok && s != c.wcSev) {
				t.Fatalf("lowWC got %v %v", s, ok)
			}
		})
	}
}

func TestEvaluateSpecialRules(t *testing.T) {
	// A3: actualizado pero no reiniciado.
	r := Evaluate(Input{Installed: pv("1.30.7"), Running: pv("nginx/1.30.6")})
	if s, ok := sevOf(r, "RESTART-PENDING", ""); !ok || s != High {
		t.Fatalf("restart: %v %v", s, ok)
	}
	if r.VersionSource != "running" || r.EffectiveVersion != "1.30.6" {
		t.Fatalf("effective %s %s", r.EffectiveVersion, r.VersionSource)
	}
	// Mismatch sin cambio de estado de vulnerabilidad.
	r = Evaluate(Input{Installed: pv("1.31.10"), Running: pv("1.31.9")})
	if s, _ := sevOf(r, "RESTART-PENDING", ""); s != Medium {
		t.Fatalf("got %v", s)
	}
	// Server header oculto.
	r = Evaluate(Input{Installed: pv("1.30.7"), RunningHidden: true})
	if _, ok := sevOf(r, "RUNNING-VERSION-HIDDEN", ""); !ok {
		t.Fatal("hidden")
	}
	// Distro.
	r = Evaluate(Input{Installed: pv("nginx/1.24.0 (Ubuntu)")})
	if _, ok := sevOf(r, "DISTRO-PACKAGE", ""); !ok {
		t.Fatal("distro")
	}
	if !strings.Contains(r.Findings[0].Mitigation, "no upstream fix") {
		t.Fatalf("old branch mitigation: %s", r.Findings[0].Mitigation)
	}
	// Módulo HTTP/2 ausente baja a low.
	raw := "nginx version: nginx/1.30.6\nconfigure arguments: --with-http_ssl_module"
	r = Evaluate(Input{Installed: pv(raw), InstalledRaw: raw})
	if s, _ := sevOf(r, "VULNERABLE-VERSION", "CVE-2026-123007"); s != Low {
		t.Fatalf("module absent: %v", s)
	}
	// Versión desconocida con HTTP/2 activo.
	r = Evaluate(Input{Config: mustCfg(t, cfgH2Proxy), ConfigProvided: true, WCThreshold: 100})
	if s, _ := sevOf(r, "H2-ENABLED-VERSION-UNKNOWN", ""); s != Medium {
		t.Fatal("unknown version")
	}
	if _, ok := sevOf(r, "LOW-WORKER-CONNECTIONS", ""); ok {
		t.Fatal("threshold 100 should not flag 256")
	}
}

func TestReportOrderingDeterministic(t *testing.T) {
	in := Input{Installed: pv("1.30.7"), Running: pv("nginx/1.30.6 (Ubuntu)"), Config: mustCfg(t, cfgH2Proxy), ConfigProvided: true}
	a, b := Evaluate(in), Evaluate(in)
	if len(a.Findings) != len(b.Findings) {
		t.Fatal("len")
	}
	for i := range a.Findings {
		if a.Findings[i].Rule != b.Findings[i].Rule {
			t.Fatal("order")
		}
		if i > 0 && a.Findings[i-1].Severity < a.Findings[i].Severity {
			t.Fatal("not sorted by severity")
		}
	}
	if _, ok := (Report{}).MaxSeverity(); ok {
		t.Fatal("empty")
	}
	if b, _ := Critical.MarshalText(); string(b) != "critical" {
		t.Fatal("marshal")
	}
}

func TestErrorsFormat(t *testing.T) {
	e := &IncludeError{File: "a", Line: 2, Pattern: "x", Reason: "cycle"}
	if e.Error() != `a:2: include "x": cycle` {
		t.Fatal(e.Error())
	}
	if (&VersionError{Input: strings.Repeat("x", 100)}).Error() == "" {
		t.Fatal("empty")
	}
}
