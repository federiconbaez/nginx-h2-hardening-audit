package domain

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Severity de un hallazgo.
type Severity int

// Severidades, de menor a mayor.
const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

func (s Severity) String() string {
	return [...]string{"info", "low", "medium", "high", "critical"}[s]
}

// MarshalText serializa la severidad como texto en JSON.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// Finding es un hallazgo del auditor.
type Finding struct {
	Rule       string   `json:"rule"`
	Severity   Severity `json:"severity"`
	Title      string   `json:"title"`
	CVEs       []string `json:"cves,omitempty"`
	Evidence   []string `json:"evidence,omitempty"`
	Mitigation string   `json:"mitigation,omitempty"`
}

// DefaultWorkerConnections es el valor por defecto de nginx cuando
// worker_connections no está definido.
const DefaultWorkerConnections = 512

// DefaultWCThreshold es el umbral heurístico (no proviene del advisory) por
// debajo del cual se considera "bajo" worker_connections.
const DefaultWCThreshold = 1024

// Input agrupa las entradas ya parseadas para la evaluación.
type Input struct {
	Installed      *Version // de `nginx -V` / string de versión
	InstalledRaw   string   // texto crudo, para detectar --with-http_v2_module
	Running        *Version // versión en ejecución (Server header, string)
	RunningHidden  bool     // se dio un Server header sin número (server_tokens off)
	Config         []Directive
	ConfigProvided bool
	WCThreshold    int
}

// Facts son los hechos extraídos de la configuración.
type Facts struct {
	HTTP2          []string `json:"http2_enabled_at,omitempty"`
	Proxy          []string `json:"proxy_at,omitempty"`
	WorkerConns    int      `json:"worker_connections,omitempty"`
	WorkerConnsAt  string   `json:"worker_connections_at,omitempty"`
	ConfigProvided bool     `json:"config_provided"`
}

// Report es el resultado de la auditoría.
type Report struct {
	EffectiveVersion string    `json:"effective_version,omitempty"`
	VersionSource    string    `json:"version_source,omitempty"`
	Facts            Facts     `json:"facts"`
	Findings         []Finding `json:"findings"`
}

// MaxSeverity devuelve la severidad máxima y si hay hallazgos.
func (r Report) MaxSeverity() (Severity, bool) {
	if len(r.Findings) == 0 {
		return Info, false
	}
	m := Info
	for _, f := range r.Findings {
		if f.Severity > m {
			m = f.Severity
		}
	}
	return m, true
}

// ExtractFacts recorre la configuración.
func ExtractFacts(ds []Directive, provided bool) Facts {
	f := Facts{ConfigProvided: provided}
	if !provided {
		return f
	}
	f.WorkerConns = DefaultWorkerConnections
	f.WorkerConnsAt = "default (worker_connections not set)"
	Walk(ds, func(d Directive, ctx []string) {
		switch d.Name {
		case "http2":
			if len(d.Args) > 0 && strings.EqualFold(d.Args[0], "on") {
				f.HTTP2 = append(f.HTTP2, d.Location()+" http2 on")
			}
		case "listen":
			for _, a := range d.Args[min(1, len(d.Args)):] {
				if a == "http2" {
					f.HTTP2 = append(f.HTTP2, d.Location()+" listen "+strings.Join(d.Args, " "))
					break
				}
			}
		case "proxy_pass", "grpc_pass":
			f.Proxy = append(f.Proxy, d.Location()+" "+d.Name)
		case "worker_connections":
			if len(ctx) > 0 && ctx[len(ctx)-1] == "events" && len(d.Args) == 1 {
				if n, err := strconv.Atoi(d.Args[0]); err == nil && n >= 0 {
					f.WorkerConns = n
					f.WorkerConnsAt = d.Location()
				}
			}
		}
	})
	return f
}

type h2State int

const (
	h2Unknown h2State = iota
	h2Off
	h2On
)

// Evaluate aplica las reglas. Es determinista (I6).
func Evaluate(in Input) Report {
	th := in.WCThreshold
	if th <= 0 {
		th = DefaultWCThreshold
	}
	facts := ExtractFacts(in.Config, in.ConfigProvided)
	rep := Report{Facts: facts}

	eff, src := in.Running, "running"
	if eff == nil {
		eff, src = in.Installed, "installed"
	}
	if eff != nil {
		rep.EffectiveVersion = eff.String()
		rep.VersionSource = src
	}

	state := h2Unknown
	if in.ConfigProvided {
		state = h2Off
		if len(facts.HTTP2) > 0 {
			state = h2On
		}
	}
	modPresent, modKnown := HasHTTP2Module(in.InstalledRaw)
	if modKnown && !modPresent {
		rep.Findings = append(rep.Findings, Finding{
			Rule: "H2-MODULE-ABSENT", Severity: Info,
			Title:    "binary built without --with-http_v2_module: HTTP/2 cannot be enabled",
			Evidence: []string{"nginx -V: configure arguments lack --with-http_v2_module"},
		})
		state = h2Off
	}
	lowWC := facts.WorkerConns < th
	hasProxy := len(facts.Proxy) > 0

	anyVuln := false
	for _, a := range Advisories() {
		if eff == nil || !a.Affects(*eff) {
			continue
		}
		anyVuln = true
		rep.Findings = append(rep.Findings, cveFinding(a, *eff, src, state, hasProxy, lowWC, facts, th))
	}

	if eff == nil && state == h2On {
		rep.Findings = append(rep.Findings, Finding{
			Rule: "H2-ENABLED-VERSION-UNKNOWN", Severity: Medium,
			Title:      "HTTP/2 enabled but nginx version unknown: cannot rule out CVE-2026-123007/CVE-2026-123633",
			CVEs:       []string{"CVE-2026-123007", "CVE-2026-123633"},
			Evidence:   facts.HTTP2,
			Mitigation: "provide `nginx -V` output (-nginx-v) to evaluate; vulnerable ranges: 1.9.5-1.31.8 and 1.19.7-1.31.8, fixed in 1.31.9 / 1.30.7",
		})
	}

	if state == h2On && hasProxy && lowWC {
		sev := Info
		if eff == nil || anyVuln {
			sev = Medium
		}
		ev := append([]string{fmt.Sprintf("%s worker_connections %d < threshold %d", facts.WorkerConnsAt, facts.WorkerConns, th)}, facts.Proxy...)
		rep.Findings = append(rep.Findings, Finding{
			Rule: "LOW-WORKER-CONNECTIONS", Severity: sev,
			Title:      "HTTP/2 + proxy with low worker_connections (precondition of CVE-2026-123633)",
			CVEs:       []string{"CVE-2026-123633"},
			Evidence:   ev,
			Mitigation: "upgrade is the fix; raising worker_connections (and worker_rlimit_nofile) only reduces exposure. Threshold is a heuristic (-wc-threshold).",
		})
	}

	if in.Installed != nil && in.Running != nil && in.Installed.Compare(*in.Running) != 0 {
		sev := Medium
		runVuln, instVuln := false, false
		for _, a := range Advisories() {
			runVuln = runVuln || a.Affects(*in.Running)
			instVuln = instVuln || a.Affects(*in.Installed)
		}
		if runVuln && !instVuln {
			sev = High
		}
		rep.Findings = append(rep.Findings, Finding{
			Rule: "RESTART-PENDING", Severity: sev,
			Title: fmt.Sprintf("installed nginx %s differs from running %s: upgraded but not restarted", in.Installed, in.Running),
			Evidence: []string{
				"installed: " + in.Installed.String(),
				"running: " + in.Running.String(),
			},
			Mitigation: "do a full restart (`sudo systemctl restart nginx`); `nginx -s reload` keeps the old master binary",
		})
	}
	if in.RunningHidden {
		rep.Findings = append(rep.Findings, Finding{
			Rule: "RUNNING-VERSION-HIDDEN", Severity: Info,
			Title:      "running version not disclosed (server_tokens off): restart state cannot be verified",
			Mitigation: "compare the master process start time with the package install time, or pass -running with the version",
		})
	}
	if eff != nil && eff.Suffix != "" {
		rep.Findings = append(rep.Findings, Finding{
			Rule: "DISTRO-PACKAGE", Severity: Info,
			Title:      fmt.Sprintf("distribution build %q: the distro may backport fixes without changing the upstream version", eff.Suffix),
			Mitigation: "check your distribution's security tracker for CVE-2026-123007 and CVE-2026-123633, or switch to nginx.org packages (docs/HARDENING.md)",
		})
	}

	sort.SliceStable(rep.Findings, func(i, j int) bool {
		a, b := rep.Findings[i], rep.Findings[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		return a.Rule < b.Rule
	})
	if rep.Findings == nil {
		rep.Findings = []Finding{}
	}
	return rep
}

func cveFinding(a Advisory, eff Version, src string, state h2State, hasProxy, lowWC bool, facts Facts, th int) Finding {
	sev := Low
	switch {
	case state == h2Unknown:
		sev = High
	case state == h2On && !a.NeedsProxy:
		sev = Critical
	case state == h2On && a.NeedsProxy && hasProxy && lowWC:
		sev = Critical
	case state == h2On && a.NeedsProxy && hasProxy:
		sev = High
	}
	ev := []string{fmt.Sprintf("%s version %s (%s branch) in vulnerable range %s-%s", src, eff, eff.Branch(), a.From, a.To)}
	switch state {
	case h2On:
		ev = append(ev, facts.HTTP2...)
	case h2Off:
		ev = append(ev, "HTTP/2 not enabled in analyzed config")
	default:
		ev = append(ev, "no config provided: HTTP/2 usage unknown")
	}
	if a.NeedsProxy && state == h2On {
		if hasProxy {
			ev = append(ev, facts.Proxy...)
			ev = append(ev, fmt.Sprintf("%s worker_connections %d (threshold %d)", facts.WorkerConnsAt, facts.WorkerConns, th))
		} else {
			ev = append(ev, "no proxy_pass/grpc_pass found")
		}
	}

	var up string
	if fix, ok := a.FixFor(eff); ok {
		up = fmt.Sprintf("upgrade to %s (%s branch)", fix, eff.Branch())
	} else {
		up = fmt.Sprintf("branch %d.%d has no upstream fix: upgrade to 1.30.7 (stable) or 1.31.9 (mainline)", eff.Major, eff.Minor)
	}
	mit := up + ", then full restart (`sudo systemctl restart nginx`, not reload) and verify with `nginx -v`."
	if state != h2Off {
		mit += " If you cannot upgrade now: `http2 off;` and remove `http2` from `listen` lines, then reload."
	}
	return Finding{
		Rule:       "VULNERABLE-VERSION",
		Severity:   sev,
		Title:      fmt.Sprintf("%s: %s (nginx.org: %s, CVSSv4 %.1f, %s)", a.ID, a.Title, a.NginxRating, a.CVSSv4, a.CWE),
		CVEs:       []string{a.ID},
		Evidence:   ev,
		Mitigation: mit + " Advisory: " + a.F5Article,
	}
}
