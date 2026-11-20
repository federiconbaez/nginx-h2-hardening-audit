package app

import (
	"errors"
	"fmt"
	"testing"

	"github.com/federiconbaez/nginx-h2-hardening-audit/internal/domain"
	"github.com/federiconbaez/nginx-h2-hardening-audit/internal/ports/porttest"
)

type fakeVersions struct {
	inst, run string
	err       error
}

func (f fakeVersions) Installed() (string, bool, error) { return f.inst, f.inst != "", f.err }
func (f fakeVersions) Running() (string, bool, error)   { return f.run, f.run != "", f.err }

func TestRunIncludesAndFindings(t *testing.T) {
	src := porttest.MemSource{
		"nginx.conf":     "events { worker_connections 128; }\nhttp {\n include /etc/nginx/conf.d/*.conf;\n include sites/one.conf;\n include /opt/other.conf;\n}\n",
		"conf.d/a.conf":  "server { listen 443 ssl http2; }\n",
		"conf.d/b.conf":  "server { location / { proxy_pass http://x; } }\n",
		"sites/one.conf": "server { http2 on; }\n",
	}
	res, err := Run(Options{Config: src, Versions: fakeVersions{inst: "nginx version: nginx/1.31.8"}})
	if err != nil {
		t.Fatal(err)
	}
	f := res.Report.Facts
	if len(f.HTTP2) != 2 || len(f.Proxy) != 1 || f.WorkerConns != 128 {
		t.Fatalf("facts %+v", f)
	}
	if f.HTTP2[0] != "conf.d/a.conf:1 listen 443 ssl http2" {
		t.Fatalf("evidence %v", f.HTTP2)
	}
	if len(res.Warnings) != 1 {
		t.Fatalf("warnings %v", res.Warnings)
	}
	if m, _ := res.Report.MaxSeverity(); m != domain.Critical {
		t.Fatalf("max %v", m)
	}
}

func TestRunErrors(t *testing.T) {
	cases := map[string]struct {
		opts  Options
		check func(error) bool
	}{
		"no input": {Options{}, func(e error) bool { return errors.Is(e, domain.ErrNoInput) }},
		"bad version": {Options{Versions: fakeVersions{inst: "garbage"}},
			func(e error) bool { return errors.Is(e, domain.ErrInvalidVersion) }},
		"bad running": {Options{Versions: fakeVersions{inst: "1.30.7", run: "Apache/2.4"}},
			func(e error) bool { return errors.Is(e, domain.ErrInvalidVersion) }},
		"version source error": {Options{Versions: fakeVersions{inst: "1.30.7", err: errors.New("boom")}},
			func(e error) bool { return e != nil }},
		"missing main": {Options{Config: porttest.MemSource{}}, func(e error) bool { return e != nil }},
		"cycle": {Options{Config: porttest.MemSource{"nginx.conf": "include a.conf;", "a.conf": "include nginx.conf;"}},
			func(e error) bool { var ie *domain.IncludeError; return errors.As(e, &ie) }},
		"missing include": {Options{Config: porttest.MemSource{"nginx.conf": "include nope.conf;"}},
			func(e error) bool {
				var ie *domain.IncludeError
				return errors.As(e, &ie) && ie.Reason == "file not found"
			}},
		"bad include args": {Options{Config: porttest.MemSource{"nginx.conf": "include a b;"}},
			func(e error) bool { var ie *domain.IncludeError; return errors.As(e, &ie) }},
		"bad glob": {Options{Config: porttest.MemSource{"nginx.conf": "include [;"}},
			func(e error) bool { var ie *domain.IncludeError; return errors.As(e, &ie) }},
		"syntax error in include": {Options{Config: porttest.MemSource{"nginx.conf": "include a.conf;", "a.conf": "x {"}},
			func(e error) bool { var pe *domain.ParseError; return errors.As(e, &pe) && pe.File == "a.conf" }},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Run(c.opts)
			if !c.check(err) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestIncludeDepthAndEscape(t *testing.T) {
	src := porttest.MemSource{}
	for i := 0; i <= MaxIncludeDepth+1; i++ {
		src[name(i)] = "include " + name(i+1) + ";"
	}
	src[name(MaxIncludeDepth+2)] = "events {}"
	_, err := Run(Options{Config: src, MainFile: name(0)})
	var ie *domain.IncludeError
	if !errors.As(err, &ie) || ie.Reason != "include depth exceeded" {
		t.Fatalf("got %v", err)
	}
	res, err := Run(Options{Config: porttest.MemSource{"nginx.conf": "include ../x.conf; include conf.d/../../y;"}})
	if err != nil || len(res.Warnings) != 2 {
		t.Fatalf("escape: %v %v", res.Warnings, err)
	}
}

func TestRunningHidden(t *testing.T) {
	res, err := Run(Options{Versions: fakeVersions{inst: "1.30.7", run: "Server: nginx"}})
	if err != nil || len(res.Report.Findings) != 1 || res.Report.Findings[0].Rule != "RUNNING-VERSION-HIDDEN" {
		t.Fatalf("%+v %v", res.Report.Findings, err)
	}
}

func name(i int) string { return fmt.Sprintf("f%03d.conf", i) }
