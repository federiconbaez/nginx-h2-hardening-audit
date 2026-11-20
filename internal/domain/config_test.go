package domain

import (
	"errors"
	"strings"
	"testing"
)

func TestParseConfigOK(t *testing.T) {
	src := "# c\nevents { worker_connections 256; }\nhttp {\n  server {\n    listen 443 ssl http2; # x\n    add_header X \"a;b {c}\";\n    location / { proxy_pass http://u; }\n  }\n}\n"
	ds, err := ParseConfig("nginx.conf", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	Walk(ds, func(d Directive, ctx []string) { names = append(names, strings.Join(append(ctx, d.Name), "/")) })
	got := strings.Join(names, ",")
	want := "events,events/worker_connections,http,http/server,http/server/listen,http/server/add_header,http/server/location,http/server/location/proxy_pass"
	if got != want {
		t.Fatalf("got %s", got)
	}
	f := ExtractFacts(ds, true)
	if len(f.HTTP2) != 1 || f.HTTP2[0] != "nginx.conf:5 listen 443 ssl http2" {
		t.Fatalf("http2 %v", f.HTTP2)
	}
	if f.WorkerConns != 256 || f.WorkerConnsAt != "nginx.conf:2" || len(f.Proxy) != 1 {
		t.Fatalf("facts %+v", f)
	}
}

func TestParseConfigEdgeCases(t *testing.T) {
	ds, err := ParseConfig("a", []byte("x 'it\\'s';\nempty {}\ny \"multi\nline\";\nz;"))
	if err != nil {
		t.Fatal(err)
	}
	if ds[0].Args[0] != "it's" || ds[1].Block == nil || len(ds[1].Block) != 0 || ds[3].Line != 5 {
		t.Fatalf("%+v", ds)
	}
	if ds[0].Location() != "a:1" {
		t.Fatal(ds[0].Location())
	}
}

func TestParseConfigErrors(t *testing.T) {
	cases := map[string]struct {
		src  string
		line int
	}{
		"unterminated quote": {"a \"b;\n", 1},
		"missing semicolon":  {"a b", 1},
		"unclosed block":     {"http {\n a b;\n", 2},
		"extra brace":        {"a;\n}\n", 2},
		"brace in args":      {"http { a } ", 1},
		"leading semicolon":  {";", 1},
		"leading brace":      {"{", 1},
		"unclosed nested":    {"http {\n server {\n", 2},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseConfig("f.conf", []byte(c.src))
			var pe *ParseError
			if !errors.As(err, &pe) {
				t.Fatalf("want *ParseError, got %v", err)
			}
			if pe.Line != c.line || pe.File != "f.conf" {
				t.Fatalf("got %s", pe)
			}
		})
	}
}

func TestParseConfigLimits(t *testing.T) {
	deep := strings.Repeat("a {", 70) + strings.Repeat("}", 70)
	if _, err := ParseConfig("d", []byte(deep)); err == nil {
		t.Fatal("expected nesting error")
	}
	big := make([]byte, maxConfigBytes+1)
	if _, err := ParseConfig("b", big); err == nil {
		t.Fatal("expected size error")
	}
}

func TestItoa(t *testing.T) {
	for n, s := range map[int]string{0: "0", 7: "7", 1234: "1234", -5: "-5"} {
		if itoa(n) != s {
			t.Fatalf("%d", n)
		}
	}
}

func FuzzParseConfig(f *testing.F) {
	for _, s := range []string{
		"events { worker_connections 256; }",
		"http { server { listen 443 ssl http2; location / { proxy_pass http://x; } } }",
		"a \"b\\\"c\" 'd';",
		"# only comment",
		"x {",
		"}",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		ds, err := ParseConfig("fuzz.conf", b)
		if err != nil {
			var pe *ParseError
			if !errors.As(err, &pe) || pe.Line < 1 {
				t.Fatalf("bad error %v", err)
			}
			return
		}
		Walk(ds, func(d Directive, _ []string) {
			if d.Line < 1 || d.File != "fuzz.conf" {
				t.Fatalf("bad location %+v", d)
			}
		})
		_ = Evaluate(Input{Config: ds, ConfigProvided: true})
	})
}
