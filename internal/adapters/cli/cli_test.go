package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "update golden files")

const fx = "../../../testdata/fixtures"

func run(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

// Regresión: salida de texto del fixture vulnerable contra golden file.
func TestGoldenVulnProxy(t *testing.T) {
	code, out, _ := run(t, "", "-nginx-v", fx+"/vuln-proxy/nginx-V.txt", "-config-root", fx+"/vuln-proxy")
	if code != ExitFindings {
		t.Fatalf("exit %d", code)
	}
	golden := filepath.Join(fx, "vuln-proxy", "expected.txt")
	if *update {
		if err := os.WriteFile(golden, []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if out != string(want) {
		t.Fatalf("golden mismatch:\n%s", out)
	}
}

func TestExitCodesAndFormats(t *testing.T) {
	cases := []struct {
		name  string
		stdin string
		args  []string
		code  int
		has   string
	}{
		{"patched clean", "", []string{"-version", "1.30.7", "-config-root", fx + "/patched"}, ExitClean, "no findings"},
		{"static h2 vulnerable", "", []string{"-version", "1.30.0", "-config-root", fx + "/static-only"}, ExitFindings, "[CRITICAL] VULNERABLE-VERSION: CVE-2026-123007"},
		{"restart pending", "", []string{"-version", "1.30.7", "-running", "Server: nginx/1.30.6"}, ExitFindings, "RESTART-PENDING"},
		{"stdin nginx -V", "nginx version: nginx/1.31.9\n", []string{"-nginx-v", "-"}, ExitClean, "1.31.9"},
		{"hidden running info only", "", []string{"-version", "1.31.9", "-running", "nginx"}, ExitClean, "RUNNING-VERSION-HIDDEN"},
		{"help", "", []string{"-h"}, ExitClean, ""},
		{"no input", "", nil, ExitInput, ""},
		{"bad version", "", []string{"-version", "abc"}, ExitInput, ""},
		{"both version flags", "", []string{"-version", "1.30.7", "-nginx-v", "x"}, ExitInput, ""},
		{"both running flags", "", []string{"-version", "1.30.7", "-running", "1.30.7", "-running-file", "x"}, ExitInput, ""},
		{"bad format", "", []string{"-version", "1.30.7", "-format", "xml"}, ExitInput, ""},
		{"bad threshold", "", []string{"-version", "1.30.7", "-wc-threshold", "0"}, ExitInput, ""},
		{"extra args", "", []string{"-version", "1.30.7", "foo"}, ExitInput, ""},
		{"unknown flag", "", []string{"-nope"}, ExitInput, ""},
		{"missing root", "", []string{"-config-root", fx + "/does-not-exist"}, ExitInput, ""},
		{"cycle", "", []string{"-config-root", fx + "/cycle"}, ExitInput, ""},
		{"missing nginx -V file", "", []string{"-nginx-v", fx + "/missing.txt"}, ExitInput, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out, errOut := run(t, c.stdin, c.args...)
			if code != c.code {
				t.Fatalf("exit %d want %d; stderr=%s", code, c.code, errOut)
			}
			if c.has != "" && !strings.Contains(out, c.has) {
				t.Fatalf("output lacks %q:\n%s", c.has, out)
			}
		})
	}
}

func TestJSONOutput(t *testing.T) {
	code, out, _ := run(t, "", "-format", "json", "-nginx-v", fx+"/vuln-proxy/nginx-V.txt", "-config-root", fx+"/vuln-proxy")
	if code != ExitFindings {
		t.Fatalf("exit %d", code)
	}
	var doc struct {
		Report struct {
			EffectiveVersion string `json:"effective_version"`
			Findings         []struct {
				Rule     string   `json:"rule"`
				Severity string   `json:"severity"`
				CVEs     []string `json:"cves"`
				Evidence []string `json:"evidence"`
			} `json:"findings"`
		} `json:"report"`
		Warnings []string `json:"warnings"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Report.EffectiveVersion != "1.30.6" || len(doc.Report.Findings) != 3 || doc.Report.Findings[0].Severity != "critical" {
		t.Fatalf("%+v", doc)
	}
	if !strings.Contains(strings.Join(doc.Report.Findings[1].Evidence, "|"), "conf.d/mcp.conf:6") {
		t.Fatalf("evidence %v", doc.Report.Findings[1].Evidence)
	}
}
