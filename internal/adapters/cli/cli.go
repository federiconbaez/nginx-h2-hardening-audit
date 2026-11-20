// Package cli es el adaptador de línea de comandos: flags, salida texto/JSON y
// códigos de salida (0 limpio, 1 hallazgos >= low, 2 error de entrada).
package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/federiconbaez/nginx-h2-hardening-audit/internal/adapters/fsconfig"
	"github.com/federiconbaez/nginx-h2-hardening-audit/internal/adapters/textversion"
	"github.com/federiconbaez/nginx-h2-hardening-audit/internal/app"
	"github.com/federiconbaez/nginx-h2-hardening-audit/internal/domain"
)

// Códigos de salida.
const (
	ExitClean    = 0
	ExitFindings = 1
	ExitInput    = 2
)

// Run ejecuta la CLI y devuelve el código de salida.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("nginx-h2-audit", flag.ContinueOnError)
	fl.SetOutput(stderr)
	var (
		nginxV      = fl.String("nginx-v", "", "file with `nginx -V` output of the installed binary (\"-\" = stdin)")
		version     = fl.String("version", "", "installed version string, e.g. 1.30.6 (alternative to -nginx-v)")
		running     = fl.String("running", "", "running version: Server header (\"nginx/1.30.6\") or version string")
		runningFile = fl.String("running-file", "", "file with the running version / Server header")
		root        = fl.String("config-root", "", "directory with a copy (or the original) of the nginx config tree, read-only")
		mainFile    = fl.String("config-main", "nginx.conf", "main config file, relative to -config-root")
		strip       = fl.String("strip-prefix", "/etc/nginx", "absolute include prefix mapped to -config-root")
		threshold   = fl.Int("wc-threshold", domain.DefaultWCThreshold, "worker_connections below this value count as low (heuristic)")
		format      = fl.String("format", "text", "output format: text or json")
	)
	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitClean
		}
		return ExitInput
	}
	if fl.NArg() > 0 {
		fmt.Fprintf(stderr, "error: unexpected arguments: %s\n", strings.Join(fl.Args(), " "))
		return ExitInput
	}
	if *nginxV != "" && *version != "" {
		fmt.Fprintln(stderr, "error: use either -nginx-v or -version, not both")
		return ExitInput
	}
	if *running != "" && *runningFile != "" {
		fmt.Fprintln(stderr, "error: use either -running or -running-file, not both")
		return ExitInput
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintln(stderr, "error: -format must be text or json")
		return ExitInput
	}
	if *threshold <= 0 {
		fmt.Fprintln(stderr, "error: -wc-threshold must be > 0")
		return ExitInput
	}
	opts := app.Options{
		MainFile:    *mainFile,
		StripPrefix: *strip,
		WCThreshold: *threshold,
		Versions: textversion.New(textversion.Spec{
			InstalledFile: *nginxV, InstalledString: *version,
			RunningFile: *runningFile, RunningString: *running,
			Stdin: stdin,
		}),
	}
	if *root != "" {
		src, err := fsconfig.Open(*root)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return ExitInput
		}
		defer func() { _ = src.Close() }()
		opts.Config = src
	}
	res, err := app.Run(opts)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return ExitInput
	}
	if *format == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return ExitInput
		}
	} else {
		writeText(stdout, res)
	}
	if m, ok := res.Report.MaxSeverity(); ok && m >= domain.Low {
		return ExitFindings
	}
	return ExitClean
}

func writeText(w io.Writer, res app.Result) {
	r := res.Report
	if r.EffectiveVersion != "" {
		fmt.Fprintf(w, "nginx version evaluated: %s (%s)\n", r.EffectiveVersion, r.VersionSource)
	} else {
		fmt.Fprintln(w, "nginx version evaluated: unknown")
	}
	if r.Facts.ConfigProvided {
		fmt.Fprintf(w, "config: http2 enabled at %d place(s), proxy/grpc_pass at %d, worker_connections %d\n",
			len(r.Facts.HTTP2), len(r.Facts.Proxy), r.Facts.WorkerConns)
	}
	for _, wn := range res.Warnings {
		fmt.Fprintf(w, "warning: %s\n", wn)
	}
	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "no findings")
		return
	}
	for _, f := range r.Findings {
		fmt.Fprintf(w, "\n[%s] %s: %s\n", strings.ToUpper(f.Severity.String()), f.Rule, f.Title)
		for _, e := range f.Evidence {
			fmt.Fprintf(w, "  evidence: %s\n", e)
		}
		if f.Mitigation != "" {
			fmt.Fprintf(w, "  mitigation: %s\n", f.Mitigation)
		}
	}
}
