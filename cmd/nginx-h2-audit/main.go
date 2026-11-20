// Command nginx-h2-audit audita offline una instalación de nginx frente a
// CVE-2026-123007 y CVE-2026-123633. No usa la red ni ejecuta nginx.
package main

import (
	"os"

	"github.com/federiconbaez/nginx-h2-hardening-audit/internal/adapters/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
