// Command alert-linter lints Prometheus alerting rules for on-call anti-patterns.
package main

import (
	"os"

	"github.com/mohammed-saaduddin-ansari/alert-linter/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
