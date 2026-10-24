// Command ipd is the single binary: serve, mcp, agent, ingest, and the checks.
package main

import (
	"os"

	"ipd/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:]))
}
