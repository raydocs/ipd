// ipd-eval is an offline evaluator, deliberately separate from the application.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"ipd/internal/evaluation"
)

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ipd-eval", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dataset := flags.String("dataset", "", "local versioned dataset JSON (required)")
	split := flags.String("split", "test", "train, validation, or test")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *dataset == "" || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: ipd-eval -dataset FILE [-split test]")
		return 2
	}
	f, err := os.Open(*dataset)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer f.Close()
	d, err := evaluation.Load(f)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	report, err := evaluation.Evaluate(d, *split)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}
func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
