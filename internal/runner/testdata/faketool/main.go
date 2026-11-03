// Command faketool stands in for a scanner in the runner and command tests.
// It copies a SARIF file to --out (or to stdout with --stdout), can dump its
// environment, sleep, and exits with --code.
package main

import (
	"flag"
	"os"
	"strings"
	"time"
)

func main() {
	sarif := flag.String("sarif", "", "SARIF file to copy")
	out := flag.String("out", "", "where to write the SARIF")
	stdout := flag.Bool("stdout", false, "write the SARIF to stdout")
	noWrite := flag.Bool("no-write", false, "write no SARIF")
	code := flag.Int("code", 0, "exit code")
	sleep := flag.Duration("sleep", 0, "sleep before writing")
	envDump := flag.String("env-dump", "", "file to write the environment to")
	flag.Parse()

	if *envDump != "" {
		if err := os.WriteFile(*envDump, []byte(strings.Join(os.Environ(), "\n")), 0o600); err != nil {
			os.Exit(90)
		}
	}
	time.Sleep(*sleep)
	if !*noWrite {
		data, err := os.ReadFile(*sarif)
		if err != nil {
			os.Exit(91)
		}
		if *stdout {
			_, _ = os.Stdout.Write(data)
		} else if err := os.WriteFile(*out, data, 0o600); err != nil {
			os.Exit(92)
		}
	}
	os.Stderr.WriteString("faketool: done\n")
	os.Exit(*code)
}
