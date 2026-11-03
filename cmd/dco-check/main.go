// Command dco-check reads `git log --format=%H%x00%B%x1e <base>..<head>` on stdin,
// prints the SHA of every commit without a Signed-off-by line, and exits 1 if there is any.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/cybedefend/cybedefend-scanners/internal/dco"
)

func main() {
	os.Exit(run(os.Stdin, os.Stdout, os.Stderr))
}

func run(stdin io.Reader, stdout, stderr io.Writer) int {
	in, err := io.ReadAll(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "dco-check: reading stdin: %v\n", err)
		return 2
	}
	missing := dco.MissingSignoff(dco.ParseLog(string(in)))
	for _, sha := range missing {
		fmt.Fprintln(stdout, sha)
	}
	if len(missing) > 0 {
		fmt.Fprintf(stderr, "dco-check: %d commit(s) without a Signed-off-by line; sign them off with `git commit -s` (see CONTRIBUTING.md)\n", len(missing))
		return 1
	}
	return 0
}
