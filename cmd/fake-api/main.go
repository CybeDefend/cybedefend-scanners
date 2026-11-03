// Command fake-api serves internal/fakeapi on a fixed address, for the
// action's self-test (.github/workflows/action-self-test.yml).
//
//	FAKE_API_TOKEN=<token> [FAKE_API_ADDR=127.0.0.1:8080] [FAKE_API_DUMP=<file>] fake-api
//
// It accepts uploads whose bearer is FAKE_API_TOKEN and, on SIGTERM or
// SIGINT, writes them as a JSON array to FAKE_API_DUMP, then exits. The token
// is never printed nor written to the dump.
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/cybedefend/cybedefend-scanners/internal/fakeapi"
)

const defaultAddr = "127.0.0.1:8080"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Getenv, nil, os.Stderr))
}

// run serves until ctx is done, then writes the dump. When ready is not nil,
// the server's URL is sent on it once it listens.
func run(ctx context.Context, getenv func(string) string, ready chan<- string, stderr io.Writer) int {
	logf := func(format string, a ...any) { fmt.Fprintf(stderr, "fake-api: "+format+"\n", a...) }

	token := getenv("FAKE_API_TOKEN")
	if token == "" {
		logf("set FAKE_API_TOKEN, the bearer the fake API accepts")
		return 2
	}
	addr := getenv("FAKE_API_ADDR")
	if addr == "" {
		addr = defaultAddr
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logf("listen on %s: %v", addr, err)
		return 2
	}
	s := fakeapi.NewOn(token, ln)
	defer s.Close()
	logf("listening on %s", s.URL())
	if ready != nil {
		ready <- s.URL()
	}

	<-ctx.Done()
	ups := s.Uploads()
	logf("stopping after %d uploads", len(ups))
	dump := getenv("FAKE_API_DUMP")
	if dump == "" {
		return 0
	}
	if err := writeDump(s, dump); err != nil {
		logf("write the dump: %v", err)
		return 1
	}
	logf("wrote %s", dump)
	return 0
}

func writeDump(s *fakeapi.Server, path string) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".fake-api-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op once renamed
	if err := s.Dump(tmp); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
