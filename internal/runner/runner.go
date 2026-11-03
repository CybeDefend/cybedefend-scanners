// Package runner runs a tool with a timeout and a scrubbed environment, and
// reads the SARIF it produced.
package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/cybedefend/cybedefend-scanners/internal/adapter"
	"github.com/cybedefend/cybedefend-scanners/internal/sarif"
)

// BaseEnvKeys are passed to every tool, when the caller's environment has them.
var BaseEnvKeys = []string{"PATH", "HOME", "TMPDIR"}

// forbiddenPrefix marks the variables of this program (the token among them):
// they never reach a tool.
const forbiddenPrefix = "CYBEDEFEND_"

// maxSARIFBytes is how much of a tool's SARIF is kept: one byte past the
// parser's limit, so that sarif.Parse refuses it with ErrTooLarge.
const maxSARIFBytes = sarif.MaxDecompressedBytes + 1

// tailBytes is how much of the tool's other output is kept, for a failure.
const tailBytes = 8 << 10

// waitDelay bounds the wait for the tool's output pipes once it was killed.
const waitDelay = time.Second

// Result is one run of a tool. Output holds the end of what the tool printed
// besides its SARIF (stderr, and stdout when the SARIF goes to a file).
type Result struct {
	SARIF    []byte
	ExitCode int
	Duration time.Duration
	Output   []byte
}

// Run runs the adapter's tool on src, writing its SARIF to out. The tool's
// environment is the keys of BaseEnvKeys and of the adapter's EnvKeys found
// in env, never a CYBEDEFEND_* key. An exit code outside the adapter's
// success set, a timeout or a missing SARIF is an error; the Result is
// returned with it when the tool ran.
func Run(ctx context.Context, a adapter.Adapter, src, out string, timeout time.Duration, env map[string]string) (*Result, error) {
	childEnv := toolEnv(a, env)
	argv, onStdout := a.Command(src, out, childEnv)
	if len(argv) == 0 || argv[0] == "" {
		return nil, fmt.Errorf("%s: the adapter gave no command", a.Name())
	}

	if !onStdout {
		if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
			return nil, fmt.Errorf("create the output directory: %w", err)
		}
		// A file left by an earlier run must not pass for this run's output.
		if err := os.Remove(out); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("remove the previous output: %w", err)
		}
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// argv goes to the kernel as a list: never through a shell.
	cmd := exec.CommandContext(runCtx, argv[0], argv[1:]...)
	cmd.Env = envList(childEnv)
	cmd.Stdin = nil
	cmd.WaitDelay = waitDelay
	if info, err := os.Stat(src); err == nil && info.IsDir() {
		cmd.Dir = src
	}
	tail := &tailWriter{max: tailBytes}
	cmd.Stderr = tail
	var captured *limitedBuffer
	if onStdout {
		captured = &limitedBuffer{max: maxSARIFBytes}
		cmd.Stdout = captured
	} else {
		cmd.Stdout = tail
	}

	start := time.Now()
	runErr := cmd.Run()
	res := &Result{Duration: time.Since(start), Output: tail.bytes()}
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}

	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		return res, fmt.Errorf("%s timed out after %s", a.Name(), timeout)
	}
	if ctx.Err() != nil {
		return res, fmt.Errorf("%s was stopped: %w", a.Name(), ctx.Err())
	}
	if runErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(runErr, &exitErr) {
			return res, fmt.Errorf("start %s: %w", a.Name(), runErr)
		}
		if res.ExitCode < 0 || !slices.Contains(a.SuccessExitCodes(), res.ExitCode) {
			return res, fmt.Errorf("%s failed with exit code %d (expected one of %v)", a.Name(), res.ExitCode, a.SuccessExitCodes())
		}
	} else if !slices.Contains(a.SuccessExitCodes(), 0) {
		return res, fmt.Errorf("%s failed with exit code 0 (expected one of %v)", a.Name(), a.SuccessExitCodes())
	}

	if onStdout {
		if len(captured.buf) == 0 {
			return res, fmt.Errorf("%s wrote no SARIF to its standard output", a.Name())
		}
		res.SARIF = captured.buf
		return res, nil
	}
	data, err := readLimited(out)
	if errors.Is(err, os.ErrNotExist) {
		return res, fmt.Errorf("%s wrote no SARIF to %s", a.Name(), out)
	}
	if err != nil {
		return res, fmt.Errorf("read the SARIF of %s: %w", a.Name(), err)
	}
	if len(data) == 0 {
		return res, fmt.Errorf("%s wrote an empty SARIF file", a.Name())
	}
	res.SARIF = data
	return res, nil
}

// toolEnv keeps the base keys and the adapter's own keys, never CYBEDEFEND_*.
func toolEnv(a adapter.Adapter, env map[string]string) map[string]string {
	keys := slices.Clone(BaseEnvKeys)
	if p, ok := a.(adapter.EnvPassthrough); ok {
		keys = append(keys, p.EnvKeys()...)
	}
	out := make(map[string]string, len(keys))
	for _, k := range keys {
		if k == "" || strings.HasPrefix(strings.ToUpper(k), forbiddenPrefix) {
			continue
		}
		if v, ok := env[k]; ok {
			out[k] = v
		}
	}
	return out
}

// envList is never nil: a nil cmd.Env would hand the tool this process's
// whole environment, the token included.
func envList(env map[string]string) []string {
	list := make([]string, 0, len(env))
	for k, v := range env {
		list = append(list, k+"="+v)
	}
	slices.Sort(list)
	return list
}

func readLimited(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxSARIFBytes))
}

// limitedBuffer keeps the first max bytes and drops the rest, without ever
// blocking the tool.
type limitedBuffer struct {
	buf []byte
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.max - len(b.buf); room > 0 {
		b.buf = append(b.buf, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

// tailWriter keeps the last max bytes written.
type tailWriter struct {
	buf []byte
	max int
}

func (t *tailWriter) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	if over := len(t.buf) - t.max; over > 0 {
		t.buf = append(t.buf[:0:0], t.buf[over:]...)
	}
	return len(p), nil
}

func (t *tailWriter) bytes() []byte { return t.buf }
