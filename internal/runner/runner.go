// Package runner runs a tool with a timeout and a scrubbed environment, and
// reads the SARIF it produced.
package runner

import (
	"context"
	"encoding/json"
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
	// FallbackReason is set when the first run failed and the adapter's
	// fallback (adapter.FallbackAdapter) ran instead: why, in a fixed sentence.
	FallbackReason string
	// NothingToAudit is set when the tool said the source holds nothing it
	// audits (adapter.QuietAdapter): SARIF is then an empty run of the tool.
	NothingToAudit bool
}

// Run runs the adapter's tool on src, writing its SARIF to out. The tool's
// environment is the keys of BaseEnvKeys and of the keys the adapter declares
// (adapter.EnvForwarder) found in env, never a CYBEDEFEND_* key. An exit
// code outside the adapter's success set, a timeout or a missing SARIF is an
// error; the Result is returned with it when the tool ran.
//
// When the run fails and the adapter names a fallback for that failure
// (adapter.FallbackAdapter), the fallback runs once, with what is left of
// the timeout, and its outcome is the Run's.
func Run(ctx context.Context, a adapter.Adapter, src, out string, timeout time.Duration, env map[string]string) (*Result, error) {
	start := time.Now()
	res, err := runOnce(ctx, a, src, out, timeout, env)
	if err == nil || res == nil || ctx.Err() != nil {
		return res, err
	}
	f, ok := a.(adapter.FallbackAdapter)
	if !ok {
		return res, err
	}
	alt, reason, ok := f.Fallback(res.ExitCode, res.Output)
	if !ok {
		return res, err
	}
	left := timeout - time.Since(start)
	if left <= 0 {
		return res, err
	}
	res, err = runOnce(ctx, alt, src, out, left, env)
	if res != nil {
		res.FallbackReason = reason
	}
	return res, err
}

// runOnce is one run of the adapter's tool: see Run.
func runOnce(ctx context.Context, a adapter.Adapter, src, out string, timeout time.Duration, env map[string]string) (*Result, error) {
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

	ensureToolDirs(childEnv)

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
		if q, ok := a.(adapter.QuietAdapter); ok && q.NothingToAudit(res.ExitCode, res.Output) {
			res.NothingToAudit = true
			res.SARIF = emptySARIF(a.Name())
			return res, nil
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

// toolDirKeys name the directories a tool writes besides its output: the
// images point them under /tmp/appsec-scanner, where an emptyDir or a tmpfs
// arrives empty on a read-only root filesystem.
var toolDirKeys = []string{"HOME", "TMPDIR"}

// ensureToolDirs creates the absolute HOME and TMPDIR of the tool's
// environment (0700, the parents as needed) before the tool starts. It is
// best effort: a directory it cannot create is left to the tool, which may
// never use it (a CI runner's HOME, say), and reports its own error if it does.
func ensureToolDirs(env map[string]string) {
	for _, k := range toolDirKeys {
		if dir := env[k]; dir != "" && filepath.IsAbs(dir) {
			_ = os.MkdirAll(dir, 0o700)
		}
	}
}

// toolEnv keeps the base keys and the adapter's own keys, never CYBEDEFEND_*.
func toolEnv(a adapter.Adapter, env map[string]string) map[string]string {
	// The base keys first, then the keys the adapter declares
	// (adapter.EnvForwarder).
	keys := append(slices.Clone(BaseEnvKeys), adapter.ToolEnvKeys(a)...)
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

// emptySARIF is one run of the tool with no result, for a tool that had
// nothing to audit.
func emptySARIF(tool string) []byte {
	name, _ := json.Marshal(tool)
	return []byte(`{"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{"tool":{"driver":{"name":` + string(name) + `}},"results":[]}]}`)
}
