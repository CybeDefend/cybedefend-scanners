package runner

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cybedefend/cybedefend-scanners/internal/adapter"
)

var fakeTool string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "faketool-")
	if err != nil {
		panic(err)
	}
	fakeTool = filepath.Join(dir, "faketool")
	build := exec.Command("go", "build", "-o", fakeTool, "./testdata/faketool")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		panic("build faketool: " + err.Error() + "\n" + string(out))
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func minimalSARIF(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs("../../testdata/sarif/minimal.sarif")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// fakeAdapter runs faketool with extra flags.
type fakeAdapter struct {
	flags   []string
	stdout  bool
	codes   []int
	envKeys []string
	sarif   string
	lastEnv map[string]string
}

func (f *fakeAdapter) Name() string             { return "fake" }
func (f *fakeAdapter) Type() adapter.ImportType { return adapter.TypeSAST }
func (f *fakeAdapter) Command(src, out string, env map[string]string) ([]string, bool) {
	f.lastEnv = env
	argv := []string{fakeTool, "--sarif", f.sarif, "--out", out}
	if f.stdout {
		argv = append(argv, "--stdout")
	}
	return append(argv, f.flags...), f.stdout
}
func (f *fakeAdapter) SuccessExitCodes() []int {
	if f.codes == nil {
		return []int{0}
	}
	return f.codes
}
func (f *fakeAdapter) EnvKeys() []string { return f.envKeys }

func outPath(t *testing.T) string { return filepath.Join(t.TempDir(), "sub", "results.sarif") }

func TestRunTreatsFindingExitCodesAsSuccess(t *testing.T) {
	for _, code := range []string{"1", "13"} {
		a := &fakeAdapter{flags: []string{"--code", code}, codes: []int{0, 1, 13}, sarif: minimalSARIF(t)}
		res, err := Run(context.Background(), a, t.TempDir(), outPath(t), 10*time.Second, nil)
		if err != nil {
			t.Fatalf("exit %s: %v", code, err)
		}
		if res.ExitCode == 0 || !strings.Contains(string(res.SARIF), `"version"`) {
			t.Fatalf("exit %s: result %+v", code, res)
		}
	}
	a := &fakeAdapter{flags: []string{"--code", "2"}, codes: []int{0, 1, 13}, sarif: minimalSARIF(t)}
	_, err := Run(context.Background(), a, t.TempDir(), outPath(t), 10*time.Second, nil)
	if err == nil || !strings.Contains(err.Error(), "2") {
		t.Fatalf("exit 2: err = %v, want an error naming the exit code", err)
	}
}

func TestRunFailsWhenNoSARIFWasWritten(t *testing.T) {
	out := outPath(t)
	// A file left by an earlier run must not pass for this run's output.
	if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, []byte(`{"version":"2.1.0","runs":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &fakeAdapter{flags: []string{"--no-write"}, sarif: minimalSARIF(t)}
	if _, err := Run(context.Background(), a, t.TempDir(), out, 10*time.Second, nil); err == nil {
		t.Fatal("no error when the tool wrote no SARIF")
	}
	a = &fakeAdapter{flags: []string{"--no-write"}, stdout: true, sarif: minimalSARIF(t)}
	if _, err := Run(context.Background(), a, t.TempDir(), outPath(t), 10*time.Second, nil); err == nil {
		t.Fatal("no error when the tool wrote nothing to stdout")
	}
}

func TestRunReadsSARIFFromStdout(t *testing.T) {
	want, err := os.ReadFile(minimalSARIF(t))
	if err != nil {
		t.Fatal(err)
	}
	a := &fakeAdapter{stdout: true, sarif: minimalSARIF(t)}
	res, err := Run(context.Background(), a, t.TempDir(), outPath(t), 10*time.Second, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if string(res.SARIF) != string(want) {
		t.Fatalf("SARIF = %q", res.SARIF)
	}
	if strings.Contains(string(res.SARIF), "faketool: done") {
		t.Fatal("stderr leaked into the SARIF")
	}
}

func TestRunNeverPassesCYBEDEFENDVariablesToTheTool(t *testing.T) {
	dump := filepath.Join(t.TempDir(), "env.txt")
	a := &fakeAdapter{
		flags:   []string{"--env-dump", dump},
		envKeys: []string{"GH_TOKEN", "CYBEDEFEND_TOKEN"},
		sarif:   minimalSARIF(t),
	}
	env := map[string]string{
		"PATH": "/usr/bin:/bin", "HOME": "/home/scanner", "TMPDIR": "/tmp",
		"GH_TOKEN": "gh_value", "AWS_SECRET_ACCESS_KEY": "aws_value",
		"CYBEDEFEND_TOKEN": "cdp_secret_value", "CYBEDEFEND_PAT": "cdp_pat_value",
		"CYBEDEFEND_API_URL": "https://appsec.example.com/api",
	}
	if _, err := Run(context.Background(), a, t.TempDir(), outPath(t), 10*time.Second, env); err != nil {
		t.Fatalf("Run: %v", err)
	}
	raw, err := os.ReadFile(dump)
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	for _, bad := range []string{"CYBEDEFEND_", "cdp_secret_value", "cdp_pat_value", "AWS_SECRET_ACCESS_KEY", "aws_value"} {
		if strings.Contains(got, bad) {
			t.Errorf("the tool's environment holds %q:\n%s", bad, got)
		}
	}
	for _, good := range []string{"PATH=/usr/bin:/bin", "HOME=/home/scanner", "TMPDIR=/tmp", "GH_TOKEN=gh_value"} {
		if !strings.Contains(got, good) {
			t.Errorf("the tool's environment lacks %q:\n%s", good, got)
		}
	}
	for k := range a.lastEnv {
		if strings.HasPrefix(k, "CYBEDEFEND_") {
			t.Errorf("Command received %s", k)
		}
	}
}

func TestRunHonoursTheTimeout(t *testing.T) {
	a := &fakeAdapter{flags: []string{"--sleep", "5s"}, sarif: minimalSARIF(t)}
	start := time.Now()
	_, err := Run(context.Background(), a, t.TempDir(), outPath(t), 200*time.Millisecond, nil)
	if err == nil {
		t.Fatal("no error after the timeout")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("Run returned after %s", d)
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err = %v, want a timeout", err)
	}
}

func TestRunRefusesAnEmptyCommand(t *testing.T) {
	if _, err := Run(context.Background(), emptyAdapter{}, t.TempDir(), outPath(t), time.Second, nil); err == nil {
		t.Fatal("no error for an empty argv")
	}
}

type emptyAdapter struct{}

func (emptyAdapter) Name() string                                               { return "empty" }
func (emptyAdapter) Type() adapter.ImportType                                   { return adapter.TypeSAST }
func (emptyAdapter) Command(string, string, map[string]string) ([]string, bool) { return nil, false }
func (emptyAdapter) SuccessExitCodes() []int                                    { return []int{0} }

// forwardingAdapter declares its tool's keys through adapter.EnvForwarder.
type forwardingAdapter struct {
	fakeAdapter
	forwarded []string
}

func (f *forwardingAdapter) ForwardedEnv() []string { return f.forwarded }

func TestRunForwardsDeclaredKeysOnly(t *testing.T) {
	dump := filepath.Join(t.TempDir(), "env.txt")
	a := &forwardingAdapter{
		fakeAdapter: fakeAdapter{flags: []string{"--env-dump", dump}, sarif: minimalSARIF(t)},
		forwarded:   []string{"TRIVY_DB_REPOSITORY", "CYBEDEFEND_TOKEN"},
	}
	env := map[string]string{
		"PATH":                "/usr/bin:/bin",
		"TRIVY_DB_REPOSITORY": "mirror.example/trivy-db",
		"TRIVY_OTHER":         "x",
		"CYBEDEFEND_TOKEN":    "t",
	}
	if _, err := Run(context.Background(), a, t.TempDir(), outPath(t), 10*time.Second, env); err != nil {
		t.Fatalf("Run: %v", err)
	}
	raw, err := os.ReadFile(dump)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSpace(string(raw)), "\n")
	want := []string{"PATH=/usr/bin:/bin", "TRIVY_DB_REPOSITORY=mirror.example/trivy-db"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("the tool's environment = %q, want %q", got, want)
	}
}
