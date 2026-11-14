package runner

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cybedefend/cybedefend-scanners/internal/adapter"
	"github.com/cybedefend/cybedefend-scanners/internal/sarif"
	"github.com/cybedefend/cybedefend-scanners/internal/sbom"
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
func (f *fakeAdapter) ForwardedEnv() []string { return f.envKeys }

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

// An emptyDir or a tmpfs mounted at /tmp/cybedefend-scanner arrives empty: the
// HOME and TMPDIR the images point under it must exist before the tool runs.
func TestRunCreatesHomeAndTmpdirBeforeTheTool(t *testing.T) {
	base := filepath.Join(t.TempDir(), "cybedefend-scanner")
	home := filepath.Join(base, "home")
	tmp := filepath.Join(base, "tmp")
	dump := filepath.Join(t.TempDir(), "env.txt")
	a := &fakeAdapter{flags: []string{"--env-dump", dump}, sarif: minimalSARIF(t)}
	env := map[string]string{"PATH": "/usr/bin:/bin", "HOME": home, "TMPDIR": tmp}
	if _, err := Run(context.Background(), a, t.TempDir(), outPath(t), 10*time.Second, env); err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, d := range []string{home, tmp} {
		info, err := os.Stat(d)
		if err != nil || !info.IsDir() {
			t.Fatalf("%s was not created: %v", d, err)
		}
		if perm := info.Mode().Perm(); perm != 0o700 {
			t.Errorf("%s has mode %o, want 700", d, perm)
		}
	}
}

// A relative HOME or TMPDIR names no place the runner should create.
func TestRunCreatesOnlyAbsoluteHomeAndTmpdir(t *testing.T) {
	dir := t.TempDir()
	a := &fakeAdapter{sarif: minimalSARIF(t)}
	env := map[string]string{"PATH": "/usr/bin:/bin", "HOME": "relhome", "TMPDIR": "reltmp"}
	if _, err := Run(context.Background(), a, dir, outPath(t), 10*time.Second, env); err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, d := range []string{"relhome", "reltmp"} {
		if _, err := os.Stat(filepath.Join(dir, d)); err == nil {
			t.Errorf("a relative %s was created in the source directory", d)
		}
	}
}

// quietAdapter is a tool that says, by exit code 3 and its own sentence, that
// the source holds nothing it audits (zizmor on a repository without
// workflows).
type quietAdapter struct{ fakeAdapter }

func (q *quietAdapter) NothingToAudit(exitCode int, output []byte) bool {
	return exitCode == 3 && bytes.Contains(output, []byte("nothing to audit here"))
}

func TestRunTurnsNothingToAuditIntoAnEmptySARIF(t *testing.T) {
	for _, stdout := range []bool{true, false} {
		a := &quietAdapter{fakeAdapter{flags: []string{"--code", "3", "--no-write", "--say", "error: nothing to audit here"}, stdout: stdout, sarif: minimalSARIF(t)}}
		res, err := Run(context.Background(), a, t.TempDir(), outPath(t), 10*time.Second, nil)
		if err != nil {
			t.Fatalf("stdout=%v: %v", stdout, err)
		}
		if !res.NothingToAudit || res.ExitCode != 3 {
			t.Fatalf("stdout=%v: result %+v, want NothingToAudit with exit code 3", stdout, res)
		}
		log, err := sarif.Parse(bytes.NewReader(res.SARIF))
		if err != nil {
			t.Fatalf("stdout=%v: the empty SARIF does not parse: %v", stdout, err)
		}
		if err := sarif.Check(log); err != nil {
			t.Fatalf("stdout=%v: the empty SARIF is refused: %v", stdout, err)
		}
		if len(log.Runs) != 1 || log.Runs[0].Tool.Driver.Name != "fake" || len(log.Runs[0].Results) != 0 {
			t.Fatalf("stdout=%v: SARIF %s, want one run of fake with no result", stdout, res.SARIF)
		}
	}
}

func TestRunStillFailsOnEveryOtherExitOfAQuietTool(t *testing.T) {
	cases := [][]string{
		{"--code", "3", "--no-write"},                                   // the code without the sentence
		{"--code", "2", "--no-write", "--say", "nothing to audit here"}, // the sentence with another code
	}
	for _, flags := range cases {
		a := &quietAdapter{fakeAdapter{flags: flags, stdout: true, sarif: minimalSARIF(t)}}
		if _, err := Run(context.Background(), a, t.TempDir(), outPath(t), 10*time.Second, nil); err == nil {
			t.Fatalf("flags %v: no error", flags)
		}
	}
}

// retryAdapter falls back, on its own sentence, to another fake run.
type retryAdapter struct {
	fakeAdapter
	alt *fakeAdapter
}

func (r *retryAdapter) Fallback(exitCode int, output []byte) (adapter.Adapter, string, bool) {
	if exitCode == 1 && bytes.Contains(output, []byte("rate limited")) {
		return r.alt, "the registry refused, ran again offline", true
	}
	return nil, "", false
}

func TestRunFallsBackOnceWhenTheAdapterAsks(t *testing.T) {
	a := &retryAdapter{
		fakeAdapter: fakeAdapter{flags: []string{"--code", "1", "--no-write", "--say", "rate limited"}, sarif: minimalSARIF(t)},
		alt:         &fakeAdapter{sarif: minimalSARIF(t)},
	}
	res, err := Run(context.Background(), a, t.TempDir(), outPath(t), 10*time.Second, nil)
	if err != nil {
		t.Fatalf("fallback run: %v", err)
	}
	if res.FallbackReason != "the registry refused, ran again offline" || !strings.Contains(string(res.SARIF), `"version"`) {
		t.Fatalf("result %+v, want the fallback's SARIF and its reason", res)
	}
}

func TestRunDoesNotFallBackOnAnotherFailure(t *testing.T) {
	a := &retryAdapter{
		fakeAdapter: fakeAdapter{flags: []string{"--code", "1", "--no-write", "--say", "disk full"}, sarif: minimalSARIF(t)},
		alt:         &fakeAdapter{sarif: minimalSARIF(t)},
	}
	if _, err := Run(context.Background(), a, t.TempDir(), outPath(t), 10*time.Second, nil); err == nil {
		t.Fatal("no error: the run fell back on a failure the adapter does not name")
	}
}

func TestRunReportsTheFallbacksOwnFailure(t *testing.T) {
	a := &retryAdapter{
		fakeAdapter: fakeAdapter{flags: []string{"--code", "1", "--no-write", "--say", "rate limited"}, sarif: minimalSARIF(t)},
		alt:         &fakeAdapter{flags: []string{"--code", "2", "--no-write"}, sarif: minimalSARIF(t)},
	}
	_, err := Run(context.Background(), a, t.TempDir(), outPath(t), 10*time.Second, nil)
	if err == nil || !strings.Contains(err.Error(), "2") {
		t.Fatalf("err = %v, want the fallback's exit code", err)
	}
}

// convertingAdapter writes a report with faketool, then converts it: the
// SARIF conversion copies sarifFile to out, the SBOM one sbomFile to sbomPath.
type convertingAdapter struct {
	fakeAdapter
	sarifFlags, sbomFlags []string
	sbomFile, sbomPath    string
	noSBOM                bool
}

func (c *convertingAdapter) Command(src, out string, env map[string]string) ([]string, bool) {
	return append([]string{fakeTool, "--sarif", c.sarif, "--out", out + ".report"}, c.flags...), false
}

func (c *convertingAdapter) Conversion(out string) (adapter.Conversion, bool) {
	conv := adapter.Conversion{
		Report: out + ".report",
		SARIF:  append([]string{fakeTool, "--sarif", out + ".report", "--out", out}, c.sarifFlags...),
	}
	if !c.noSBOM {
		conv.SBOM = append([]string{fakeTool, "--sarif", c.sbomFile, "--out", c.sbomPath}, c.sbomFlags...)
		conv.SBOMPath = c.sbomPath
	}
	return conv, true
}

func writeTemp(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func newConverting(t *testing.T) *convertingAdapter {
	return &convertingAdapter{
		fakeAdapter: fakeAdapter{sarif: minimalSARIF(t)},
		sbomFile:    writeTemp(t, "in.cdx.json", `{"bomFormat":"CycloneDX","specVersion":"1.7"}`),
		sbomPath:    filepath.Join(t.TempDir(), "results.cdx.json"),
	}
}

func TestRunConvertsTheReportIntoTheSARIFAndTheSBOM(t *testing.T) {
	a := newConverting(t)
	out := outPath(t)
	res, err := Run(context.Background(), a, t.TempDir(), out, 10*time.Second, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(string(res.SARIF), `"version"`) {
		t.Fatalf("SARIF = %q", res.SARIF)
	}
	if string(res.SBOM) != `{"bomFormat":"CycloneDX","specVersion":"1.7"}` || res.SBOMErr != nil {
		t.Fatalf("SBOM = %q, err %v", res.SBOM, res.SBOMErr)
	}
	if _, err := os.Stat(out + ".report"); !os.IsNotExist(err) {
		t.Fatalf("the report was left behind: %v", err)
	}
}

func TestRunWithoutAnSBOMConversionReadsNoSBOM(t *testing.T) {
	a := newConverting(t)
	a.noSBOM = true
	res, err := Run(context.Background(), a, t.TempDir(), outPath(t), 10*time.Second, nil)
	if err != nil || res.SBOM != nil || res.SBOMErr != nil {
		t.Fatalf("res %+v, err %v", res, err)
	}
}

// The SBOM is extra: when its conversion fails, the scan still has its SARIF.
func TestRunKeepsTheSARIFWhenTheSBOMConversionFails(t *testing.T) {
	a := newConverting(t)
	a.sbomFlags = []string{"--code", "3", "--no-write"}
	res, err := Run(context.Background(), a, t.TempDir(), outPath(t), 10*time.Second, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.SBOM != nil || res.SBOMErr == nil || !strings.Contains(res.SBOMErr.Error(), "3") {
		t.Fatalf("SBOM %q, SBOMErr %v: want no SBOM and the exit code", res.SBOM, res.SBOMErr)
	}
	if !strings.Contains(string(res.SARIF), `"version"`) {
		t.Fatalf("SARIF = %q", res.SARIF)
	}
}

func TestRunNeverReadsAnSBOMLeftByAnEarlierRun(t *testing.T) {
	a := newConverting(t)
	if err := os.WriteFile(a.sbomPath, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	a.sbomFlags = []string{"--no-write"}
	res, err := Run(context.Background(), a, t.TempDir(), outPath(t), 10*time.Second, nil)
	if err != nil || res.SBOM != nil || res.SBOMErr == nil {
		t.Fatalf("SBOM %q, SBOMErr %v, err %v: want no SBOM", res.SBOM, res.SBOMErr, err)
	}
}

func TestRunRefusesAnSBOMAboveTheLimit(t *testing.T) {
	old := maxSBOMBytes
	maxSBOMBytes = 10
	t.Cleanup(func() { maxSBOMBytes = old })
	res, err := Run(context.Background(), newConverting(t), t.TempDir(), outPath(t), 10*time.Second, nil)
	if err != nil || res.SBOM != nil || !errors.Is(res.SBOMErr, sbom.ErrTooLarge) {
		t.Fatalf("SBOM %q, SBOMErr %v, err %v: want ErrTooLarge", res.SBOM, res.SBOMErr, err)
	}
}

func TestRunFailsWhenTheSARIFConversionFails(t *testing.T) {
	a := newConverting(t)
	a.sarifFlags = []string{"--code", "4", "--no-write"}
	if _, err := Run(context.Background(), a, t.TempDir(), outPath(t), 10*time.Second, nil); err == nil || !strings.Contains(err.Error(), "4") {
		t.Fatalf("err = %v, want the conversion's exit code", err)
	}
}

func TestRunFailsWhenTheScanItselfFailsBeforeAnyConversion(t *testing.T) {
	a := newConverting(t)
	a.flags = []string{"--code", "1", "--no-write"}
	res, err := Run(context.Background(), a, t.TempDir(), outPath(t), 10*time.Second, nil)
	if err == nil || res == nil || res.ExitCode != 1 {
		t.Fatalf("res %+v err %v, want the scan's exit 1", res, err)
	}
}

func TestRunCreatesTheDirectoryOfTheSBOM(t *testing.T) {
	a := newConverting(t)
	a.sbomPath = filepath.Join(t.TempDir(), "deeper", "results.cdx.json")
	res, err := Run(context.Background(), a, t.TempDir(), outPath(t), 10*time.Second, nil)
	if err != nil || res.SBOMErr != nil || res.SBOM == nil {
		t.Fatalf("SBOM %q, SBOMErr %v, err %v", res.SBOM, res.SBOMErr, err)
	}
}
