package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/cybedefend/cybedefend-scanners/internal/adapter"
	"github.com/cybedefend/cybedefend-scanners/internal/sarif"
)

const testToken = "cdp_test_secret_value_0123456789"

var fakeTool string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "cybedefend-scanner-test-")
	if err != nil {
		panic(err)
	}
	fakeTool = filepath.Join(dir, "faketool")
	build := exec.Command("go", "build", "-o", fakeTool, "../../internal/runner/testdata/faketool")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		panic("build faketool: " + err.Error() + "\n" + string(out))
	}
	sarifPath, err := filepath.Abs("../../testdata/sarif/absolute-uri.sarif")
	if err != nil {
		panic(err)
	}
	adapter.Register(testAdapter{name: "test-sast", sarif: sarifPath})
	adapter.Register(testAdapter{name: "test-broken", sarif: sarifPath, flags: []string{"--code", "2"}})
	imageSARIF, err := filepath.Abs("../../testdata/sarif/trivy-image.sarif")
	if err != nil {
		panic(err)
	}
	adapter.Register(testImageAdapter{name: "test-image", sarif: imageSARIF})
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type testAdapter struct {
	name  string
	sarif string
	flags []string
}

func (a testAdapter) Name() string             { return a.name }
func (a testAdapter) Type() adapter.ImportType { return adapter.TypeSAST }
func (a testAdapter) Command(src, out string, env map[string]string) ([]string, bool) {
	return append([]string{fakeTool, "--sarif", a.sarif, "--out", out}, a.flags...), false
}
func (a testAdapter) SuccessExitCodes() []int { return []int{0, 1} }

type received struct {
	mu        sync.Mutex
	userAgent string
	auth      string
	fields    map[string]string
	sarif     []byte
}

func importServer(t *testing.T, status int, body string) (*httptest.Server, *received) {
	t.Helper()
	rec := &received{fields: map[string]string{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		if r.URL.Path != "/api/project/p1/scan/import/start" {
			http.NotFound(w, r)
			return
		}
		rec.userAgent = r.Header.Get("User-Agent")
		rec.auth = r.Header.Get("Authorization")
		mr, err := r.MultipartReader()
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			data, _ := io.ReadAll(p)
			if p.FormName() == "file" {
				rec.sarif = data
			} else {
				rec.fields[p.FormName()] = string(data)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, rec
}

func uploadEnv(apiURL string) func(string) string {
	env := map[string]string{
		"CYBEDEFEND_API_URL": apiURL, "CYBEDEFEND_PROJECT_ID": "p1",
		"CYBEDEFEND_TOKEN": testToken, "GITHUB_REF_NAME": "main",
		"PATH": os.Getenv("PATH"),
	}
	return func(k string) string { return env[k] }
}

func TestRunUploadsNormalisedSARIF(t *testing.T) {
	srv, rec := importServer(t, 202, `{"scanId":"6f1c2a9e-0000-4000-8000-000000000001"}`)
	out := filepath.Join(t.TempDir(), "results.sarif")
	var stdout, stderr bytes.Buffer
	code := run([]string{"run", "test-sast", "--source", "/src", "--out", out, "--upload"}, uploadEnv(srv.URL+"/api"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if rec.userAgent != "cybedefend-scanner/"+version {
		t.Errorf("User-Agent = %q", rec.userAgent)
	}
	if rec.auth != "Bearer "+testToken {
		t.Errorf("Authorization header not the bearer token")
	}
	if rec.fields["type"] != "sast" || rec.fields["branch"] != "main" || rec.fields["format"] != "sarif" {
		t.Errorf("fields = %v", rec.fields)
	}
	if _, ok := rec.fields["image"]; ok {
		t.Error("an image part was sent for a sast import")
	}
	uris := uploadedURIs(t, rec.sarif)
	if len(uris) != 4 {
		t.Fatalf("URIs = %v, want 4", uris)
	}
	for _, u := range uris {
		if strings.HasPrefix(u, "/") || strings.Contains(u, ":") || strings.HasPrefix(u, ".") {
			t.Errorf("URI %q is not relative", u)
		}
	}
	written, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(written, rec.sarif) {
		t.Error("--out does not hold the uploaded SARIF")
	}
	if !strings.Contains(stdout.String(), "scan 6f1c2a9e-0000-4000-8000-000000000001 queued") {
		t.Errorf("stdout = %q", stdout.String())
	}
	for _, s := range []string{stdout.String(), stderr.String(), string(rec.sarif)} {
		if strings.Contains(s, testToken) {
			t.Error("the token was printed or written")
		}
	}
	if !strings.Contains(stderr.String(), "4 results") || !strings.Contains(stderr.String(), "3 rewritten") || !strings.Contains(stderr.String(), "0 dropped") {
		t.Errorf("stderr lacks the counts: %s", stderr.String())
	}
}

func uploadedURIs(t *testing.T, raw []byte) []string {
	t.Helper()
	var l struct {
		Runs []struct {
			Results []struct {
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI       string `json:"uri"`
							URIBaseID string `json:"uriBaseId"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &l); err != nil {
		t.Fatalf("uploaded SARIF: %v", err)
	}
	var uris []string
	for _, r := range l.Runs {
		for _, res := range r.Results {
			for _, loc := range res.Locations {
				uris = append(uris, loc.PhysicalLocation.ArtifactLocation.URI)
			}
		}
	}
	return uris
}

func TestRunWithoutUploadMakesNoRequest(t *testing.T) {
	srv, rec := importServer(t, 202, `{"scanId":"x"}`)
	out := filepath.Join(t.TempDir(), "results.sarif")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"run", "test-sast", "--out", out}, uploadEnv(srv.URL+"/api"), &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if rec.sarif != nil {
		t.Error("a request was made without --upload")
	}
	if _, err := os.Stat(out); err != nil {
		t.Errorf("no SARIF at --out: %v", err)
	}
}

func TestRunExitCodes(t *testing.T) {
	out := func() string { return filepath.Join(t.TempDir(), "results.sarif") }

	var stdout, stderr bytes.Buffer
	if code := run([]string{"run", "no-such-adapter", "--out", out()}, uploadEnv("http://unused/api"), &stdout, &stderr); code != 4 {
		t.Errorf("unknown adapter: exit %d, want 4", code)
	}
	if !strings.Contains(stderr.String(), "test-sast") {
		t.Errorf("unknown adapter: the known adapters are not listed: %s", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"run", "test-sast", "--upload", "--out", out()}, func(string) string { return "" }, &stdout, &stderr); code != 4 {
		t.Errorf("missing configuration: exit %d, want 4", code)
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"run", "test-broken", "--out", out()}, uploadEnv("http://unused/api"), &stdout, &stderr); code != 2 {
		t.Errorf("tool failure: exit %d, want 2", code)
	}

	srv, _ := importServer(t, 401, `{"message":"jwt expired for `+testToken+`"}`)
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"run", "test-sast", "--upload", "--out", out()}, uploadEnv(srv.URL+"/api"), &stdout, &stderr); code != 3 {
		t.Errorf("401: exit %d, want 3", code)
	}
	if !strings.Contains(stderr.String(), "The token was refused: it may be expired or revoked. Create a new personal access token.") {
		t.Errorf("401: stderr = %q", stderr.String())
	}
	if strings.Contains(stderr.String()+stdout.String(), testToken) || strings.Contains(stderr.String(), "jwt expired") {
		t.Error("401: the server's message or the token was printed")
	}

	stdout.Reset()
	stderr.Reset()
	if code := run(nil, uploadEnv(""), &stdout, &stderr); code != 4 {
		t.Errorf("no command: exit %d, want 4", code)
	}
	if code := run([]string{"frobnicate"}, uploadEnv(""), &stdout, &stderr); code != 4 {
		t.Errorf("unknown command: exit %d, want 4", code)
	}
}

func TestRunRefusesInvalidSARIFWithExit3(t *testing.T) {
	bad, err := filepath.Abs("../../testdata/sarif/not-json.txt")
	if err != nil {
		t.Fatal(err)
	}
	adapter.Register(testAdapter{name: "test-bad-sarif", sarif: bad})
	var stdout, stderr bytes.Buffer
	if code := run([]string{"run", "test-bad-sarif", "--out", filepath.Join(t.TempDir(), "r.sarif")}, uploadEnv(""), &stdout, &stderr); code != 3 {
		t.Fatalf("exit %d, want 3: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "IMPORT_INVALID_SARIF") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

func TestScanIDIsPrintedOnlyWhenItLooksLikeAnID(t *testing.T) {
	srv, _ := importServer(t, 202, `{"scanId":"\u001b[31mevil"}`)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"run", "test-sast", "--upload", "--out", filepath.Join(t.TempDir(), "r.sarif")}, uploadEnv(srv.URL+"/api"), &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "\u001b") || !strings.Contains(stdout.String(), "scan queued") {
		t.Errorf("stdout = %q", stdout.String())
	}
}

func TestVersionPrintsTheBuildVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"version"}, uploadEnv(""), &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if strings.TrimSpace(stdout.String()) != "cybedefend-scanner dev" {
		t.Fatalf("stdout = %q, want the default version dev", stdout.String())
	}

	bin := filepath.Join(t.TempDir(), "cybedefend-scanner")
	build := exec.Command("go", "build", "-ldflags", "-X main.version=1.2.3", "-o", bin, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	got, err := exec.Command(bin, "version").Output()
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	if strings.TrimSpace(string(got)) != "cybedefend-scanner 1.2.3" {
		t.Fatalf("version = %q", got)
	}
}

// testImageAdapter is an ImageAdapter whose fake tool writes a Trivy image SARIF.
type testImageAdapter struct {
	name           string
	sarif          string
	image, archive string
}

func (a testImageAdapter) Name() string             { return a.name }
func (a testImageAdapter) Type() adapter.ImportType { return adapter.TypeContainer }
func (a testImageAdapter) Command(src, out string, env map[string]string) ([]string, bool) {
	return []string{fakeTool, "--sarif", a.sarif, "--out", out}, false
}
func (a testImageAdapter) SuccessExitCodes() []int { return []int{0} }
func (a testImageAdapter) SourceRoot() string      { return "/" }
func (a testImageAdapter) WithImage(image, archive string) adapter.Adapter {
	a.image, a.archive = image, archive
	return a
}

// withEnv adds keys to an environment.
func withEnv(base func(string) string, extra map[string]string) func(string) string {
	return func(k string) string {
		if v, ok := extra[k]; ok {
			return v
		}
		return base(k)
	}
}

func TestRunTrivyImageWithoutImageIsAConfigError(t *testing.T) {
	srv, rec := importServer(t, 202, `{"scanId":"x"}`)
	var stdout, stderr bytes.Buffer
	code := run([]string{"run", "trivy-image", "--upload", "--out", filepath.Join(t.TempDir(), "r.sarif")}, uploadEnv(srv.URL+"/api"), &stdout, &stderr)
	if code != 4 {
		t.Fatalf("exit %d, want 4: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "CYBEDEFEND_IMAGE") {
		t.Errorf("stderr does not name CYBEDEFEND_IMAGE: %q", stderr.String())
	}
	if rec.sarif != nil || rec.fields["type"] != "" {
		t.Error("a request was made")
	}
}

func TestRunTrivyImageWithAnInvalidImageIsAConfigError(t *testing.T) {
	srv, rec := importServer(t, 202, `{"scanId":"x"}`)
	var stdout, stderr bytes.Buffer
	env := withEnv(uploadEnv(srv.URL+"/api"), map[string]string{"CYBEDEFEND_IMAGE": "Bad Image"})
	code := run([]string{"run", "trivy-image", "--upload", "--out", filepath.Join(t.TempDir(), "r.sarif")}, env, &stdout, &stderr)
	if code != 4 {
		t.Fatalf("exit %d, want 4: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "CYBEDEFEND_IMAGE") {
		t.Errorf("stderr does not name CYBEDEFEND_IMAGE: %q", stderr.String())
	}
	if rec.sarif != nil || rec.fields["type"] != "" {
		t.Error("a request was made")
	}
}

func TestRunImageOnAnotherAdapterIsAConfigError(t *testing.T) {
	srv, rec := importServer(t, 202, `{"scanId":"x"}`)
	var stdout, stderr bytes.Buffer
	env := withEnv(uploadEnv(srv.URL+"/api"), map[string]string{"CYBEDEFEND_IMAGE": "x:1"})
	code := run([]string{"run", "test-sast", "--upload", "--out", filepath.Join(t.TempDir(), "r.sarif")}, env, &stdout, &stderr)
	if code != 4 {
		t.Fatalf("exit %d, want 4: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "CYBEDEFEND_IMAGE is only used by trivy-image") {
		t.Errorf("stderr = %q", stderr.String())
	}
	if rec.sarif != nil {
		t.Error("a request was made")
	}
	// A real adapter of this repository, and --image instead of the variable.
	stderr.Reset()
	code = run([]string{"run", "trivy-fs", "--image", "x:1", "--out", filepath.Join(t.TempDir(), "r.sarif")}, uploadEnv(srv.URL+"/api"), &stdout, &stderr)
	if code != 4 || !strings.Contains(stderr.String(), "CYBEDEFEND_IMAGE is only used by trivy-image") {
		t.Errorf("trivy-fs with --image: exit %d, stderr %q", code, stderr.String())
	}
}

func TestRunUploadsTheImagePart(t *testing.T) {
	srv, rec := importServer(t, 202, `{"scanId":"6f1c2a9e-0000-4000-8000-000000000002"}`)
	out := filepath.Join(t.TempDir(), "results.sarif")
	var stdout, stderr bytes.Buffer
	env := withEnv(uploadEnv(srv.URL+"/api"), map[string]string{"CYBEDEFEND_IMAGE": "ghcr.io/acme/api:1.4.2"})
	code := run([]string{"run", "test-image", "--upload", "--out", out}, env, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if rec.fields["type"] != "container" {
		t.Errorf("type = %q, want container", rec.fields["type"])
	}
	if rec.fields["image"] != "ghcr.io/acme/api:1.4.2" {
		t.Errorf("image = %q, want the configured reference", rec.fields["image"])
	}
	uris := uploadedURIs(t, rec.sarif)
	if len(uris) != 2 || uris[0] != "app/package-lock.json" {
		t.Fatalf("URIs = %q, want both results, app/package-lock.json first", uris)
	}
	if !strings.Contains(stderr.String(), "0 dropped") {
		t.Errorf("stderr lacks 0 dropped: %s", stderr.String())
	}
	var l struct {
		Runs []struct {
			Properties map[string]any `json:"properties"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(rec.sarif, &l); err != nil {
		t.Fatal(err)
	}
	if len(l.Runs) != 1 || l.Runs[0].Properties["imageName"] != "alpine:3.18.0" || l.Runs[0].Properties["imageID"] == nil {
		t.Errorf("run properties not kept: %+v", l.Runs)
	}
}

// rewritingAdapter is testAdapter with a SARIFRewriter that renames rule A.
type rewritingAdapter struct {
	testAdapter
	src *string
}

func (a rewritingAdapter) RewriteSARIF(l *sarif.Log, src string, env map[string]string) int {
	*a.src = src
	return sarif.RenameRuleIDs(l, func(*sarif.Run) func(string) (string, bool) {
		return func(id string) (string, bool) { return "plain-" + id, id == "A" }
	})
}

func TestRunAppliesTheAdaptersSARIFRewriterBeforeUpload(t *testing.T) {
	var gotSrc string
	sarifPath, err := filepath.Abs("../../testdata/sarif/absolute-uri.sarif")
	if err != nil {
		t.Fatal(err)
	}
	adapter.Register(rewritingAdapter{testAdapter: testAdapter{name: "test-rewriter", sarif: sarifPath}, src: &gotSrc})
	srv, rec := importServer(t, 202, `{"scanId":"s1"}`)
	out := filepath.Join(t.TempDir(), "results.sarif")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"run", "test-rewriter", "--source", "/src", "--out", out, "--upload"}, uploadEnv(srv.URL+"/api"), &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d\nstderr: %s", code, stderr.String())
	}
	if gotSrc != "/src" {
		t.Errorf("RewriteSARIF got src %q, want /src", gotSrc)
	}
	var log struct {
		Runs []struct {
			Results []struct {
				RuleID string `json:"ruleId"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(rec.sarif, &log); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range log.Runs[0].Results {
		got = append(got, r.RuleID)
	}
	if strings.Join(got, ",") != "plain-A,B,C,D" {
		t.Errorf("uploaded ruleIds = %q, want plain-A,B,C,D", got)
	}
	if !strings.Contains(stderr.String(), "rewrote 1 values of the SARIF") {
		t.Errorf("stderr lacks the rewrite count: %s", stderr.String())
	}
}
