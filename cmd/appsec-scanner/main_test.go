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
)

const testToken = "cdp_test_secret_value_0123456789"

var fakeTool string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "appsec-scanner-test-")
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
	if rec.userAgent != "appsec-scanner/"+version {
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
	if strings.TrimSpace(stdout.String()) != "appsec-scanner dev" {
		t.Fatalf("stdout = %q, want the default version dev", stdout.String())
	}

	bin := filepath.Join(t.TempDir(), "appsec-scanner")
	build := exec.Command("go", "build", "-ldflags", "-X main.version=1.2.3", "-o", bin, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	got, err := exec.Command(bin, "version").Output()
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	if strings.TrimSpace(string(got)) != "appsec-scanner 1.2.3" {
		t.Fatalf("version = %q", got)
	}
}
