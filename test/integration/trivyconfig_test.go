//go:build integration

package integration

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// trivyConfigImage is what `make images` builds from images/trivy-config.
const trivyConfigImage = "cybedefend-scanners/trivy-config:dev"

// TestTrivyConfigImageOffline runs the image with no network at all: the
// scan must work on Trivy's embedded checks alone.
func TestTrivyConfigImageOffline(t *testing.T) {
	tcRequireImage(t)
	outDir := tcWritableDir(t)

	out, err := tcDocker(t, "run", "--rm", "--network", "none",
		"-v", tcSample(t)+":/src:ro",
		"-v", outDir+":/out",
		trivyConfigImage, "--out", "/out/results.sarif")
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}

	data := readScannerOutput(t, trivyConfigImage, outDir, "results.sarif")
	results, rulesWithSeverity := tcResults(t, data)
	tcExpectResult(t, results, regexp.MustCompile(`(?i)aws-?0107`), "main.tf")
	tcExpectResult(t, results, regexp.MustCompile(`(?i)ds-?0002`), "Dockerfile")
	if rulesWithSeverity == 0 {
		t.Error(`no rule carries properties["security-severity"]`)
	}
}

// TestTrivyConfigImageUploads uploads the normalised SARIF as type=iac.
func TestTrivyConfigImageUploads(t *testing.T) {
	tcRequireImage(t)
	api := tcStartFakeAPI(t)

	out, err := tcDocker(t, "run", "--rm",
		"--add-host", "host.docker.internal:host-gateway",
		"-v", tcSample(t)+":/src:ro",
		"-e", "CYBEDEFEND_API_URL="+api.url,
		"-e", "CYBEDEFEND_PROJECT_ID=11111111-2222-3333-4444-555555555555",
		"-e", "CYBEDEFEND_TOKEN=cdp_integration-test-token",
		"-e", "CYBEDEFEND_BRANCH=main",
		trivyConfigImage, "--upload")
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "cdp_integration-test-token") {
		t.Fatal("the token was printed")
	}

	uploads := api.received()
	if len(uploads) != 1 {
		t.Fatalf("the fake API received %d uploads, want 1\n%s", len(uploads), out)
	}
	u := uploads[0]
	if u.fields["type"] != "iac" {
		t.Errorf("type = %q, want iac", u.fields["type"])
	}
	if u.fields["branch"] != "main" || u.fields["format"] != "sarif" {
		t.Errorf("branch = %q, format = %q", u.fields["branch"], u.fields["format"])
	}
	if _, ok := u.fields["image"]; ok {
		t.Error("an iac upload carries an image part")
	}
	results, _ := tcResults(t, u.sarif)
	tcExpectResult(t, results, regexp.MustCompile(`(?i)aws-?0107`), "main.tf")
	if bytes.Contains(u.sarif, []byte("cdp_integration-test-token")) {
		t.Fatal("the token is in the uploaded SARIF")
	}
}

type tcResult struct {
	ruleID string
	uris   []string
}

// tcResults reads every result's ruleId and URIs, and counts the rules that
// carry a security-severity.
func tcResults(t *testing.T, data []byte) ([]tcResult, int) {
	t.Helper()
	var log struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						Properties map[string]any `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("the SARIF is not JSON: %v", err)
	}
	var results []tcResult
	withSeverity := 0
	for _, run := range log.Runs {
		for _, rule := range run.Tool.Driver.Rules {
			if _, ok := rule.Properties["security-severity"]; ok {
				withSeverity++
			}
		}
		for _, r := range run.Results {
			res := tcResult{ruleID: r.RuleID}
			for _, l := range r.Locations {
				res.uris = append(res.uris, l.PhysicalLocation.ArtifactLocation.URI)
			}
			results = append(results, res)
		}
	}
	return results, withSeverity
}

func tcExpectResult(t *testing.T, results []tcResult, rule *regexp.Regexp, uri string) {
	t.Helper()
	for _, r := range results {
		if !rule.MatchString(r.ruleID) {
			continue
		}
		for _, u := range r.uris {
			if u == uri {
				return
			}
		}
	}
	t.Errorf("no result matching %s at %s among %+v", rule, uri, results)
}

func tcRequireImage(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not on PATH")
	}
	if out, err := exec.Command("docker", "image", "inspect", trivyConfigImage).CombinedOutput(); err != nil {
		t.Fatalf("%s is not built (run `make images`): %v\n%s", trivyConfigImage, err, out)
	}
}

func tcDocker(t *testing.T, args ...string) ([]byte, error) {
	t.Helper()
	cmd := exec.Command("docker", args...)
	done := make(chan struct{})
	var out []byte
	var err error
	go func() { out, err = cmd.CombinedOutput(); close(done) }()
	select {
	case <-done:
		return out, err
	case <-time.After(5 * time.Minute):
		_ = cmd.Process.Kill()
		<-done
		t.Fatalf("docker %s timed out", strings.Join(args, " "))
		return nil, nil
	}
}

// tcSample is the absolute path of the Terraform and Dockerfile sample.
func tcSample(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	dir, err := filepath.Abs(filepath.Join(filepath.Dir(file), "..", "..", "testdata", "samples", "iac-terraform"))
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// tcWritableDir is a directory the image's user (uid 65532) can write to.
func tcWritableDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	return dir
}

type tcUpload struct {
	fields map[string]string
	sarif  []byte
}

type tcFakeAPI struct {
	url     string
	mu      sync.Mutex
	uploads []tcUpload
}

func (f *tcFakeAPI) received() []tcUpload {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]tcUpload(nil), f.uploads...)
}

// tcStartFakeAPI serves the import route on every interface, reached from
// the container as host.docker.internal.
func tcStartFakeAPI(t *testing.T) *tcFakeAPI {
	t.Helper()
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &tcFakeAPI{url: "http://host.docker.internal:" + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)}
	route := regexp.MustCompile(`^/project/[^/]+/scan/import/start$`)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !route.MatchString(r.URL.Path) {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseMultipartForm(64 << 20); err != nil {
			http.Error(w, `{"code":"IMPORT_INVALID_REQUEST"}`, http.StatusBadRequest)
			return
		}
		u := tcUpload{fields: map[string]string{}}
		for k, v := range r.MultipartForm.Value {
			u.fields[k] = v[0]
		}
		if files := r.MultipartForm.File["file"]; len(files) == 1 {
			fh, err := files[0].Open()
			if err == nil {
				var rd io.Reader = fh
				if strings.HasSuffix(files[0].Filename, ".gz") {
					if gz, gzErr := gzip.NewReader(fh); gzErr == nil {
						rd = gz
					}
				}
				u.sarif, _ = io.ReadAll(rd)
				fh.Close()
			}
		}
		f.mu.Lock()
		f.uploads = append(f.uploads, u)
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"scanId":"00000000-0000-0000-0000-000000000001"}`))
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return f
}
