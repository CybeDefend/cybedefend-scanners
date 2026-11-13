//go:build integration

package integration

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
)

const trivyFsImage = "appsec-scanners-trivy-fs:dev"

// trivyFsSkip skips when the test cannot download Trivy's database or run docker.
func trivyFsSkip(t *testing.T) {
	t.Helper()
	if os.Getenv("APPSEC_SCANNERS_NO_NETWORK") == "1" {
		t.Skip("APPSEC_SCANNERS_NO_NETWORK=1: trivy-fs downloads its vulnerability database")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not on PATH")
	}
}

func trivyFsSample(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs("../../testdata/samples/sca-npm")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// trivyFsRun runs the image with the sample at /src (read-only) and outDir at
// /out, and returns the exit code and the combined output.
func trivyFsRun(t *testing.T, outDir string, env []string, args ...string) (int, string) {
	t.Helper()
	argv := []string{"run", "--rm", "--network", "host",
		"-v", trivyFsSample(t) + ":/src:ro",
		"-v", outDir + ":/out"}
	for _, e := range env {
		argv = append(argv, "-e", e)
	}
	argv = append(argv, trivyFsImage)
	argv = append(argv, args...)
	cmd := exec.Command("docker", argv...)
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("docker run: %v\n%s", err, out)
		}
		code = ee.ExitCode()
	}
	return code, string(out)
}

// writableDir is a temp dir uid 65532 can write to.
func writableDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0o777); err != nil {
		t.Fatal(err)
	}
	return d
}

type trivyFsSARIF struct {
	Runs []struct {
		Tool struct {
			Driver struct {
				Rules []struct {
					ID         string `json:"id"`
					Properties struct {
						Tags []string `json:"tags"`
					} `json:"properties"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID  string `json:"ruleId"`
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
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

// assertLodashFinding checks the CVE-2021-23337 result the sample must give.
func assertLodashFinding(t *testing.T, raw []byte) {
	t.Helper()
	var log trivyFsSARIF
	if err := json.Unmarshal(raw, &log); err != nil {
		t.Fatalf("the SARIF does not parse: %v", err)
	}
	for _, run := range log.Runs {
		tags := map[string][]string{}
		for _, r := range run.Tool.Driver.Rules {
			tags[r.ID] = r.Properties.Tags
		}
		for _, res := range run.Results {
			if res.RuleID != "CVE-2021-23337" {
				continue
			}
			if len(res.Locations) == 0 || res.Locations[0].PhysicalLocation.ArtifactLocation.URI != "package-lock.json" {
				t.Errorf("CVE-2021-23337 locations = %+v, want package-lock.json", res.Locations)
			}
			if tg := tags[res.RuleID]; len(tg) == 0 || tg[0] != "vulnerability" {
				t.Errorf("rule CVE-2021-23337 tags = %q, want vulnerability first", tg)
			}
			if !strings.HasPrefix(res.Message.Text, "Package: lodash\nInstalled Version: 4.17.20\n") {
				t.Errorf("message = %q", res.Message.Text)
			}
			return
		}
	}
	t.Fatalf("no CVE-2021-23337 result in the SARIF:\n%s", raw)
}

var zeroDropped = regexp.MustCompile(`normalised: \d+ results, \d+ rewritten, 0 dropped`)

func TestTrivyFsImageOnNpmSample(t *testing.T) {
	trivyFsSkip(t)
	out := writableDir(t)
	code, output := trivyFsRun(t, out, nil, "--out", "/out/results.sarif")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, output)
	}
	if !zeroDropped.MatchString(output) {
		t.Errorf("the normalise report did not log 0 dropped:\n%s", output)
	}
	raw := readScannerOutput(t, trivyFsImage, out, "results.sarif")
	assertLodashFinding(t, raw)
}

// trivyFsUpload is one request the inline import API received.
type trivyFsUpload struct {
	fields   map[string][]string
	fileName string
	file     []byte
	auth     string
}

func TestTrivyFsImageUploads(t *testing.T) {
	trivyFsSkip(t)
	var (
		mu      sync.Mutex
		uploads []trivyFsUpload
	)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/project/11111111-2222-3333-4444-555555555555/scan/import/start" {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseMultipartForm(64 << 20); err != nil {
			http.Error(w, `{"code":"IMPORT_INVALID_REQUEST"}`, http.StatusBadRequest)
			return
		}
		up := trivyFsUpload{fields: r.MultipartForm.Value, auth: r.Header.Get("Authorization")}
		if fh := r.MultipartForm.File["file"]; len(fh) == 1 {
			up.fileName = fh[0].Filename
			f, err := fh[0].Open()
			if err == nil {
				up.file, _ = io.ReadAll(f)
				f.Close()
			}
		}
		mu.Lock()
		uploads = append(uploads, up)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"scanId":"0a1b2c3d-0000-4000-8000-000000000001"}`))
	}))
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	srv.Listener = ln
	srv.Start()
	defer srv.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	env := []string{
		"CYBEDEFEND_API_URL=http://127.0.0.1:" + strconv.Itoa(port) + "/api",
		"CYBEDEFEND_PROJECT_ID=11111111-2222-3333-4444-555555555555",
		"CYBEDEFEND_TOKEN=cdp_integration_test_token",
		"CYBEDEFEND_BRANCH=main",
	}
	code, output := trivyFsRun(t, writableDir(t), env, "--upload")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, output)
	}
	if strings.Contains(output, "cdp_integration_test_token") {
		t.Error("the token was printed")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(uploads) != 1 {
		t.Fatalf("%d uploads, want 1", len(uploads))
	}
	up := uploads[0]
	if got := up.fields["type"]; len(got) != 1 || got[0] != "sca" {
		t.Errorf("type = %q, want sca", got)
	}
	if got := up.fields["branch"]; len(got) != 1 || got[0] != "main" {
		t.Errorf("branch = %q, want main", got)
	}
	if got := up.fields["format"]; len(got) != 1 || got[0] != "sarif" {
		t.Errorf("format = %q, want sarif", got)
	}
	if _, has := up.fields["image"]; has {
		t.Errorf("an image field was sent with type sca: %q", up.fields["image"])
	}
	if up.auth != "Bearer cdp_integration_test_token" {
		t.Error("the Authorization header is not the bearer token")
	}
	file := up.file
	if strings.HasSuffix(up.fileName, ".gz") {
		zr, err := gzip.NewReader(bytes.NewReader(file))
		if err != nil {
			t.Fatal(err)
		}
		if file, err = io.ReadAll(zr); err != nil {
			t.Fatal(err)
		}
	}
	if bytes.Contains(file, []byte("cdp_integration_test_token")) {
		t.Error("the token is in the uploaded SARIF")
	}
	assertLodashFinding(t, file)
}
