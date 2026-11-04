package main

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cybedefend/cybedefend-scanners/internal/adapter"
	"github.com/cybedefend/cybedefend-scanners/internal/fakeapi"
	"github.com/cybedefend/cybedefend-scanners/internal/upload"
)

const (
	scanRunToken  = "cdst_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_AbC"
	scanRunID     = "6f1c2a9e-1b2c-4d3e-8f00-000000000001"
	archiveSecret = "X-Amz-Signature=not-a-real-signature"
)

// sourceZip builds a zip of the given files (name → body).
func sourceZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(w, body)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// scanRunEnv is a pod's environment for the archive and API URLs.
func scanRunEnv(apiURL, archiveURL string) func(string) string {
	env := map[string]string{
		"CYBEDEFEND_API_URL": apiURL, "CYBEDEFEND_SCAN_ID": scanRunID,
		"CYBEDEFEND_SCAN_TOKEN": scanRunToken, "CYBEDEFEND_ARCHIVE_URL": archiveURL,
		"PATH": os.Getenv("PATH"),
	}
	return func(k string) string { return env[k] }
}

// scanRunDirs returns an empty --source and an --out in a fresh directory.
func scanRunDirs(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "src"), filepath.Join(dir, "out", "results.sarif")
}

// results answers every results upload with status and body, and counts them.
func results(t *testing.T, archive []byte, status int, body string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/archive.zip" {
			_, _ = w.Write(archive)
			return
		}
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

// assertNoCredential fails when the output quotes the token, the archive URL or its query.
func assertNoCredential(t *testing.T, archiveURL string, outputs ...string) {
	t.Helper()
	for _, out := range outputs {
		for _, s := range []string{scanRunToken, "cdst_", archiveURL, archiveSecret, "X-Amz-Signature", "/archive.zip"} {
			if strings.Contains(out, s) {
				t.Errorf("the output quotes %q:\n%s", s, out)
			}
		}
	}
}

func TestScanRunSubmitsTheNormalisedSARIF(t *testing.T) {
	api := fakeapi.New(scanRunToken)
	defer api.Close()
	api.SetArchive(sourceZip(t, map[string]string{"app/main.py": "print(1)\n"}))
	src, out := scanRunDirs(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{"run", "test-sast", "--scan-run", "--source", src, "--out", out}, scanRunEnv(api.URL()+"/api", api.ArchiveURL()), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d\nstderr: %s", code, stderr.String())
	}
	ups := api.Uploads()
	if len(ups) != 1 || ups[0].ScanID != scanRunID || ups[0].Protocol != "1" || ups[0].Authorization != "Bearer "+scanRunToken {
		t.Fatalf("uploads = %+v", ups)
	}
	if ups[0].UserAgent != "appsec-scanner/"+version {
		t.Errorf("User-Agent = %q", ups[0].UserAgent)
	}
	if _, err := os.Stat(filepath.Join(src, "app", "main.py")); err != nil {
		t.Errorf("the archive was not unpacked into --source: %v", err)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(out), "archive-*.zip")); len(left) != 0 {
		t.Errorf("the zip was left behind: %v", left)
	}
	if !strings.Contains(stdout.String(), "results submitted") {
		t.Errorf("stdout = %q", stdout.String())
	}
	assertNoCredential(t, api.ArchiveURL(), stdout.String(), stderr.String())
}

func TestScanRunScansTheArchivesSingleTopFolder(t *testing.T) {
	sarifPath, err := filepath.Abs("../../testdata/sarif/absolute-uri.sarif")
	if err != nil {
		t.Fatal(err)
	}
	var gotSrc string
	adapter.Register(rewritingAdapter{testAdapter: testAdapter{name: "test-scanrun-root", sarif: sarifPath}, src: &gotSrc})

	cases := []struct {
		name  string
		files map[string]string
		top   string
	}{
		{"one top folder", map[string]string{"repo-0a1b2c/app/main.py": "x", "repo-0a1b2c/README.md": "r"}, "repo-0a1b2c"},
		{"several entries", map[string]string{"app/main.py": "x", "README.md": "r"}, ""},
		{"a single file", map[string]string{"main.py": "x"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api := fakeapi.New(scanRunToken)
			defer api.Close()
			api.SetArchive(sourceZip(t, tc.files))
			src, out := scanRunDirs(t)
			var stdout, stderr bytes.Buffer
			if code := run([]string{"run", "test-scanrun-root", "--scan-run", "--source", src, "--out", out}, scanRunEnv(api.URL(), api.ArchiveURL()), &stdout, &stderr); code != 0 {
				t.Fatalf("exit %d\nstderr: %s", code, stderr.String())
			}
			want := filepath.Join(src, tc.top)
			if gotSrc != want {
				t.Errorf("scanned %q, want %q", gotSrc, want)
			}
		})
	}
}

func TestScanRunExit6OnFetchFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "AccessDenied "+archiveSecret, http.StatusForbidden)
	}))
	defer srv.Close()
	archiveURL := srv.URL + "/archive.zip?" + archiveSecret
	src, out := scanRunDirs(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{"run", "test-sast", "--scan-run", "--source", src, "--out", out}, scanRunEnv(srv.URL, archiveURL), &stdout, &stderr)
	if code != 6 {
		t.Fatalf("exit %d, want 6\nstderr: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "the archive could not be fetched") || !strings.Contains(stderr.String(), "HTTP 403") {
		t.Errorf("stderr = %s", stderr.String())
	}
	assertNoCredential(t, archiveURL, stdout.String(), stderr.String())

	// An address nothing listens on.
	stderr.Reset()
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL + "/archive.zip?" + archiveSecret
	dead.Close()
	src, out = scanRunDirs(t)
	if code := run([]string{"run", "test-sast", "--scan-run", "--source", src, "--out", out}, scanRunEnv(srv.URL, deadURL), &stdout, &stderr); code != 6 {
		t.Errorf("unreachable archive: exit %d, want 6\nstderr: %s", code, stderr.String())
	}
	assertNoCredential(t, deadURL, stderr.String())
}

func TestScanRunExit6WhenTheArchiveHangs(t *testing.T) {
	old := fetchDeadline
	fetchDeadline = 300 * time.Millisecond
	t.Cleanup(func() { fetchDeadline = old })
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Headers, then a body that never comes.
		w.Header().Set("Content-Length", "1000000")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer srv.Close()
	defer close(release)
	archiveURL := srv.URL + "/archive.zip?" + archiveSecret
	src, out := scanRunDirs(t)
	var stdout, stderr bytes.Buffer
	start := time.Now()
	code := run([]string{"run", "test-sast", "--scan-run", "--source", src, "--out", out}, scanRunEnv(srv.URL, archiveURL), &stdout, &stderr)
	if code != 6 {
		t.Fatalf("exit %d, want 6\nstderr: %s", code, stderr.String())
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("a hung archive took %v to fail", d)
	}
	assertNoCredential(t, archiveURL, stderr.String())
}

func TestFetchClientIsBounded(t *testing.T) {
	hc := fetchClient()
	tr, ok := hc.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport %T, want *http.Transport", hc.Transport)
	}
	if tr.DialContext == nil || tr.TLSHandshakeTimeout != fetchConnectTimeout || tr.ResponseHeaderTimeout <= 0 {
		t.Errorf("transport is not bounded: TLS %v, headers %v", tr.TLSHandshakeTimeout, tr.ResponseHeaderTimeout)
	}
	if fetchConnectTimeout != 30*time.Second || fetchDeadline != 15*time.Minute {
		t.Errorf("bounds = %v / %v, want 30s / 15m", fetchConnectTimeout, fetchDeadline)
	}
}

func TestScanRunExit5OnProtocolRefusal(t *testing.T) {
	archive := sourceZip(t, map[string]string{"a.py": "x"})
	srv, calls := results(t, archive, 400, `{"statusCode":400,"code":"SCAN_PROTOCOL_UNSUPPORTED","message":"`+scanRunToken+`"}`)
	src, out := scanRunDirs(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{"run", "test-sast", "--scan-run", "--source", src, "--out", out}, scanRunEnv(srv.URL, srv.URL+"/archive.zip?"+archiveSecret), &stdout, &stderr)
	if code != 5 {
		t.Fatalf("exit %d, want 5\nstderr: %s", code, stderr.String())
	}
	if calls.Load() != 1 {
		t.Errorf("results requests = %d, want 1", calls.Load())
	}
	if !strings.Contains(stderr.String(), "scan protocol") {
		t.Errorf("stderr = %s", stderr.String())
	}
	assertNoCredential(t, srv.URL+"/archive.zip?"+archiveSecret, stdout.String(), stderr.String())
}

func TestScanRunOutcomes(t *testing.T) {
	archive := sourceZip(t, map[string]string{"a.py": "x"})
	cases := []struct {
		name     string
		status   int
		body     string
		code     int
		calls    int32
		sentence string
	}{
		{"accepted", 202, `{"accepted":true}`, 0, 1, ""},
		{"already submitted", 409, `{"statusCode":409,"code":"SCAN_RESULTS_ALREADY_SUBMITTED"}`, 0, 1, ""},
		{"token refused", 401, `{"statusCode":401,"code":"SCAN_TOKEN_INVALID","message":"x"}`, 3, 1, "SCAN_TOKEN_INVALID: the instance refused the scan token"},
		{"too large", 413, `{"statusCode":413,"code":"IMPORT_UPLOAD_TOO_LARGE"}`, 3, 1, "IMPORT_UPLOAD_TOO_LARGE: the results are larger than the instance accepts"},
		{"invalid SARIF", 400, `{"statusCode":400,"code":"IMPORT_INVALID_SARIF"}`, 3, 1, "IMPORT_INVALID_SARIF: the instance found the SARIF invalid"},
		{"unsupported file", 400, `{"statusCode":400,"code":"IMPORT_UNSUPPORTED_FILE"}`, 3, 1, "IMPORT_UNSUPPORTED_FILE: the instance refused the results file"},
		{"other 400", 400, `{"statusCode":400}`, 3, 1, "the instance refused the results (HTTP 400)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, calls := results(t, archive, tc.status, tc.body)
			archiveURL := srv.URL + "/archive.zip?" + archiveSecret
			src, out := scanRunDirs(t)
			var stdout, stderr bytes.Buffer
			code := run([]string{"run", "test-sast", "--scan-run", "--source", src, "--out", out}, scanRunEnv(srv.URL+"/api", archiveURL), &stdout, &stderr)
			if code != tc.code {
				t.Fatalf("exit %d, want %d\nstderr: %s", code, tc.code, stderr.String())
			}
			if calls.Load() != tc.calls {
				t.Errorf("results requests = %d, want %d", calls.Load(), tc.calls)
			}
			if tc.sentence != "" && !strings.Contains(stderr.String(), tc.sentence) {
				t.Errorf("stderr lacks %q:\n%s", tc.sentence, stderr.String())
			}
			// A pod's sentences never speak of the import's personal access tokens.
			for _, s := range []string{"personal access token", "start_scan", "Project not found"} {
				if strings.Contains(stderr.String(), s) {
					t.Errorf("stderr speaks of %q:\n%s", s, stderr.String())
				}
			}
			assertNoCredential(t, archiveURL, stdout.String(), stderr.String())
		})
	}
}

func TestScanRunNeverLogsURLOrToken(t *testing.T) {
	// The tool fails: its output is printed, its environment never had the credentials.
	archive := sourceZip(t, map[string]string{"a.py": "x"})
	srv, _ := results(t, archive, 202, `{}`)
	archiveURL := srv.URL + "/archive.zip?" + archiveSecret
	for _, tc := range []struct {
		adapter string
		code    int
	}{{"test-sast", 0}, {"test-broken", 2}} {
		src, out := scanRunDirs(t)
		var stdout, stderr bytes.Buffer
		if code := run([]string{"run", tc.adapter, "--scan-run", "--source", src, "--out", out}, scanRunEnv(srv.URL, archiveURL), &stdout, &stderr); code != tc.code {
			t.Errorf("%s: exit %d, want %d\nstderr: %s", tc.adapter, code, tc.code, stderr.String())
		}
		assertNoCredential(t, archiveURL, stdout.String(), stderr.String())
	}
	// A configuration error.
	var stdout, stderr bytes.Buffer
	env := scanRunEnv("ftp://bad", archiveURL)
	if code := run([]string{"run", "test-sast", "--scan-run"}, env, &stdout, &stderr); code != 4 {
		t.Errorf("bad API URL: exit %d, want 4", code)
	}
	assertNoCredential(t, archiveURL, stdout.String(), stderr.String())
}

func TestScanRunConfigurationErrorsExit4(t *testing.T) {
	env := scanRunEnv("http://127.0.0.1:1/api", "http://127.0.0.1:1/archive.zip")
	for _, args := range [][]string{
		{"run", "trivy-image", "--scan-run"},
		{"run", "test-image", "--scan-run"},
		{"run", "test-sast", "--scan-run", "--upload"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(args, withEnv(env, map[string]string{"CYBEDEFEND_IMAGE": "alpine:3.20"}), &stdout, &stderr); code != 4 {
			t.Errorf("%v: exit %d, want 4\nstderr: %s", args, code, stderr.String())
		}
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"run", "test-sast", "--scan-run"}, func(string) string { return "" }, &stdout, &stderr); code != 4 {
		t.Errorf("no variables: exit %d, want 4", code)
	}
}

func TestScanRunStoppedDuringTheFetchExits3(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000000")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		close(started)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer srv.Close()
	defer close(release)
	archiveURL := srv.URL + "/archive.zip?" + archiveSecret
	src, out := scanRunDirs(t)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-started
		cancel() // SIGTERM: the pod is being stopped.
	}()
	var stdout, stderr bytes.Buffer
	code := runAdapter(ctx, []string{"test-sast", "--scan-run", "--source", src, "--out", out}, scanRunEnv(srv.URL, archiveURL), &stdout, &stderr)
	if code != 3 {
		t.Fatalf("exit %d, want 3\nstderr: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "the scan run was stopped") || strings.Contains(stderr.String(), "could not be fetched") {
		t.Errorf("stderr = %s", stderr.String())
	}
	assertNoCredential(t, archiveURL, stdout.String(), stderr.String())
}

func TestScanRunOutcomeTellsALocalFailureFromATransportOne(t *testing.T) {
	code, local := scanRunOutcome(errors.New("write the file part: short write"))
	if code != 3 || !strings.Contains(local, "the results could not be prepared") || strings.Contains(local, "reach the instance") {
		t.Errorf("local failure: %d %q", code, local)
	}
	transport := fmt.Errorf("send the results request: %w", &url.Error{Op: "Post", URL: "http://x/scan-runs/s/results", Err: errors.New("connection refused")})
	code, sentence := scanRunOutcome(transport)
	if code != 3 || !strings.Contains(sentence, "could not reach the instance") {
		t.Errorf("transport failure: %d %q", code, sentence)
	}
	if strings.Contains(local+sentence, "http://x") || strings.Contains(local, "short write") {
		t.Error("an error's text was printed")
	}
}

func TestScanRunTokenSentenceDoesNotSayUsed(t *testing.T) {
	_, s := scanRunOutcome(upload.ErrScanTokenRefused)
	if strings.Contains(s, "already used") || !strings.HasPrefix(s, "SCAN_TOKEN_INVALID: ") {
		t.Errorf("sentence = %q", s)
	}
}

func TestScanRunPastTheUploadDeadlineExits3Interrupted(t *testing.T) {
	code, sentence := scanRunOutcome(upload.ErrScanRunDeadline)
	if code != 3 {
		t.Errorf("exit %d, want 3", code)
	}
	if sentence != "the results upload was interrupted." {
		t.Errorf("sentence = %q", sentence)
	}
}
