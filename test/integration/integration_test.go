//go:build integration

// Package integration runs the built images against a fake import API.
// Build the images first (`make images`), then:
//
//	CGO_ENABLED=0 go test -count=1 -tags integration ./test/integration/...
//
// The containers run with --network host, so that they reach the fake API on
// the test's loopback address.
package integration

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testProjectID = "00000000-0000-4000-8000-000000000001"
	testToken     = "cdp_integration-test-token"
	testBranch    = "main"
	runTimeout    = 10 * time.Minute
)

// repoRoot is the repository root, from this package's directory.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// requireDocker skips the test when docker is not on PATH.
func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not on PATH")
	}
}

// imageName is the local tag `make images` gives an adapter's image.
func imageName(adapter string) string { return "appsec-scanners-" + adapter + ":dev" }

// buildImage makes sure appsec-scanners-<adapter>:dev exists, building it
// from images/<adapter>/Dockerfile when `make images` did not.
func buildImage(t *testing.T, adapter string) string {
	t.Helper()
	requireDocker(t)
	name := imageName(adapter)
	if exec.Command("docker", "image", "inspect", name).Run() == nil {
		return name
	}
	root := repoRoot(t)
	cmd := exec.Command("docker", "build", "-f", filepath.Join(root, "images", adapter, "Dockerfile"), "-t", name, root)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("docker build %s: %v\n%s", name, err, out)
	}
	return name
}

// upload is one request the fake API received.
type upload struct {
	Authorization string
	UserAgent     string
	Fields        map[string]string
	FileName      string
	// Raw is the file part as sent; SARIF is it decompressed.
	Raw   []byte
	SARIF []byte
}

// fakeAPI is an inline import API until internal/fakeapi exists.
type fakeAPI struct {
	URL     string
	mu      sync.Mutex
	uploads []upload
}

func (f *fakeAPI) Uploads() []upload {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]upload(nil), f.uploads...)
}

// startFakeAPI listens on 0.0.0.0 and answers the import route with 202.
func startFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeAPI{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := "/project/" + testProjectID + "/scan/import/start"
		if r.Method != http.MethodPost || r.URL.Path != want {
			http.Error(w, `{"code":"NOT_FOUND"}`, http.StatusNotFound)
			return
		}
		u, err := readUpload(r)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"code":"IMPORT_INVALID_REQUEST"}`)
			return
		}
		f.mu.Lock()
		f.uploads = append(f.uploads, u)
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"scanId":"11111111-2222-4333-8444-555555555555"}`)
	}))
	srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	f.URL = "http://127.0.0.1:" + portOf(t, ln.Addr())
	return f
}

func portOf(t *testing.T, a net.Addr) string {
	t.Helper()
	_, port, err := net.SplitHostPort(a.String())
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func readUpload(r *http.Request) (upload, error) {
	u := upload{
		Authorization: r.Header.Get("Authorization"),
		UserAgent:     r.Header.Get("User-Agent"),
		Fields:        map[string]string{},
	}
	mr, err := r.MultipartReader()
	if err != nil {
		return u, err
	}
	for {
		p, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return u, err
		}
		data, err := io.ReadAll(io.LimitReader(p, 60<<20))
		if err != nil {
			return u, err
		}
		if p.FormName() == "file" {
			u.FileName = p.FileName()
			u.Raw = data
			continue
		}
		u.Fields[p.FormName()] = string(data)
	}
	if u.Raw == nil {
		return u, errors.New("no file part")
	}
	u.SARIF = u.Raw
	if strings.HasSuffix(u.FileName, ".gz") {
		zr, err := gzip.NewReader(bytes.NewReader(u.Raw))
		if err != nil {
			return u, err
		}
		if u.SARIF, err = io.ReadAll(zr); err != nil {
			return u, err
		}
	}
	return u, nil
}

// runImage runs the adapter's image with sampleDir mounted read-only at /src
// and --upload to fakeAPIURL. extraEnv holds more KEY=VALUE pairs. It returns
// the exit code and the combined output.
func runImage(t *testing.T, adapter, sampleDir, fakeAPIURL string, extraEnv ...string) (int, string) {
	t.Helper()
	image := buildImage(t, adapter)
	src, err := filepath.Abs(sampleDir)
	if err != nil {
		t.Fatal(err)
	}
	args := []string{
		"run", "--rm", "--network", "host",
		"-v", src + ":/src:ro",
		"-e", "CYBEDEFEND_API_URL=" + fakeAPIURL,
		"-e", "CYBEDEFEND_PROJECT_ID=" + testProjectID,
		"-e", "CYBEDEFEND_TOKEN=" + testToken,
		"-e", "CYBEDEFEND_BRANCH=" + testBranch,
	}
	for _, e := range extraEnv {
		args = append(args, "-e", e)
	}
	args = append(args, image, "--upload")

	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err == nil {
		return 0, string(out)
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), string(out)
	}
	t.Fatalf("docker run %s: %v\n%s", image, err, out)
	return -1, ""
}

// sarifResult is the part of a SARIF result the tests read.
type sarifResult struct {
	RuleID    string `json:"ruleId"`
	Locations []struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
		} `json:"physicalLocation"`
	} `json:"locations"`
}

// sarifResults returns every result of every run of data.
func sarifResults(t *testing.T, data []byte) []sarifResult {
	t.Helper()
	var log struct {
		Runs []struct {
			Results []sarifResult `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("the uploaded SARIF is not JSON: %v", err)
	}
	var all []sarifResult
	for _, r := range log.Runs {
		all = append(all, r.Results...)
	}
	return all
}
