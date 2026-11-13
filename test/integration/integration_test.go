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
	"context"
	"encoding/json"
	"errors"
	"net"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/cybedefend/cybedefend-scanners/internal/fakeapi"
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

// upload is one request the fake API received, as the tests read it.
type upload struct {
	Authorization string
	UserAgent     string
	// Fields holds every non-file part; « image » only when it was sent.
	Fields   map[string]string
	FileName string
	// SARIF is the file part, decompressed.
	SARIF []byte
}

// fakeAPI wraps internal/fakeapi for the tests of this package.
type fakeAPI struct {
	URL string
	srv *fakeapi.Server
}

// Uploads returns what the API accepted, oldest first.
func (f *fakeAPI) Uploads() []upload {
	var out []upload
	for _, u := range f.srv.Uploads() {
		fields := map[string]string{"type": u.Type, "branch": u.Branch, "format": u.Format}
		for _, name := range u.Fields {
			if name == "image" {
				fields["image"] = u.Image
			}
		}
		out = append(out, upload{
			Authorization: u.Authorization,
			UserAgent:     u.UserAgent,
			Fields:        fields,
			FileName:      u.Filename,
			SARIF:         u.Body,
		})
	}
	return out
}

// startFakeAPI listens on 0.0.0.0, so that a container on the host network
// reaches it, and accepts the test token.
func startFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := fakeapi.NewOn(testToken, ln)
	t.Cleanup(srv.Close)
	return &fakeAPI{URL: "http://127.0.0.1:" + portOf(t, ln.Addr()), srv: srv}
}

func portOf(t *testing.T, a net.Addr) string {
	t.Helper()
	_, port, err := net.SplitHostPort(a.String())
	if err != nil {
		t.Fatal(err)
	}
	return port
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

// readScannerOutput reads a file the scanner wrote into dir, mounted at /out.
// The scanner writes it as uid 65532 with mode 0600, as a SARIF may hold
// sensitive findings: on Linux the host's user cannot open it, so it is read
// from a container of the same image, as that user.
func readScannerOutput(t *testing.T, image, dir, name string) []byte {
	t.Helper()
	out, err := exec.Command("docker", "run", "--rm", "--network", "none",
		"-v", dir+":/out:ro", "--entrypoint", "cat", image, "/out/"+name).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			t.Fatalf("read /out/%s from %s: %v\n%s", name, image, err, ee.Stderr)
		}
		t.Fatalf("read /out/%s from %s: %v", name, image, err)
	}
	return out
}
