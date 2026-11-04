//go:build integration

package integration

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cybedefend/cybedefend-scanners/internal/fakeapi"
)

const (
	scanRunScanID = "6f1c2a9e-1b2c-4d3e-8f00-000000000001"
	scanRunToken  = "cdst_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_AbC"
	// archiveTop is the single folder a GitHub or GitLab archive unpacks under.
	archiveTop = "sample-repo-0a1b2c3d"
)

// zipDir zips dir under archiveTop/, as a forge's source archive.
func zipDir(t *testing.T, dir string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		w, err := zw.Create(archiveTop + "/" + filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		_, err = w.Write(data)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// runScanRun runs the adapter's image as a scanner pod does: entrypoint
// replaced by `appsec-scanner run <adapter> --scan-run`, a read-only root, and
// empty tmpfs at /src and /tmp/appsec-scanner. The fake API serves the
// archive and the results route.
func runScanRun(t *testing.T, adapter, sampleDir, network string) (*fakeapi.Server, string, string) {
	t.Helper()
	image := buildImage(t, adapter)
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	api := fakeapi.NewOn(scanRunToken, ln)
	t.Cleanup(api.Close)
	api.SetArchive(zipDir(t, sampleDir))
	base := "http://127.0.0.1:" + portOf(t, ln.Addr())
	archiveURL := base + "/archive.zip?X-Amz-Signature=integration-signature"

	args := []string{
		"run", "--rm", "--network", network,
		"--read-only",
		"--tmpfs", "/src:uid=65532,gid=65532,mode=0755",
		"--tmpfs", "/tmp/appsec-scanner:uid=65532,gid=65532,mode=0755",
		"-e", "CYBEDEFEND_API_URL=" + base + "/api",
		"-e", "CYBEDEFEND_SCAN_ID=" + scanRunScanID,
		"-e", "CYBEDEFEND_SCAN_TOKEN=" + scanRunToken,
		"-e", "CYBEDEFEND_ARCHIVE_URL=" + archiveURL,
		"--entrypoint", "/usr/local/bin/appsec-scanner",
		image, "run", adapter, "--scan-run",
	}
	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		t.Fatalf("docker run %s: %v\n%s", image, err, out)
	}
	if err != nil {
		t.Fatalf("%s --scan-run: exit %d\n%s", adapter, exitErr.ExitCode(), out)
	}
	return api, string(out), archiveURL
}

// assertOneScanRunUpload checks the single upload: the scan, its protocol,
// at least one result, and paths relative to the repository.
func assertOneScanRunUpload(t *testing.T, api *fakeapi.Server, out, archiveURL string) {
	t.Helper()
	ups := api.Uploads()
	if len(ups) != 1 {
		t.Fatalf("%d uploads, want 1\n%s", len(ups), out)
	}
	u := ups[0]
	if u.ScanID != scanRunScanID || u.Protocol != "1" || u.Authorization != "Bearer "+scanRunToken {
		t.Errorf("upload scan %q protocol %q", u.ScanID, u.Protocol)
	}
	results := sarifResults(t, u.Body)
	if len(results) == 0 {
		t.Fatalf("the upload holds no result\n%s", out)
	}
	for _, r := range results {
		for _, l := range r.Locations {
			uri := l.PhysicalLocation.ArtifactLocation.URI
			if strings.Contains(uri, archiveTop) || strings.HasPrefix(uri, "/") || strings.HasPrefix(uri, "file:") {
				t.Errorf("result %s has a path outside the repository: %q", r.RuleID, uri)
			}
		}
	}
	for _, s := range []string{scanRunToken, archiveURL, "integration-signature"} {
		if strings.Contains(out, s) {
			t.Errorf("the pod's output quotes %q", s)
		}
	}
}

func scanRunSample(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "testdata", "samples", name)
}

func TestScanRun_Opengrep(t *testing.T) {
	requireDocker(t)
	api, out, archiveURL := runScanRun(t, "opengrep", scanRunSample(t, "sast-python"), "host")
	assertOneScanRunUpload(t, api, out, archiveURL)
}

func TestScanRun_Zizmor(t *testing.T) {
	requireDocker(t)
	api, out, archiveURL := runScanRun(t, "zizmor", scanRunSample(t, "cicd-github-actions"), "host")
	assertOneScanRunUpload(t, api, out, archiveURL)
}

func TestScanRun_Gitleaks(t *testing.T) {
	requireDocker(t)
	src := copySecretSample(t)
	appendLine(t, filepath.Join(src, "settings.env"), "STRIPE_KEY="+generateStripeKey(t))
	api, out, archiveURL := runScanRun(t, "gitleaks", src, "host")
	assertOneScanRunUpload(t, api, out, archiveURL)
}

func TestScanRun_TrivyConfig(t *testing.T) {
	requireDocker(t)
	api, out, archiveURL := runScanRun(t, "trivy-config", scanRunSample(t, "iac-terraform"), "host")
	assertOneScanRunUpload(t, api, out, archiveURL)
}

func TestScanRun_TrivyFs(t *testing.T) {
	trivyFsSkip(t)
	api, out, archiveURL := runScanRun(t, "trivy-fs", scanRunSample(t, "sca-npm"), "host")
	assertOneScanRunUpload(t, api, out, archiveURL)
}
