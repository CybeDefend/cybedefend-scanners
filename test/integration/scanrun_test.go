//go:build integration

package integration

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
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
// replaced by `cybedefend-scanner run <adapter> --scan-run`, a read-only root, and
// empty tmpfs at /src and /tmp/cybedefend-scanner. The fake API serves the
// archive and the results route.
func runScanRun(t *testing.T, adapter, sampleDir, network string) (*fakeapi.Server, string, string) {
	t.Helper()
	return runScanRunWith(t, adapter, sampleDir, network, nil)
}

// runScanRunWith is runScanRun with the fake API set up by setup first.
func runScanRunWith(t *testing.T, adapter, sampleDir, network string, setup func(*fakeapi.Server)) (*fakeapi.Server, string, string) {
	t.Helper()
	image := buildImage(t, adapter)
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	api := fakeapi.NewOn(scanRunToken, ln)
	t.Cleanup(api.Close)
	if setup != nil {
		setup(api)
	}
	api.SetArchive(zipDir(t, sampleDir))
	base := "http://127.0.0.1:" + portOf(t, ln.Addr())
	archiveURL := base + "/archive.zip?X-Amz-Signature=integration-signature"

	args := []string{
		"run", "--rm", "--network", network,
		"--read-only",
		"--tmpfs", "/src:uid=65532,gid=65532,mode=0755",
		"--tmpfs", "/tmp/cybedefend-scanner:uid=65532,gid=65532,mode=0755",
		"-e", "CYBEDEFEND_API_URL=" + base + "/api",
		"-e", "CYBEDEFEND_SCAN_ID=" + scanRunScanID,
		"-e", "CYBEDEFEND_SCAN_TOKEN=" + scanRunToken,
		"-e", "CYBEDEFEND_ARCHIVE_URL=" + archiveURL,
		"--entrypoint", "/usr/local/bin/cybedefend-scanner",
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

// assertOneScanRunUpload checks the single upload: the scan, protocol 1, at
// least one result, and paths relative to the repository.
func assertOneScanRunUpload(t *testing.T, api *fakeapi.Server, out, archiveURL string) fakeapi.Upload {
	t.Helper()
	return assertOneScanRunUploadAs(t, api, out, archiveURL, "1")
}

// assertOneScanRunUploadAs is assertOneScanRunUpload with the protocol given.
func assertOneScanRunUploadAs(t *testing.T, api *fakeapi.Server, out, archiveURL, protocol string) fakeapi.Upload {
	t.Helper()
	ups := api.Uploads()
	if len(ups) != 1 {
		t.Fatalf("%d uploads, want 1\n%s", len(ups), out)
	}
	u := ups[0]
	if u.ScanID != scanRunScanID || u.Protocol != protocol || u.Authorization != "Bearer "+scanRunToken {
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
	return u
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

// trivy-fs submits, with its SARIF, the CycloneDX SBOM of the same scan:
// protocol 2, every package with its purl, no path of the pod.
func TestScanRun_TrivyFs(t *testing.T) {
	trivyFsSkip(t)
	api, out, archiveURL := runScanRun(t, "trivy-fs", scanRunSample(t, "sca-npm"), "host")
	u := assertOneScanRunUploadAs(t, api, out, archiveURL, "2")
	assertLodashFinding(t, u.Body)
	if u.SBOMFilename != "results.cdx.json" || u.SBOMContentType != "application/vnd.cyclonedx+json" {
		t.Errorf("sbom part %q %q", u.SBOMFilename, u.SBOMContentType)
	}
	var bom struct {
		BOMFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Metadata    struct {
			Component struct{ Name string } `json:"component"`
		} `json:"metadata"`
		Components []struct {
			Type, Name, Version, Purl string
			Licenses                  []struct {
				License struct{ ID string } `json:"license"`
			} `json:"licenses"`
		} `json:"components"`
		Dependencies []struct {
			Ref       string   `json:"ref"`
			DependsOn []string `json:"dependsOn"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(u.SBOM, &bom); err != nil {
		t.Fatalf("the SBOM does not parse: %v\n%s", err, out)
	}
	if bom.BOMFormat != "CycloneDX" || bom.Metadata.Component.Name != "." {
		t.Errorf("SBOM %s %s, root %q", bom.BOMFormat, bom.SpecVersion, bom.Metadata.Component.Name)
	}
	found := false
	for _, c := range bom.Components {
		if c.Purl == "pkg:npm/lodash@4.17.20" && len(c.Licenses) > 0 && c.Licenses[0].License.ID == "MIT" {
			found = true
		}
	}
	if !found {
		t.Errorf("no lodash 4.17.20 with its MIT license in the SBOM:\n%s", u.SBOM)
	}
	edges := 0
	for _, d := range bom.Dependencies {
		edges += len(d.DependsOn)
	}
	if edges == 0 {
		t.Errorf("the SBOM has no dependency graph:\n%s", u.SBOM)
	}
	for _, leak := range []string{"/src", "/tmp/cybedefend-scanner", archiveTop} {
		if strings.Contains(string(u.SBOM), leak) {
			t.Errorf("the SBOM names %q", leak)
		}
	}
	if !strings.Contains(out, "SBOM: ") || strings.Contains(out, "lodash") {
		t.Errorf("the pod's output lacks the SBOM count, or names a package:\n%s", out)
	}
}

// An instance older than the SBOM refuses protocol 2: the pod sends the same
// SARIF again, as protocol 1, and says so once.
func TestScanRun_TrivyFsToAnInstanceWithoutSBOM(t *testing.T) {
	trivyFsSkip(t)
	api, out, archiveURL := runScanRunWith(t, "trivy-fs", scanRunSample(t, "sca-npm"), "host", func(s *fakeapi.Server) {
		s.SetScanProtocols("1")
	})
	u := assertOneScanRunUpload(t, api, out, archiveURL)
	if u.SBOM != nil {
		t.Errorf("the protocol 1 upload carries an SBOM")
	}
	if got := api.RefusedProtocols(); len(got) != 1 || got[0] != "2" {
		t.Errorf("refused protocols = %q, want [2]", got)
	}
	assertLodashFinding(t, u.Body)
	if strings.Count(out, "the instance did not accept the SBOM (SCAN_PROTOCOL_UNSUPPORTED)") != 1 {
		t.Errorf("the pod's output lacks the one SBOM line:\n%s", out)
	}
}

// The instance refuses the SBOM (IMPORT_INVALID_SBOM): stored nothing, token
// unspent, so the pod sends the same SARIF alone as protocol 1.
func TestScanRun_TrivyFsWhenTheInstanceRefusesTheSBOM(t *testing.T) {
	trivyFsSkip(t)
	api, out, archiveURL := runScanRunWith(t, "trivy-fs", scanRunSample(t, "sca-npm"), "host", func(s *fakeapi.Server) {
		s.RefuseSBOM()
	})
	u := assertOneScanRunUpload(t, api, out, archiveURL)
	if u.SBOM != nil {
		t.Errorf("the protocol 1 upload carries an SBOM")
	}
	assertLodashFinding(t, u.Body)
	if strings.Count(out, "the instance did not accept the SBOM (IMPORT_INVALID_SBOM)") != 1 {
		t.Errorf("the pod's output lacks the one SBOM line:\n%s", out)
	}
}
