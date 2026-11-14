package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cybedefend/cybedefend-scanners/internal/adapter"
	"github.com/cybedefend/cybedefend-scanners/internal/fakeapi"
)

// sbomAdapter is testAdapter as trivy-fs is with an SBOM: the scan writes a
// report, which is converted into the SARIF and into the SBOM read from
// *fixture (written by each test, since it names the test's source root).
type sbomAdapter struct {
	testAdapter
	fixture   *string
	sbomPath  string
	sbomFlags []string
}

func (a sbomAdapter) Command(src, out string, env map[string]string) ([]string, bool) {
	if a.sbomPath == "" {
		return a.testAdapter.Command(src, out, env)
	}
	return []string{fakeTool, "--sarif", a.sarif, "--out", out + ".report"}, false
}

func (a sbomAdapter) WithSBOM(path string) adapter.Adapter {
	a.sbomPath = path
	return a
}

func (a sbomAdapter) Conversion(out string) (adapter.Conversion, bool) {
	if a.sbomPath == "" {
		return adapter.Conversion{}, false
	}
	return adapter.Conversion{
		Report:   out + ".report",
		SARIF:    []string{fakeTool, "--sarif", out + ".report", "--out", out},
		SBOM:     append([]string{fakeTool, "--sarif", *a.fixture, "--out", a.sbomPath}, a.sbomFlags...),
		SBOMPath: a.sbomPath,
	}, true
}

var sbomAdapters atomic.Int32

// registerSBOMAdapter registers a fresh sbomAdapter and returns its name and
// the fixture path it reads.
func registerSBOMAdapter(t *testing.T, sbomFlags ...string) (string, *string) {
	t.Helper()
	sarifPath, err := filepath.Abs("../../testdata/sarif/absolute-uri.sarif")
	if err != nil {
		t.Fatal(err)
	}
	name := "test-sbom-" + string(rune('a'+sbomAdapters.Add(1)))
	fixture := new(string)
	adapter.Register(sbomAdapter{testAdapter: testAdapter{name: name, sarif: sarifPath}, fixture: fixture, sbomFlags: sbomFlags})
	return name, fixture
}

// writeSBOMFixture writes a CycloneDX document naming root as Trivy does.
func writeSBOMFixture(t *testing.T, fixture *string, root, specVersion string) {
	t.Helper()
	doc := `{"bomFormat":"CycloneDX","specVersion":"` + specVersion + `","version":1,` +
		`"metadata":{"component":{"bom-ref":"r","type":"application","name":"` + root + `"}},` +
		`"components":[{"bom-ref":"pkg:npm/lodash@4.17.20","type":"library","name":"lodash","version":"4.17.20","purl":"pkg:npm/lodash@4.17.20",` +
		`"properties":[{"name":"aquasecurity:trivy:FilePath","value":"` + root + `/web/package-lock.json"}]}],` +
		`"dependencies":[{"ref":"r","dependsOn":["pkg:npm/lodash@4.17.20"]}]}`
	*fixture = filepath.Join(t.TempDir(), "fixture.cdx.json")
	if err := os.WriteFile(*fixture, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
}

const sbomTop = "repo-0a1b2c"

func scanRunWithSBOM(t *testing.T, api *fakeapi.Server, name string, fixture *string, specVersion string) (int, string, string, string) {
	t.Helper()
	api.SetArchive(sourceZip(t, map[string]string{sbomTop + "/web/package-lock.json": "{}", sbomTop + "/README.md": "r"}))
	src, out := scanRunDirs(t)
	writeSBOMFixture(t, fixture, filepath.Join(src, sbomTop), specVersion)
	var stdout, stderr bytes.Buffer
	code := run([]string{"run", name, "--scan-run", "--source", src, "--out", out}, scanRunEnv(api.URL()+"/api", api.ArchiveURL()), &stdout, &stderr)
	return code, stderr.String(), src, out
}

func TestScanRunSubmitsTheSBOMWithProtocol2(t *testing.T) {
	name, fixture := registerSBOMAdapter(t)
	api := fakeapi.New(scanRunToken)
	defer api.Close()
	code, stderr, src, out := scanRunWithSBOM(t, api, name, fixture, "1.7")
	if code != 0 {
		t.Fatalf("exit %d\nstderr: %s", code, stderr)
	}
	ups := api.Uploads()
	if len(ups) != 1 || ups[0].Protocol != "2" || ups[0].SBOM == nil {
		t.Fatalf("uploads = %+v, want one protocol 2 upload with an SBOM", ups)
	}
	if ups[0].SBOMFilename != "results.cdx.json" || ups[0].SBOMContentType != "application/vnd.cyclonedx+json" {
		t.Errorf("sbom part %q %q", ups[0].SBOMFilename, ups[0].SBOMContentType)
	}
	sent := string(ups[0].SBOM)
	if strings.Contains(sent, src) || strings.Contains(sent, sbomTop) {
		t.Fatalf("the SBOM names the pod's path:\n%s", sent)
	}
	var doc struct {
		Metadata struct {
			Component struct{ Name string } `json:"component"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(ups[0].SBOM, &doc); err != nil || doc.Metadata.Component.Name != "." {
		t.Fatalf("root component = %q (%v), want .", doc.Metadata.Component.Name, err)
	}
	if !strings.Contains(sent, `"web/package-lock.json"`) || !strings.Contains(sent, "pkg:npm/lodash@4.17.20") {
		t.Errorf("the SBOM lost its content:\n%s", sent)
	}
	written, err := os.ReadFile(filepath.Join(filepath.Dir(out), "results.cdx.json"))
	if err != nil || !bytes.Equal(written, ups[0].SBOM) {
		t.Errorf("the SBOM written next to --out (%v) is not the one sent", err)
	}
	if !strings.Contains(stderr, "SBOM: 1 components") {
		t.Errorf("stderr lacks the SBOM count:\n%s", stderr)
	}
	for _, leak := range []string{src, "lodash", "package-lock"} {
		if strings.Contains(stderr, leak) {
			t.Errorf("stderr names %q:\n%s", leak, stderr)
		}
	}
	assertNoCredential(t, api.ArchiveURL(), stderr)
}

func TestScanRunSendsTheSARIFAgainAloneToAnInstanceOlderThanProtocol2(t *testing.T) {
	name, fixture := registerSBOMAdapter(t)
	api := fakeapi.New(scanRunToken)
	defer api.Close()
	api.SetScanProtocols("1")
	code, stderr, _, _ := scanRunWithSBOM(t, api, name, fixture, "1.7")
	if code != 0 {
		t.Fatalf("exit %d\nstderr: %s", code, stderr)
	}
	if got := api.RefusedProtocols(); len(got) != 1 || got[0] != "2" {
		t.Fatalf("refused protocols = %q, want one protocol 2 attempt", got)
	}
	ups := api.Uploads()
	if len(ups) != 1 || ups[0].Protocol != "1" || ups[0].SBOM != nil {
		t.Fatalf("uploads = %+v, want the SARIF alone as protocol 1", ups)
	}
	if strings.Count(stderr, "the instance did not accept the SBOM (SCAN_PROTOCOL_UNSUPPORTED)") != 1 {
		t.Errorf("stderr lacks the one line about the SBOM:\n%s", stderr)
	}
}

// The SBOM never fails the scan: no SBOM, or one the instance cannot read,
// sends the SARIF alone as protocol 1.
func TestScanRunWithoutAUsableSBOMSendsTheSARIFAlone(t *testing.T) {
	for _, c := range []struct {
		name, specVersion, line string
		flags                   []string
	}{
		{"the conversion fails", "1.7", "no SBOM: the SBOM conversion failed with exit code 3", []string{"--code", "3", "--no-write"}},
		{"a version the instance does not read", "1.8", "no SBOM: the SBOM's CycloneDX version", nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			name, fixture := registerSBOMAdapter(t, c.flags...)
			api := fakeapi.New(scanRunToken)
			defer api.Close()
			code, stderr, _, out := scanRunWithSBOM(t, api, name, fixture, c.specVersion)
			if code != 0 {
				t.Fatalf("exit %d\nstderr: %s", code, stderr)
			}
			ups := api.Uploads()
			if len(ups) != 1 || ups[0].Protocol != "1" || ups[0].SBOM != nil {
				t.Fatalf("uploads = %+v, want the SARIF alone", ups)
			}
			if !strings.Contains(stderr, c.line) {
				t.Errorf("stderr lacks %q:\n%s", c.line, stderr)
			}
			// what the tool wrote names the pod's paths: it is not left behind
			if _, err := os.Stat(filepath.Join(filepath.Dir(out), "results.cdx.json")); !os.IsNotExist(err) {
				t.Errorf("an unusable SBOM was left next to --out: %v", err)
			}
		})
	}
}

func TestSBOMOutWritesTheSBOMOfALocalRun(t *testing.T) {
	name, fixture := registerSBOMAdapter(t)
	src := t.TempDir()
	writeSBOMFixture(t, fixture, src, "1.6")
	dir := t.TempDir()
	out, sbomOut := filepath.Join(dir, "results.sarif"), filepath.Join(dir, "sbom", "app.cdx.json")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"run", name, "--source", src, "--out", out, "--sbom-out", sbomOut}, uploadEnv("http://127.0.0.1:1/api"), &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d\nstderr: %s", code, stderr.String())
	}
	data, err := os.ReadFile(sbomOut)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), src) || !strings.Contains(string(data), `"web/package-lock.json"`) {
		t.Fatalf("--sbom-out = %s", data)
	}
}

func TestLocalRunWithoutSBOMOutWritesNoSBOM(t *testing.T) {
	name, fixture := registerSBOMAdapter(t)
	writeSBOMFixture(t, fixture, "/src", "1.6")
	dir := t.TempDir()
	out := filepath.Join(dir, "results.sarif")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"run", name, "--source", t.TempDir(), "--out", out}, uploadEnv("http://127.0.0.1:1/api"), &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d\nstderr: %s", code, stderr.String())
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("files next to --out: %v, want the SARIF alone", entries)
	}
}

func TestSBOMOutOnAnAdapterWithoutSBOMIsAConfigError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"run", "test-sast", "--source", t.TempDir(), "--out", filepath.Join(t.TempDir(), "r.sarif"), "--sbom-out", filepath.Join(t.TempDir(), "s.json")}, uploadEnv("http://127.0.0.1:1/api"), &stdout, &stderr)
	if code != exitConfig || !strings.Contains(stderr.String(), "--sbom-out is only used by trivy-fs") {
		t.Fatalf("exit %d, stderr %s", code, stderr.String())
	}
}

// The instance refuses the SBOM (IMPORT_INVALID_SBOM, token unspent): the
// same SARIF goes again alone as protocol 1, and one line names the code.
func TestScanRunSendsTheSARIFAgainAloneWhenTheInstanceRefusesTheSBOM(t *testing.T) {
	name, fixture := registerSBOMAdapter(t)
	api := fakeapi.New(scanRunToken)
	defer api.Close()
	api.RefuseSBOM()
	code, stderr, _, _ := scanRunWithSBOM(t, api, name, fixture, "1.7")
	if code != 0 {
		t.Fatalf("exit %d\nstderr: %s", code, stderr)
	}
	ups := api.Uploads()
	if len(ups) != 1 || ups[0].Protocol != "1" || ups[0].SBOM != nil {
		t.Fatalf("uploads = %+v, want the SARIF alone as protocol 1", ups)
	}
	if strings.Count(stderr, "the instance did not accept the SBOM (IMPORT_INVALID_SBOM)") != 1 {
		t.Errorf("stderr lacks the one SBOM line:\n%s", stderr)
	}
}
