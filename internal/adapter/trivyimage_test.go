package adapter

import (
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/cybedefend/cybedefend-scanners/internal/sarif"
)

func TestTrivyImageCommandPullsTheReference(t *testing.T) {
	a := TrivyImage{}.WithImage("ghcr.io/acme/api:1.4.2", "")
	argv, onStdout := a.Command("/src", "/tmp/o.sarif", map[string]string{})
	want := []string{
		"trivy", "image", "--scanners", "vuln", "--format", "sarif", "--output", "/tmp/o.sarif",
		"--exit-code", "0", "--cache-dir", "/tmp/cybedefend-scanner/trivy-cache",
		"--skip-version-check", "--disable-telemetry", "--quiet", "ghcr.io/acme/api:1.4.2",
	}
	if !reflect.DeepEqual(argv, want) {
		t.Fatalf("argv = %q\nwant   %q", argv, want)
	}
	if onStdout {
		t.Fatal("sarifOnStdout = true, want false")
	}
	for _, a := range argv {
		if a == "/src" || a == "--input" {
			t.Errorf("argv names %q: %q", a, argv)
		}
	}
}

func TestTrivyImageCommandReadsAnArchive(t *testing.T) {
	a := TrivyImage{}.WithImage("ghcr.io/acme/api:1.4.2", "/out/image.tar")
	argv, _ := a.Command("/src", "/tmp/o.sarif", map[string]string{})
	want := []string{
		"trivy", "image", "--scanners", "vuln", "--format", "sarif", "--output", "/tmp/o.sarif",
		"--exit-code", "0", "--cache-dir", "/tmp/cybedefend-scanner/trivy-cache",
		"--skip-version-check", "--disable-telemetry", "--quiet", "--input", "/out/image.tar",
	}
	if !reflect.DeepEqual(argv, want) {
		t.Fatalf("argv = %q\nwant   %q", argv, want)
	}
	for _, a := range argv {
		if strings.Contains(a, "ghcr.io/acme/api") {
			t.Errorf("the reference is in the argv of an archive scan: %q", argv)
		}
	}
}

func TestTrivyImageTypeExitCodesAndRoot(t *testing.T) {
	var a ImageAdapter = TrivyImage{}
	if got := a.Type(); got != "container" {
		t.Errorf("Type() = %q, want container", got)
	}
	if got := a.Name(); got != "trivy-image" {
		t.Errorf("Name() = %q, want trivy-image", got)
	}
	if got := a.SuccessExitCodes(); !reflect.DeepEqual(got, []int{0}) {
		t.Errorf("SuccessExitCodes() = %v, want [0]", got)
	}
	if got := a.SourceRoot(); got != "/" {
		t.Errorf("SourceRoot() = %q, want /", got)
	}
	bound, ok := a.WithImage("alpine", "").(ImageAdapter)
	if !ok || bound.SourceRoot() != "/" || bound.Type() != TypeContainer {
		t.Errorf("WithImage gave %T", bound)
	}
	reg, ok := Get("trivy-image")
	if !ok {
		t.Fatal("trivy-image is not registered")
	}
	if _, isImage := reg.(ImageAdapter); !isImage {
		t.Fatalf("Get(trivy-image) = %T, not an ImageAdapter", reg)
	}
}

func TestTrivyImageForwardsTrivyKeysAndRegistryCredentials(t *testing.T) {
	want := []string{"TRIVY_DB_REPOSITORY", "TRIVY_JAVA_DB_REPOSITORY", "TRIVY_INSECURE", "TRIVY_USERNAME", "TRIVY_PASSWORD", "TRIVY_REGISTRY_TOKEN"}
	if got := (TrivyImage{}).ForwardedEnv(); !reflect.DeepEqual(got, want) {
		t.Fatalf("ForwardedEnv() = %q, want %q", got, want)
	}
	if got := ToolEnvKeys(TrivyImage{}.WithImage("alpine", "")); !reflect.DeepEqual(got, want) {
		t.Fatalf("ToolEnvKeys of the bound adapter = %q, want %q", got, want)
	}
}

func TestValidImage(t *testing.T) {
	for _, ref := range []string{
		"alpine",
		"ghcr.io/acme/api:1.4.2",
		"registry.example:5000/team/api@sha256:" + strings.Repeat("a", 64),
		"cybedefend-scanners-sample:test",
	} {
		if !ValidImage(ref) {
			t.Errorf("ValidImage(%q) = false, want true", ref)
		}
	}
	for _, ref := range []string{
		"",
		"Ghcr.io/Acme",
		"api:1 ; rm",
		"../../x",
		"-oops",
		"Bad Image",
		strings.Repeat("a", 256),
	} {
		if ValidImage(ref) {
			t.Errorf("ValidImage(%q) = true, want false", ref)
		}
	}
	if !ValidImage(strings.Repeat("a", 255)) {
		t.Error("ValidImage of 255 characters = false, want true")
	}
}

func loadSARIF(t *testing.T, name string) *sarif.Log {
	t.Helper()
	f, err := os.Open("../../testdata/sarif/" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	l, err := sarif.Parse(f)
	if err != nil {
		t.Fatalf("Parse(%s): %v", name, err)
	}
	return l
}

func decodedURIs(t *testing.T, l *sarif.Log) []string {
	t.Helper()
	var uris []string
	for _, run := range l.Runs {
		for _, res := range run.Results {
			for _, loc := range res.Locations {
				u, err := url.PathUnescape(loc.PhysicalLocation.ArtifactLocation.URI)
				if err != nil {
					t.Fatalf("URI %q: %v", loc.PhysicalLocation.ArtifactLocation.URI, err)
				}
				uris = append(uris, u)
			}
		}
	}
	return uris
}

// Trivy writes an image's paths against the image root, not the mounted
// source: normalised against /src, every result would be dropped, and the
// import would then resolve the whole image.
func TestTrivyImageNormalisesAgainstTheImageRoot(t *testing.T) {
	l := loadSARIF(t, "trivy-image.sarif")
	rep := sarif.Normalize(l, sarif.NormalizeOptions{SourceRoot: TrivyImage{}.SourceRoot()})
	if rep.Dropped != 0 {
		t.Fatalf("Dropped = %d, want 0", rep.Dropped)
	}
	want := []string{"app/package-lock.json", "alpine:3.18.0 (alpine 3.18.0)"}
	if got := decodedURIs(t, l); !reflect.DeepEqual(got, want) {
		t.Fatalf("URIs = %q, want %q", got, want)
	}

	l = loadSARIF(t, "trivy-image.sarif")
	if rep := sarif.Normalize(l, sarif.NormalizeOptions{SourceRoot: "/src"}); rep.Dropped != 2 {
		t.Fatalf("against /src: Dropped = %d, want 2 (the failure the image root avoids)", rep.Dropped)
	}
}

// Trivy 0.76.1 writes no ROOTPATH for an image (sarifTarget is empty for a
// container image), reads an image's npm packages from their installed
// package.json (never package-lock.json) and keeps them at their path in the
// image, and names an OS package of an archive scan by the archive's absolute
// path.
func TestTrivyImageNormalisesAnArchiveScan(t *testing.T) {
	l := loadSARIF(t, "trivy-image-input.sarif")
	rep := sarif.Normalize(l, sarif.NormalizeOptions{SourceRoot: TrivyImage{}.SourceRoot()})
	if rep.Dropped != 0 {
		t.Fatalf("Dropped = %d, want 0", rep.Dropped)
	}
	want := []string{"app/node_modules/lodash/package.json", "out/image.tar"}
	if got := decodedURIs(t, l); !reflect.DeepEqual(got, want) {
		t.Fatalf("URIs = %q, want %q", got, want)
	}

	l = loadSARIF(t, "trivy-image-input.sarif")
	if rep := sarif.Normalize(l, sarif.NormalizeOptions{SourceRoot: "/src"}); rep.Dropped != 1 {
		t.Fatalf("against /src: Dropped = %d, want 1", rep.Dropped)
	}
}
