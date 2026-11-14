package adapter

import (
	"reflect"
	"strings"
	"testing"

	"github.com/cybedefend/cybedefend-scanners/internal/sarif"
)

func TestTrivyFsCommand(t *testing.T) {
	argv, onStdout := TrivyFs{}.Command("/src", "/tmp/o.sarif", map[string]string{})
	want := []string{
		"trivy", "fs", "--scanners", "vuln", "--format", "sarif", "--output", "/tmp/o.sarif",
		"--exit-code", "0", "--cache-dir", "/tmp/cybedefend-scanner/trivy-cache",
		"--skip-version-check", "--disable-telemetry", "--quiet", "/src",
	}
	if !reflect.DeepEqual(argv, want) {
		t.Fatalf("argv = %q\nwant   %q", argv, want)
	}
	if onStdout {
		t.Fatal("sarifOnStdout = true, want false")
	}
	// An sca import is the branch's whole dependency picture: the source root
	// is the only target, and nothing under it is skipped.
	targets := 0
	for _, a := range argv {
		if a == "/src" {
			targets++
		}
		if a == "--skip-dirs" || a == "--skip-files" {
			t.Errorf("argv skips part of the source: %q", argv)
		}
	}
	if targets != 1 || argv[len(argv)-1] != "/src" {
		t.Errorf("argv names %d targets, want the source root once, last: %q", targets, argv)
	}
}

func TestTrivyFsScansVulnerabilitiesOnly(t *testing.T) {
	argv, _ := TrivyFs{}.Command("/src", "/tmp/o.sarif", map[string]string{"TRIVY_INSECURE": "true"})
	for _, a := range argv {
		for _, other := range []string{"misconfig", "secret", "license"} {
			if strings.Contains(a, other) {
				t.Errorf("argv element %q names %s", a, other)
			}
		}
	}
}

func TestTrivyFsExitCodesAndType(t *testing.T) {
	if got := (TrivyFs{}).SuccessExitCodes(); !reflect.DeepEqual(got, []int{0}) {
		t.Errorf("SuccessExitCodes() = %v, want [0]", got)
	}
	if got := (TrivyFs{}).Type(); got != "sca" {
		t.Errorf("Type() = %q, want sca", got)
	}
	if got := (TrivyFs{}).Name(); got != "trivy-fs" {
		t.Errorf("Name() = %q, want trivy-fs", got)
	}
	a, ok := Get("trivy-fs")
	if !ok {
		t.Fatal("trivy-fs is not registered")
	}
	if _, isFs := a.(TrivyFs); !isFs {
		t.Fatalf("Get(trivy-fs) = %T", a)
	}
}

func TestTrivyFsForwardsOnlyTrivyKeys(t *testing.T) {
	var f EnvForwarder = TrivyFs{}
	want := []string{"TRIVY_DB_REPOSITORY", "TRIVY_JAVA_DB_REPOSITORY", "TRIVY_INSECURE"}
	got := f.ForwardedEnv()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ForwardedEnv() = %q, want %q", got, want)
	}
	for _, k := range got {
		if strings.HasPrefix(k, "CYBEDEFEND_") {
			t.Errorf("ForwardedEnv() holds %s", k)
		}
	}
}

func TestTrivyCacheDirIsOutsideTheSource(t *testing.T) {
	if TrivyCacheDir != "/tmp/cybedefend-scanner/trivy-cache" {
		t.Fatalf("TrivyCacheDir = %q", TrivyCacheDir)
	}
	if strings.HasPrefix(TrivyCacheDir, "/src") {
		t.Fatal("the cache is under the source root")
	}
}

// legacyKeysOnly has the EnvKeys method of the former second interface:
// EnvForwarder is the only way an adapter declares its tool's keys.
type legacyKeysOnly struct{ stub }

func (legacyKeysOnly) EnvKeys() []string { return []string{"GH_TOKEN"} }

type duplicatedKeys struct{ stub }

func (duplicatedKeys) ForwardedEnv() []string {
	return []string{"GH_TOKEN", "", "GH_TOKEN", "cybedefend_pat"}
}

type forwarderOnly struct{ stub }

func (forwarderOnly) ForwardedEnv() []string {
	return []string{"TRIVY_DB_REPOSITORY", "CYBEDEFEND_TOKEN"}
}

func TestToolEnvKeysReadsEnvForwarderOnlyAndNeverCYBEDEFEND(t *testing.T) {
	if got := ToolEnvKeys(stub{"plain", TypeSAST}); len(got) != 0 {
		t.Errorf("plain adapter: %q", got)
	}
	if got := ToolEnvKeys(legacyKeysOnly{}); len(got) != 0 {
		t.Errorf("an EnvKeys method alone forwarded %q", got)
	}
	if got := ToolEnvKeys(duplicatedKeys{}); !reflect.DeepEqual(got, []string{"GH_TOKEN"}) {
		t.Errorf("duplicates, empty and CYBEDEFEND_* keys: %q", got)
	}
	if got := ToolEnvKeys(forwarderOnly{}); !reflect.DeepEqual(got, []string{"TRIVY_DB_REPOSITORY"}) {
		t.Errorf("EnvForwarder: %q", got)
	}
}

// Maven Central limits requests per IP: past it, Trivy cannot fetch a parent
// POM and fails the whole SCA scan (seen on a local cluster after a few scans
// of a Spring Boot project). trivy-fs then runs once more with --offline-scan,
// which calls no Maven repository: fewer versions resolved, never no result.
func TestTrivyFsFallsBackOfflineOnAMaven429(t *testing.T) {
	maven429 := []byte("2026-11-05T20:53:25Z\tFATAL\tError\tremote Maven repository returned 429 Too Many Requests for https://repo.maven.apache.org/maven2/org/springframework/boot/spring-boot-starter-parent/4.1.1/spring-boot-starter-parent-4.1.1.pom. Retry-After: 1580.\n")
	alt, reason, ok := TrivyFs{}.Fallback(1, maven429)
	if !ok {
		t.Fatal("no fallback on Maven's 429")
	}
	if reason == "" || strings.Contains(reason, "springframework") {
		t.Fatalf("reason = %q, want a fixed sentence that names no package", reason)
	}
	argv, _ := alt.Command("/src", "/tmp/o.sarif", map[string]string{})
	offline := 0
	for _, a := range argv {
		if a == "--offline-scan" {
			offline++
		}
	}
	if offline != 1 || argv[len(argv)-1] != "/src" {
		t.Fatalf("fallback argv = %q, want --offline-scan once and the source last", argv)
	}
	if alt.Name() != "trivy-fs" || alt.Type() != TypeSCA {
		t.Fatalf("fallback is %s/%s, want trivy-fs/sca", alt.Name(), alt.Type())
	}
	// the offline run has no fallback of its own: one retry at most
	if _, _, again := alt.(FallbackAdapter).Fallback(1, maven429); again {
		t.Fatal("the offline run falls back again")
	}
}

func TestTrivyFsKeepsEveryOtherFailure(t *testing.T) {
	for _, tc := range []struct {
		code   int
		output string
	}{
		{1, "FATAL\tError\tunable to initialize the scanner: DB error\n"},
		{1, "FATAL\tError\tremote Maven repository returned 500 Internal Server Error\n"},
		{0, "remote Maven repository returned 429 Too Many Requests\n"},
	} {
		if _, _, ok := (TrivyFs{}).Fallback(tc.code, []byte(tc.output)); ok {
			t.Fatalf("exit %d with %q falls back", tc.code, tc.output)
		}
	}
}

// With an SBOM, trivy-fs scans once and converts that one report twice: Maven
// Central, which limits requests per IP, is called by one scan only.
func TestTrivyFsWithSBOMWritesTrivysJSONReportOnce(t *testing.T) {
	a := TrivyFs{}.WithSBOM("/tmp/cybedefend-scanner/results.cdx.json")
	argv, onStdout := a.Command("/src", "/tmp/cybedefend-scanner/results.sarif", map[string]string{})
	want := []string{
		"trivy", "fs", "--scanners", "vuln", "--format", "json", "--list-all-pkgs",
		"--output", "/tmp/cybedefend-scanner/results.sarif.trivy.json",
		"--exit-code", "0", "--cache-dir", "/tmp/cybedefend-scanner/trivy-cache",
		"--skip-version-check", "--disable-telemetry", "--quiet", "/src",
	}
	if !reflect.DeepEqual(argv, want) || onStdout {
		t.Fatalf("argv = %q (stdout %v)\nwant   %q", argv, onStdout, want)
	}
	conv, ok := a.(ConvertingAdapter).Conversion("/tmp/cybedefend-scanner/results.sarif")
	if !ok {
		t.Fatal("no conversion with an SBOM")
	}
	wantConv := Conversion{
		Report:   "/tmp/cybedefend-scanner/results.sarif.trivy.json",
		SARIF:    []string{"trivy", "convert", "--format", "sarif", "--output", "/tmp/cybedefend-scanner/results.sarif", "--quiet", "/tmp/cybedefend-scanner/results.sarif.trivy.json"},
		SBOM:     []string{"trivy", "convert", "--format", "cyclonedx", "--output", "/tmp/cybedefend-scanner/results.cdx.json", "--quiet", "/tmp/cybedefend-scanner/results.sarif.trivy.json"},
		SBOMPath: "/tmp/cybedefend-scanner/results.cdx.json",
	}
	if !reflect.DeepEqual(conv, wantConv) {
		t.Fatalf("conversion = %+v\nwant         %+v", conv, wantConv)
	}
}

func TestTrivyFsWithoutSBOMWritesSARIFDirectly(t *testing.T) {
	if _, ok := (TrivyFs{}).Conversion("/tmp/o.sarif"); ok {
		t.Fatal("a conversion without an SBOM: the SARIF is written by the scan itself")
	}
	if _, ok := Adapter(TrivyFs{}).(SBOMAdapter); !ok {
		t.Fatal("trivy-fs is not an SBOMAdapter")
	}
}

func TestOnlyTrivyFsWritesAnSBOM(t *testing.T) {
	for _, name := range Names() {
		a, _ := Get(name)
		if _, ok := a.(SBOMAdapter); ok != (name == "trivy-fs") {
			t.Errorf("%s: SBOMAdapter = %v", name, ok)
		}
	}
}

func TestTrivyFsOfflineFallbackKeepsTheSBOM(t *testing.T) {
	maven429 := []byte("FATAL\tremote Maven repository returned 429 Too Many Requests for https://repo.maven.apache.org/x.pom\n")
	a := TrivyFs{}.WithSBOM("/tmp/s.cdx.json").(FallbackAdapter)
	alt, _, ok := a.Fallback(1, maven429)
	if !ok {
		t.Fatal("no fallback")
	}
	argv, _ := alt.Command("/src", "/tmp/o.sarif", map[string]string{})
	joined := strings.Join(argv, " ")
	if !strings.Contains(joined, "--offline-scan") || !strings.Contains(joined, "--format json --list-all-pkgs") {
		t.Fatalf("fallback argv = %q, want the JSON report, offline", argv)
	}
	conv, ok := alt.(ConvertingAdapter).Conversion("/tmp/o.sarif")
	if !ok || conv.SBOMPath != "/tmp/s.cdx.json" {
		t.Fatalf("fallback conversion = %+v, %v: the SBOM was lost", conv, ok)
	}
}

// trivy convert names the JSON report as the SARIF's ROOTPATH: the results
// would resolve against it, so ROOTPATH is set back to the scanned source, as
// a direct `trivy fs --format sarif` writes it.
func TestTrivyFsRewritesROOTPATHToTheScannedSource(t *testing.T) {
	l, err := sarif.Parse(strings.NewReader(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Trivy"}},` +
		`"originalUriBaseIds":{"ROOTPATH":{"uri":"file:///tmp/cybedefend-scanner/results.sarif.trivy.json/"}},` +
		`"results":[{"ruleId":"CVE-1","message":{"text":"x"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"package-lock.json","uriBaseId":"ROOTPATH"}}}]}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	var rw SARIFRewriter = TrivyFs{}
	if n := rw.RewriteSARIF(l, "/src/repo dir", nil); n != 1 {
		t.Fatalf("rewrote %d, want 1", n)
	}
	if got := l.Runs[0].OriginalURIBaseIDs["ROOTPATH"].URI; got != "file:///src/repo%20dir/" {
		t.Fatalf("ROOTPATH = %q", got)
	}
	rep := sarif.Normalize(l, sarif.NormalizeOptions{SourceRoot: "/src/repo dir"})
	if rep.Dropped != 0 || l.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI != "package-lock.json" {
		t.Fatalf("normalised %+v: %+v", rep, l.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation)
	}
	// a direct SARIF already names the source: nothing to rewrite
	if n := rw.RewriteSARIF(l, "/src/repo dir", nil); n != 0 {
		t.Fatalf("second pass rewrote %d, want 0", n)
	}
}
