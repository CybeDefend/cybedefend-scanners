package adapter

import (
	"reflect"
	"strings"
	"testing"
)

func TestTrivyFsCommand(t *testing.T) {
	argv, onStdout := TrivyFs{}.Command("/src", "/tmp/o.sarif", map[string]string{})
	want := []string{
		"trivy", "fs", "--scanners", "vuln", "--format", "sarif", "--output", "/tmp/o.sarif",
		"--exit-code", "0", "--cache-dir", "/tmp/appsec-scanner/trivy-cache",
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
	if TrivyCacheDir != "/tmp/appsec-scanner/trivy-cache" {
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
