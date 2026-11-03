package adapter

import (
	"reflect"
	"strings"
	"testing"
)

func TestTrivyConfigCommand(t *testing.T) {
	argv, onStdout := TrivyConfig{}.Command("/src", "/tmp/o.sarif", map[string]string{})
	want := []string{
		"trivy", "config",
		"--format", "sarif",
		"--output", "/tmp/o.sarif",
		"--exit-code", "0",
		"--skip-check-update",
		"--skip-version-check",
		"--disable-telemetry",
		"--quiet",
		"/src",
	}
	if !reflect.DeepEqual(argv, want) {
		t.Fatalf("Command() = %q\nwant        %q", argv, want)
	}
	if onStdout {
		t.Fatal("trivy config writes its SARIF to --output, not to stdout")
	}
}

// The scan must work with --network none: only Trivy's embedded checks, no
// bundle download, no version check and nothing sent to Aqua.
func TestTrivyConfigNeverReachesTheNetwork(t *testing.T) {
	argv, _ := TrivyConfig{}.Command("/src", "/tmp/o.sarif", map[string]string{})
	joined := " " + strings.Join(argv, " ") + " "
	for _, flag := range []string{"--skip-check-update", "--skip-version-check", "--disable-telemetry"} {
		if !strings.Contains(joined, " "+flag+" ") {
			t.Errorf("argv %q lacks %s", argv, flag)
		}
	}
	for _, a := range argv {
		if strings.HasPrefix(a, "--checks-bundle-repository") || strings.HasPrefix(a, "--reset-checks-bundle") {
			t.Errorf("argv %q asks for a checks bundle", argv)
		}
	}
}

func TestTrivyConfigSuccessExitCodes(t *testing.T) {
	if got := (TrivyConfig{}).SuccessExitCodes(); !reflect.DeepEqual(got, []int{0}) {
		t.Fatalf("SuccessExitCodes() = %v, want [0]", got)
	}
}

func TestTrivyConfigTypeAndRegistration(t *testing.T) {
	if got := (TrivyConfig{}).Type(); got != "iac" {
		t.Fatalf("Type() = %q, want iac", got)
	}
	if got := (TrivyConfig{}).Name(); got != "trivy-config" {
		t.Fatalf("Name() = %q, want trivy-config", got)
	}
	a, ok := Get("trivy-config")
	if !ok {
		t.Fatal("trivy-config is not registered")
	}
	if _, isTrivy := a.(TrivyConfig); !isTrivy || a.Type() != TypeIaC {
		t.Fatalf("Get(trivy-config) = %#v", a)
	}
}

// trivy config needs no variable besides PATH, HOME and TMPDIR.
func TestTrivyConfigForwardsNoExtraEnvironment(t *testing.T) {
	if _, ok := any(TrivyConfig{}).(EnvForwarder); ok {
		t.Fatal("TrivyConfig declares environment keys; it needs none")
	}
}
