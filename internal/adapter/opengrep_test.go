package adapter

import (
	"reflect"
	"strings"
	"testing"
)

func TestOpengrepCommand(t *testing.T) {
	argv, onStdout := Opengrep{}.Command("/src", "/tmp/o.sarif", map[string]string{})
	want := []string{
		"opengrep", "scan",
		"--config", "/opt/cybedefend-scanners/rules/opengrep",
		"--sarif", "--output", "/tmp/o.sarif",
		"--disable-version-check",
		"/src",
	}
	if !reflect.DeepEqual(argv, want) {
		t.Fatalf("argv = %q\nwant  %q", argv, want)
	}
	if onStdout {
		t.Fatal("sarifOnStdout = true, want false")
	}
}

func TestOpengrepConfigOverride(t *testing.T) {
	argv, _ := Opengrep{}.Command("/src", "/tmp/o.sarif", map[string]string{"OPENGREP_CONFIG": "/r1, /r2,"})
	want := []string{
		"opengrep", "scan",
		"--config", "/r1", "--config", "/r2",
		"--sarif", "--output", "/tmp/o.sarif",
		"--disable-version-check",
		"/src",
	}
	if !reflect.DeepEqual(argv, want) {
		t.Fatalf("argv = %q\nwant  %q", argv, want)
	}
}

func TestOpengrepRulesDirField(t *testing.T) {
	argv, _ := Opengrep{RulesDir: "/rules"}.Command("/src", "/tmp/o.sarif", nil)
	if argv[2] != "--config" || argv[3] != "/rules" {
		t.Fatalf("argv = %q, want --config /rules", argv)
	}
}

func TestOpengrepNeverUsesRegistryRules(t *testing.T) {
	for _, env := range []map[string]string{
		{},
		{"OPENGREP_CONFIG": "auto,p/python,r/python.lang.eval,/ok"},
	} {
		argv, _ := Opengrep{}.Command("/src", "/tmp/o.sarif", env)
		for _, a := range argv {
			if a == "auto" || strings.HasPrefix(a, "p/") || strings.HasPrefix(a, "r/") {
				t.Errorf("env %v: argv %q names registry rules (%q)", env, argv, a)
			}
		}
	}
}

func TestOpengrepSuccessExitCodes(t *testing.T) {
	if got := (Opengrep{}).SuccessExitCodes(); !reflect.DeepEqual(got, []int{0}) {
		t.Fatalf("SuccessExitCodes() = %v, want [0]", got)
	}
}

func TestOpengrepIsRegisteredAsSAST(t *testing.T) {
	a, ok := Get("opengrep")
	if !ok {
		t.Fatal("opengrep is not registered")
	}
	if a.Type() != TypeSAST {
		t.Fatalf("type = %s, want sast", a.Type())
	}
	p, ok := a.(EnvForwarder)
	// XDG_CACHE_HOME names where the image unpacked the one-file binary
	// (images/opengrep/Dockerfile): without it, opengrep unpacks itself again
	// under HOME at every run.
	if !ok || !reflect.DeepEqual(p.ForwardedEnv(), []string{"OPENGREP_CONFIG", "XDG_CACHE_HOME"}) {
		t.Fatalf("opengrep receives %v, want OPENGREP_CONFIG and XDG_CACHE_HOME", p.ForwardedEnv())
	}
}
