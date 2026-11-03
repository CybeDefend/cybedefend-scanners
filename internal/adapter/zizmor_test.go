package adapter

import (
	"reflect"
	"slices"
	"testing"
)

func TestZizmorIsRegisteredAsCICD(t *testing.T) {
	a, ok := Get("zizmor")
	if !ok {
		t.Fatal("zizmor is not registered")
	}
	if a.Type() != TypeCICD {
		t.Fatalf("Type() = %q, want %q", a.Type(), TypeCICD)
	}
	if _, ok := a.(Zizmor); !ok {
		t.Fatalf("registered adapter is %T, want Zizmor", a)
	}
}

func TestZizmorCommandOffline(t *testing.T) {
	argv, onStdout := Zizmor{}.Command("/src", "/tmp/o.sarif", map[string]string{"PATH": "/usr/bin"})
	want := []string{"zizmor", "--format", "sarif", "--no-exit-codes", "--offline", "/src"}
	if !reflect.DeepEqual(argv, want) {
		t.Fatalf("argv = %q, want %q", argv, want)
	}
	if !onStdout {
		t.Fatal("sarifOnStdout = false, want true: zizmor writes its SARIF to stdout")
	}
	// An empty GH_TOKEN is no token: the run stays offline.
	argv, _ = Zizmor{}.Command("/src", "/tmp/o.sarif", map[string]string{"GH_TOKEN": ""})
	if !reflect.DeepEqual(argv, want) {
		t.Fatalf("with an empty GH_TOKEN, argv = %q, want %q", argv, want)
	}
}

func TestZizmorCommandOnline(t *testing.T) {
	// The value is never put on the command line: zizmor reads it from its
	// environment.
	const token = "not-a-real-token-value"
	env := map[string]string{"PATH": "/usr/bin", "GH_TOKEN": token}
	argv, onStdout := Zizmor{}.Command("/src", "/tmp/o.sarif", env)
	want := []string{"zizmor", "--format", "sarif", "--no-exit-codes", "/src"}
	if !reflect.DeepEqual(argv, want) {
		t.Fatalf("argv = %q, want %q", argv, want)
	}
	if !onStdout {
		t.Fatal("sarifOnStdout = false, want true")
	}
	for _, arg := range argv {
		if arg == token {
			t.Fatal("the token is on the command line")
		}
	}
	if !slices.Contains(Zizmor{}.ForwardedEnv(), "GH_TOKEN") {
		t.Fatalf("ForwardedEnv() = %q, does not forward GH_TOKEN", Zizmor{}.ForwardedEnv())
	}
}

func TestZizmorForwardsOnlyGHToken(t *testing.T) {
	var p EnvForwarder = Zizmor{}
	if got := p.ForwardedEnv(); !reflect.DeepEqual(got, []string{"GH_TOKEN"}) {
		t.Fatalf("ForwardedEnv() = %q, want [GH_TOKEN]", got)
	}
}

func TestZizmorSuccessExitCodes(t *testing.T) {
	if got := (Zizmor{}).SuccessExitCodes(); !reflect.DeepEqual(got, []int{0}) {
		t.Fatalf("SuccessExitCodes() = %v, want [0]", got)
	}
}
