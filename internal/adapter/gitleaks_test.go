package adapter_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cybedefend/cybedefend-scanners/internal/adapter"
	"github.com/cybedefend/cybedefend-scanners/internal/runner"
	"github.com/cybedefend/cybedefend-scanners/internal/sarif"
)

func gitleaksAdapter(t *testing.T) adapter.Adapter {
	t.Helper()
	a, ok := adapter.Get("gitleaks")
	if !ok {
		t.Fatal("no adapter registered as gitleaks")
	}
	return a
}

func TestGitleaksIsRegisteredAsSecret(t *testing.T) {
	a := gitleaksAdapter(t)
	if _, ok := a.(adapter.Gitleaks); !ok {
		t.Fatalf("gitleaks is a %T, want adapter.Gitleaks", a)
	}
	if a.Name() != "gitleaks" {
		t.Errorf("Name() = %q", a.Name())
	}
	if a.Type() != adapter.TypeSecret || a.Type() != "secret" {
		t.Errorf("Type() = %q, want secret", a.Type())
	}
}

func TestGitleaksCommand(t *testing.T) {
	argv, onStdout := adapter.Gitleaks{}.Command("/src", "/tmp/o.sarif", map[string]string{})
	want := []string{"gitleaks", "dir", "/src", "--report-format", "sarif", "--report-path", "/tmp/o.sarif", "--redact=100", "--no-banner", "--exit-code", "0"}
	if !reflect.DeepEqual(argv, want) {
		t.Fatalf("argv = %q\nwant   %q", argv, want)
	}
	if onStdout {
		t.Error("gitleaks writes its SARIF to --report-path, not to stdout")
	}
}

func TestGitleaksNeverScansHistory(t *testing.T) {
	argv, _ := adapter.Gitleaks{}.Command("/src", "/tmp/o.sarif", map[string]string{"GITLEAKS_CONFIG": "/x"})
	for _, a := range argv {
		if a == "git" || a == "detect" {
			t.Fatalf("argv %q scans the git history (%q)", argv, a)
		}
	}
}

func TestGitleaksSuccessExitCodes(t *testing.T) {
	if got := (adapter.Gitleaks{}).SuccessExitCodes(); !reflect.DeepEqual(got, []int{0}) {
		t.Fatalf("SuccessExitCodes() = %v, want [0]", got)
	}
}

// TestGitleaksRedactsWithTheLocalBinary runs the real gitleaks, when it is on
// PATH, through the runner and the normalisation the command applies: the
// generated secret must not survive into the SARIF that would be uploaded.
// The image is covered by test/integration (TestGitleaksImageRedactsAndUploads).
func TestGitleaksRedactsWithTheLocalBinary(t *testing.T) {
	if _, err := exec.LookPath("gitleaks"); err != nil {
		t.Skip("gitleaks is not on PATH")
	}
	src := t.TempDir()
	secret := generatedStripeKey(t)
	if err := os.WriteFile(filepath.Join(src, "settings.env"), []byte("API_KEY=<set me>\nSTRIPE_KEY="+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "results.sarif")
	a := gitleaksAdapter(t)
	res, err := runner.Run(context.Background(), a, src, out, time.Minute, map[string]string{"PATH": os.Getenv("PATH")})
	if err != nil {
		t.Fatalf("run gitleaks: %v\n%s", err, res.Output)
	}
	for _, leak := range [][]byte{[]byte(secret), []byte(secret[len(secret)-8:])} {
		if bytes.Contains(res.Output, leak) {
			t.Fatal("gitleaks printed the secret")
		}
	}

	log, err := sarif.Parse(bytes.NewReader(res.SARIF))
	if err != nil {
		t.Fatal(err)
	}
	sarif.Normalize(log, sarif.NormalizeOptions{SourceRoot: src, DropSnippets: a.Type() == adapter.TypeSecret})
	var buf bytes.Buffer
	if err := sarif.Write(&buf, log); err != nil {
		t.Fatal(err)
	}
	got := buf.Bytes()
	if bytes.Contains(got, []byte(secret)) || bytes.Contains(got, []byte(secret[len(secret)-8:])) {
		t.Fatal("the normalised SARIF holds the secret")
	}
	if bytes.Contains(got, []byte(`"snippet"`)) {
		t.Fatal("the normalised SARIF holds a snippet")
	}
	var uploaded struct {
		Runs []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(got, &uploaded); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, run := range uploaded.Runs {
		for _, r := range run.Results {
			for _, l := range r.Locations {
				if r.RuleID == "stripe-access-token" && l.PhysicalLocation.ArtifactLocation.URI == "settings.env" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatalf("no stripe-access-token result at settings.env in\n%s", got)
	}
}

const base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// generatedStripeKey builds a Stripe-shaped key at run time, so that no
// secret-shaped string is ever committed.
func generatedStripeKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 24)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(base62))))
		if err != nil {
			t.Fatal(err)
		}
		b[i] = base62[n.Int64()]
	}
	return "sk_" + "live_" + string(b)
}
