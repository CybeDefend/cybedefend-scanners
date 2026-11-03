//go:build integration

package integration

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

// rulesPresent reports whether rules/opengrep holds at least one rule.
func rulesPresent(t *testing.T) bool {
	t.Helper()
	for _, ext := range []string{"*.yaml", "*.yml"} {
		m, err := filepath.Glob(filepath.Join(repoRoot(t), "rules", "opengrep", ext))
		if err != nil {
			t.Fatal(err)
		}
		if len(m) > 0 {
			return true
		}
	}
	return false
}

func TestOpengrepImageOnPythonSample(t *testing.T) {
	requireDocker(t)
	if !rulesPresent(t) {
		t.Skip("no bundled rules yet")
	}
	api := startFakeAPI(t)
	code, out := runImage(t, "opengrep", filepath.Join(repoRoot(t), "testdata", "samples", "sast-python"), api.URL)
	if code != 0 {
		t.Fatalf("exit %d, want 0\n%s", code, out)
	}
	if strings.Contains(out, testToken) {
		t.Error("the token was printed")
	}

	uploads := api.Uploads()
	if len(uploads) != 1 {
		t.Fatalf("%d uploads, want 1\n%s", len(uploads), out)
	}
	u := uploads[0]
	if u.Fields["type"] != "sast" || u.Fields["branch"] != testBranch || u.Fields["format"] != "sarif" {
		t.Errorf("fields = %v, want type=sast branch=%s format=sarif", u.Fields, testBranch)
	}
	if _, ok := u.Fields["image"]; ok {
		t.Error("a sast upload carries an image part")
	}
	if u.Authorization != "Bearer "+testToken {
		t.Error("the token was not sent as the bearer")
	}
	if !strings.HasPrefix(u.UserAgent, "appsec-scanner/") {
		t.Errorf("User-Agent = %q", u.UserAgent)
	}
	if bytes.Contains(u.SARIF, []byte(testToken)) {
		t.Error("the token is in the uploaded SARIF")
	}

	var found bool
	for _, r := range sarifResults(t, u.SARIF) {
		if !strings.Contains(r.RuleID, "python-eval") {
			continue
		}
		for _, l := range r.Locations {
			if l.PhysicalLocation.ArtifactLocation.URI == "app.py" {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("no python-eval result at app.py in the uploaded SARIF:\n%s", u.SARIF)
	}
}
