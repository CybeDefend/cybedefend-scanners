//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestOpengrepRulesPassTheirOwnTests runs Opengrep's own rule test mode on
// the bundled rules inside the image: every `ruleid:` line must be reported
// and no `ok:` line may be.
func TestOpengrepRulesPassTheirOwnTests(t *testing.T) {
	image := buildImage(t, "opengrep")
	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "--network", "none",
		"--entrypoint", "opengrep", image,
		"scan", "--test", "--disable-version-check", "/opt/appsec-scanners/rules/opengrep")
	out, err := cmd.CombinedOutput()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			t.Fatalf("opengrep scan --test exited %d, want 0\n%s", exitErr.ExitCode(), out)
		}
		t.Fatalf("docker run %s: %v\n%s", image, err, out)
	}
}

// TestOpengrepResultCarriesSecuritySeverity checks that the rule's
// metadata.security-severity reaches the uploaded SARIF, where the server
// reads it (on the result or on its rule descriptor).
func TestOpengrepResultCarriesSecuritySeverity(t *testing.T) {
	api := startFakeAPI(t)
	code, out := runImage(t, "opengrep", filepath.Join(repoRoot(t), "testdata", "samples", "sast-python"), api.URL)
	if code != 0 {
		t.Fatalf("exit %d, want 0\n%s", code, out)
	}
	uploads := api.Uploads()
	if len(uploads) != 1 {
		t.Fatalf("%d uploads, want 1\n%s", len(uploads), out)
	}

	var log struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID                   string `json:"id"`
						DefaultConfiguration struct {
							Level string `json:"level"`
						} `json:"defaultConfiguration"`
						Properties map[string]any `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID     string         `json:"ruleId"`
				Level      string         `json:"level"`
				Properties map[string]any `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(uploads[0].SARIF, &log); err != nil {
		t.Fatalf("the uploaded SARIF is not JSON: %v", err)
	}
	isEval := func(id string) bool { return id == "python-eval" || strings.HasSuffix(id, ".python-eval") }

	var seen bool
	for _, run := range log.Runs {
		ruleSeverity := map[string]any{}
		ruleLevel := map[string]string{}
		for _, r := range run.Tool.Driver.Rules {
			if v, ok := r.Properties["security-severity"]; ok {
				ruleSeverity[r.ID] = v
			}
			ruleLevel[r.ID] = r.DefaultConfiguration.Level
		}
		for _, res := range run.Results {
			if !isEval(res.RuleID) {
				continue
			}
			seen = true
			sev, onResult := res.Properties["security-severity"]
			if !onResult {
				sev = ruleSeverity[res.RuleID]
			}
			if fmt.Sprint(sev) != "9.8" {
				t.Errorf("python-eval security-severity = %v (result %v, rule %v), want 9.8",
					sev, res.Properties["security-severity"], ruleSeverity[res.RuleID])
			}
			// SARIF: a result without its own level takes its rule's default.
			level := res.Level
			if level == "" {
				level = ruleLevel[res.RuleID]
			}
			if level != "error" {
				t.Errorf("python-eval level = %q, want error", level)
			}
		}
	}
	if !seen {
		t.Fatalf("no python-eval result in the uploaded SARIF:\n%s", uploads[0].SARIF)
	}
}
