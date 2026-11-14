package ci

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The repository is public: anyone can open a pull request, and its
// workflows run on the code it brings. These tests keep the CI's own
// defences in place.

type hardenedWorkflow struct {
	Concurrency struct {
		Group            string `yaml:"group"`
		CancelInProgress bool   `yaml:"cancel-in-progress"`
	} `yaml:"concurrency"`
	Jobs map[string]workflowJob `yaml:"jobs"`
}

func loadHardened(t *testing.T, name string) hardenedWorkflow {
	t.Helper()
	var wf hardenedWorkflow
	if err := yaml.Unmarshal(read(t, ".github/workflows/"+name), &wf); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return wf
}

// TestPullRequestWorkflowsCancelSupersededRuns: a new push to a pull request
// cancels the runs of its previous push, so a stream of pushes cannot queue
// hours of runner time.
func TestPullRequestWorkflowsCancelSupersededRuns(t *testing.T) {
	for _, name := range []string{"ci.yml", "dco.yml", "action-self-test.yml"} {
		wf := loadHardened(t, name)
		g := wf.Concurrency.Group
		if !strings.Contains(g, "github.workflow") || !strings.Contains(g, "github.ref") {
			t.Errorf("%s: concurrency group %q, want one per workflow and ref", name, g)
		}
		if !wf.Concurrency.CancelInProgress {
			t.Errorf("%s: cancel-in-progress is off", name)
		}
	}
}

// TestCiAuditsTheWorkflows: the CI runs zizmor, at the version the zizmor
// image ships, on this repository's workflows and action, and fails on a
// finding of medium severity or more.
func TestCiAuditsTheWorkflows(t *testing.T) {
	dockerfile := string(read(t, "images/zizmor/Dockerfile"))
	pin := regexp.MustCompile(`(?m)^FROM (ghcr\.io/zizmorcore/zizmor:\S+@sha256:[0-9a-f]{64})`).FindStringSubmatch(dockerfile)
	if pin == nil {
		t.Fatal("images/zizmor/Dockerfile has no pinned zizmor image")
	}
	wf := loadHardened(t, "ci.yml")
	var found bool
	for _, job := range wf.Jobs {
		for _, s := range job.Steps {
			if !strings.Contains(s.Run, "zizmor") {
				continue
			}
			found = true
			for _, want := range []string{pin[1], "--offline", "--min-severity medium", ".github/workflows", "action.yml"} {
				if !strings.Contains(s.Run, want) {
					t.Errorf("the zizmor step lacks %q:\n%s", want, s.Run)
				}
			}
		}
	}
	if !found {
		t.Error("ci.yml runs no zizmor step")
	}
}

// TestDependabotWatchesEveryEcosystem: the pinned actions, the base images of
// every Dockerfile and the Go modules get update pull requests, so a pin
// does not stay on a vulnerable version.
func TestDependabotWatchesEveryEcosystem(t *testing.T) {
	var cfg struct {
		Version int `yaml:"version"`
		Updates []struct {
			Ecosystem   string   `yaml:"package-ecosystem"`
			Directory   string   `yaml:"directory"`
			Directories []string `yaml:"directories"`
		} `yaml:"updates"`
	}
	if err := yaml.Unmarshal(read(t, ".github/dependabot.yml"), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Version != 2 {
		t.Errorf("dependabot.yml version %d, want 2", cfg.Version)
	}
	watched := map[string]bool{}
	for _, u := range cfg.Updates {
		dirs := append([]string{u.Directory}, u.Directories...)
		for _, d := range dirs {
			if d != "" {
				watched[u.Ecosystem+" "+strings.TrimSuffix(d, "/")] = true
			}
		}
	}
	want := []string{"github-actions ", "gomod "}
	entries, err := os.ReadDir(filepath.Join(root, "images"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			want = append(want, "docker /images/"+e.Name())
		}
	}
	for _, w := range want {
		if !watched[w] && !watched[strings.TrimSpace(w)+" "] {
			t.Errorf("dependabot.yml does not watch %q", w)
		}
	}
}
