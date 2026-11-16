package ci

import (
	"fmt"
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
			Groups      map[string]struct {
				Patterns []string `yaml:"patterns"`
			} `yaml:"groups"`
			Ignore []struct {
				Name        string   `yaml:"dependency-name"`
				UpdateTypes []string `yaml:"update-types"`
			} `yaml:"ignore"`
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
		// One pull request per ecosystem: a pin shared by several images (Go,
		// Trivy, Alpine) moves in all of them at once.
		var all bool
		for _, g := range u.Groups {
			all = all || contains(g.Patterns, "*")
		}
		if !all {
			t.Errorf("dependabot.yml: the %s updates are not grouped (a group with pattern \"*\")", u.Ecosystem)
		}
		// A new Go minor or major moves go.mod, every setup-go and every
		// Dockerfile together: it is done by hand, not by Dependabot.
		if u.Ecosystem == "docker" {
			var ignored []string
			for _, i := range u.Ignore {
				if i.Name == "golang" {
					ignored = i.UpdateTypes
				}
			}
			for _, want := range []string{"version-update:semver-major", "version-update:semver-minor"} {
				if !contains(ignored, want) {
					t.Errorf("dependabot.yml: the docker updates do not ignore golang %s", want)
				}
			}
		}
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

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// TestThirdPartyNoticesNameTheShippedPins: THIRD_PARTY_NOTICES.md names the
// exact tool each image ships. An update of a pin (by Dependabot or by hand)
// fails until the notices follow it, and Trivy is the same in its three
// images.
func TestThirdPartyNoticesNameTheShippedPins(t *testing.T) {
	notices := string(read(t, "THIRD_PARTY_NOTICES.md"))
	from := regexp.MustCompile(`(?m)^FROM (\S+:(\S+?)@sha256:[0-9a-f]{64})`)
	arg := func(file, name string) string {
		m := regexp.MustCompile(`(?m)^ARG ` + name + `=(\S+)$`).FindStringSubmatch(string(read(t, file)))
		if m == nil {
			t.Fatalf("%s has no ARG %s", file, name)
		}
		return m[1]
	}
	trivy := map[string]bool{}
	for _, a := range []string{"trivy-config", "trivy-fs", "trivy-image"} {
		for _, m := range from.FindAllStringSubmatch(string(read(t, "images/"+a+"/Dockerfile")), -1) {
			if strings.HasPrefix(m[1], "aquasec/trivy:") {
				trivy[m[1]] = true
				if !strings.Contains(notices, "`"+m[1]+"`") || !strings.Contains(notices, "v"+m[2]) {
					t.Errorf("THIRD_PARTY_NOTICES.md does not name %s (v%s) that images/%s ships", m[1], m[2], a)
				}
			}
		}
	}
	if len(trivy) != 1 {
		t.Errorf("the three Trivy images ship %d different Trivy pins, want one: %v", len(trivy), trivy)
	}
	for _, m := range from.FindAllStringSubmatch(string(read(t, "images/zizmor/Dockerfile")), -1) {
		if strings.HasPrefix(m[1], "ghcr.io/zizmorcore/zizmor:") && !strings.Contains(notices, "`"+m[1]+"`") {
			t.Errorf("THIRD_PARTY_NOTICES.md does not name %s", m[1])
		}
	}
	for _, c := range []struct{ file, arg, tool string }{
		{"images/opengrep/Dockerfile", "OPENGREP_VERSION", "Opengrep"},
		{"images/gitleaks/Dockerfile", "GITLEAKS_VERSION", "Gitleaks"},
	} {
		v := arg(c.file, c.arg)
		row := fmt.Sprintf("| %s | %s |", c.tool, strings.TrimPrefix(v, "v"))
		if !strings.Contains(notices, v) && !strings.Contains(notices, row) {
			t.Errorf("THIRD_PARTY_NOTICES.md does not name %s %s", c.tool, v)
		}
	}
}

// TestDependabotLeavesTheSamplesVulnerable: the samples under testdata/samples
// carry known vulnerabilities on purpose, and the integration tests expect
// them. Dependabot security updates read every manifest of the repository, so
// each sample manifest has an update entry that ignores all its dependencies:
// otherwise Dependabot opens a pull request that fixes the sample and breaks
// the test that scans it.
func TestDependabotLeavesTheSamplesVulnerable(t *testing.T) {
	var cfg struct {
		Updates []struct {
			Ecosystem   string   `yaml:"package-ecosystem"`
			Directory   string   `yaml:"directory"`
			Directories []string `yaml:"directories"`
			Ignore      []struct {
				Name        string   `yaml:"dependency-name"`
				UpdateTypes []string `yaml:"update-types"`
			} `yaml:"ignore"`
		} `yaml:"updates"`
	}
	if err := yaml.Unmarshal(read(t, ".github/dependabot.yml"), &cfg); err != nil {
		t.Fatal(err)
	}
	ignoredAll := map[string]bool{}
	for _, u := range cfg.Updates {
		var all bool
		for _, i := range u.Ignore {
			all = all || (i.Name == "*" && len(i.UpdateTypes) == 0)
		}
		if !all {
			continue
		}
		for _, d := range append([]string{u.Directory}, u.Directories...) {
			if d != "" {
				ignoredAll[u.Ecosystem+" "+strings.TrimSuffix(d, "/")] = true
			}
		}
	}
	// The manifests Dependabot security updates read, by ecosystem.
	manifests := map[string]string{
		"package.json": "npm", "package-lock.json": "npm", "yarn.lock": "npm", "pnpm-lock.yaml": "npm",
		"requirements.txt": "pip", "Pipfile": "pip", "Pipfile.lock": "pip", "pyproject.toml": "pip", "poetry.lock": "pip",
		"go.mod": "gomod", "pom.xml": "maven", "build.gradle": "gradle", "Gemfile": "bundler", "Gemfile.lock": "bundler",
		"composer.json": "composer", "Cargo.toml": "cargo", "Cargo.lock": "cargo",
	}
	var found int
	reported := map[string]bool{}
	err := filepath.WalkDir(filepath.Join(root, "testdata", "samples"), func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		eco, ok := manifests[d.Name()]
		if !ok {
			return nil
		}
		found++
		rel, err := filepath.Rel(root, filepath.Dir(p))
		if err != nil {
			return err
		}
		want := eco + " /" + filepath.ToSlash(rel)
		if !ignoredAll[want] && !reported[want] {
			reported[want] = true
			t.Errorf("dependabot.yml has no %q entry ignoring every dependency (dependency-name \"*\"): it would fix the vulnerable sample in %s", want, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found == 0 {
		t.Error("no manifest found under testdata/samples: the test reads the wrong place")
	}
}
