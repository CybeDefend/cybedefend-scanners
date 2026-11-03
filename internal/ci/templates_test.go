// Package ci holds the checks on the GitHub Action, the GitLab CI template,
// the workflows and the examples. It has no code of its own.
package ci

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// root is the repository root, from this package's directory.
const root = "../.."

// adapters maps each adapter to the import type it uploads.
var adapters = map[string]string{
	"opengrep":     "sast",
	"gitleaks":     "secret",
	"trivy-config": "iac",
	"zizmor":       "cicd",
	"trivy-fs":     "sca",
	"trivy-image":  "container",
}

type actionInput struct {
	Description string  `yaml:"description"`
	Required    bool    `yaml:"required"`
	Default     *string `yaml:"default"`
}

type actionStep struct {
	Name  string            `yaml:"name"`
	ID    string            `yaml:"id"`
	If    string            `yaml:"if"`
	Uses  string            `yaml:"uses"`
	Run   string            `yaml:"run"`
	Shell string            `yaml:"shell"`
	Env   map[string]string `yaml:"env"`
}

type action struct {
	Name   string                 `yaml:"name"`
	Inputs map[string]actionInput `yaml:"inputs"`
	Runs   struct {
		Using string       `yaml:"using"`
		Steps []actionStep `yaml:"steps"`
	} `yaml:"runs"`
}

func read(t *testing.T, rel string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func loadAction(t *testing.T) action {
	t.Helper()
	var a action
	if err := yaml.Unmarshal(read(t, "action.yml"), &a); err != nil {
		t.Fatalf("action.yml: %v", err)
	}
	return a
}

func TestActionInputs(t *testing.T) {
	a := loadAction(t)
	want := []string{"api-url", "branch", "image", "path", "project-id", "sarif-output", "scanner", "token", "upload", "version"}
	var got []string
	for k := range a.Inputs {
		got = append(got, k)
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("inputs = %v, want %v", got, want)
	}
	for _, k := range []string{"scanner", "project-id", "api-url", "token"} {
		if !a.Inputs[k].Required {
			t.Errorf("input %s is not required", k)
		}
	}
	defaults := map[string]string{"image": "", "path": ".", "upload": "true"}
	for k, v := range defaults {
		d := a.Inputs[k].Default
		if d == nil || *d != v {
			t.Errorf("input %s: default %v, want %q", k, d, v)
		}
	}
	for _, name := range []string{"opengrep", "gitleaks", "trivy-config", "zizmor", "trivy-fs", "trivy-image"} {
		if !strings.Contains(a.Inputs["scanner"].Description, name) {
			t.Errorf("the scanner input does not name %s", name)
		}
	}
	if !strings.Contains(a.Inputs["path"].Description, "trivy-fs") || !strings.Contains(a.Inputs["path"].Description, "root") {
		t.Error("the path input does not say that trivy-fs scans the repository root")
	}
	if a.Runs.Using != "composite" {
		t.Errorf("runs.using = %q, want composite", a.Runs.Using)
	}
	for _, s := range a.Runs.Steps {
		if strings.Contains(s.Run, "inputs.token") {
			t.Errorf("step %q puts the token in its script", s.Name)
		}
		// Every input reaches a script through env:, never by substitution
		// into the script (injection).
		if strings.Contains(s.Run, "${{") {
			t.Errorf("step %q substitutes an expression into its script", s.Name)
		}
		if s.Run != "" && s.Shell != "bash" {
			t.Errorf("step %q: shell %q, want bash", s.Name, s.Shell)
		}
	}
}

// usesLine matches a « uses: » value, quoted or not, comment kept apart.
var usesLine = regexp.MustCompile(`(?m)^\s*(?:-\s+)?uses:\s*["']?([^"'\s#]+)`)

// pinned is <owner>/<repo>[/<path>]@<full commit sha>.
var pinned = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_./-]+)?@[0-9a-f]{40}$`)

func TestActionPinsActions(t *testing.T) {
	files := []string{"action.yml"}
	wf, err := filepath.Glob(filepath.Join(root, ".github", "workflows", "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(wf) == 0 {
		t.Fatal("no workflow found")
	}
	for _, f := range wf {
		rel, _ := filepath.Rel(root, f)
		files = append(files, rel)
	}
	for _, f := range files {
		for _, m := range usesLine.FindAllStringSubmatch(string(read(t, f)), -1) {
			ref := m[1]
			if ref == "./" || strings.HasPrefix(ref, "./") {
				continue // this repository's own action
			}
			if !pinned.MatchString(ref) {
				t.Errorf("%s: uses %s, want <owner>/<repo>@<40-hex sha>", f, ref)
			}
		}
	}
}

// TestActionPassesTheTokenThroughTheEnvironment: the token is never on a
// command line, where `ps` and an error message would show it.
func TestActionPassesTheTokenThroughTheEnvironment(t *testing.T) {
	a := loadAction(t)
	var dockerRun *actionStep
	for i, s := range a.Runs.Steps {
		if runsDocker(s) {
			dockerRun = &a.Runs.Steps[i]
		}
		if strings.Contains(s.Run, "CYBEDEFEND_TOKEN=") || strings.Contains(s.Run, "$CYBEDEFEND_TOKEN") || strings.Contains(s.Run, "${CYBEDEFEND_TOKEN") {
			t.Errorf("step %q expands the token in its script", s.Name)
		}
	}
	if dockerRun == nil {
		t.Fatal("no step runs docker run")
	}
	if dockerRun.Env["CYBEDEFEND_TOKEN"] != "${{ inputs.token }}" {
		t.Errorf("the docker run step's env CYBEDEFEND_TOKEN = %q, want ${{ inputs.token }}", dockerRun.Env["CYBEDEFEND_TOKEN"])
	}
	if !strings.Contains(dockerRun.Run, "-e CYBEDEFEND_TOKEN") {
		t.Error("docker run does not forward CYBEDEFEND_TOKEN by name")
	}
	for _, s := range a.Runs.Steps {
		if s.Name == dockerRun.Name {
			continue
		}
		for k, v := range s.Env {
			if strings.Contains(v, "inputs.token") {
				t.Errorf("step %q receives the token in %s; only the docker run step needs it", s.Name, k)
			}
		}
	}

	script := string(read(t, "examples/local/run.sh"))
	if strings.Contains(script, "CYBEDEFEND_TOKEN=") || !strings.Contains(script, "-e CYBEDEFEND_TOKEN") {
		t.Error("examples/local/run.sh does not forward the token by name only")
	}
	if regexp.MustCompile(`(?m)^\s*set\s+-[a-z]*x`).MatchString(script) {
		t.Error("examples/local/run.sh traces its commands")
	}
}

// dockerRunCall is a docker run, written out or through an argument array
// that starts with run.
var dockerRunCall = regexp.MustCompile(`docker\s+run\b|\(run\s`)

func runsDocker(s actionStep) bool { return dockerRunCall.MatchString(s.Run) }

func TestActionRequiresAnImageForTrivyImage(t *testing.T) {
	a := loadAction(t)
	guard, run := -1, -1
	for i, s := range a.Runs.Steps {
		cond := strings.ReplaceAll(s.If, " ", "")
		if guard < 0 && strings.Contains(cond, "inputs.scanner=='trivy-image'") && strings.Contains(cond, "inputs.image==''") &&
			strings.Contains(s.Run, "exit 1") {
			guard = i
		}
		if run < 0 && runsDocker(s) {
			run = i
		}
	}
	if guard < 0 {
		t.Fatal("no step fails when scanner is trivy-image and image is empty")
	}
	if run < 0 || guard > run {
		t.Errorf("the image check (step %d) does not come before docker run (step %d)", guard, run)
	}
	// The image reaches the container only for trivy-image, with its archive
	// and the registry credentials.
	script := a.Runs.Steps[run].Run
	for _, v := range []string{"-e CYBEDEFEND_IMAGE", "-e IMAGE_ARCHIVE", "-e TRIVY_USERNAME", "-e TRIVY_PASSWORD"} {
		if !strings.Contains(script, v) {
			t.Errorf("docker run does not pass %s", v)
		}
	}
	saved := false
	for _, s := range a.Runs.Steps[:run] {
		if strings.Contains(s.Run, "docker image inspect") && strings.Contains(s.Run, "docker save") &&
			strings.Contains(s.Run, "cybedefend-image.tar") {
			saved = true
		}
	}
	if !saved {
		t.Error("no step saves a local image to cybedefend-image.tar before docker run")
	}
}

// TestActionRunsOnTheDefaultNetwork: on a self-hosted runner, the host
// network would let a scanner reach every service on the runner's localhost.
// host.docker.internal reaches the runner when the API listens there.
func TestActionRunsOnTheDefaultNetwork(t *testing.T) {
	a := loadAction(t)
	found := false
	for _, s := range a.Runs.Steps {
		if strings.Contains(s.Run, "--network") || strings.Contains(s.Run, "--net ") || strings.Contains(s.Run, "--net=") {
			t.Errorf("step %q chooses a docker network", s.Name)
		}
		if runsDocker(s) {
			found = true
			if !strings.Contains(s.Run, "--add-host host.docker.internal:host-gateway") {
				t.Errorf("step %q does not add host.docker.internal", s.Name)
			}
		}
	}
	if !found {
		t.Fatal("no step runs docker run")
	}
}

type gitlabJob struct {
	Image struct {
		Name       string   `yaml:"name"`
		Entrypoint []string `yaml:"entrypoint"`
	} `yaml:"image"`
	Variables map[string]string `yaml:"variables"`
	Script    []string          `yaml:"script"`
	Artifacts struct {
		Paths []string `yaml:"paths"`
	} `yaml:"artifacts"`
}

func TestGitLabTemplateJobs(t *testing.T) {
	var doc map[string]yaml.Node
	data := read(t, "templates/gitlab/appsec-scanners.gitlab-ci.yml")
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	jobs := map[string]string{
		".cybedefend-sast":      "opengrep",
		".cybedefend-secret":    "gitleaks",
		".cybedefend-iac":       "trivy-config",
		".cybedefend-cicd":      "zizmor",
		".cybedefend-sca":       "trivy-fs",
		".cybedefend-container": "trivy-image",
	}
	for job, adapter := range jobs {
		node, ok := doc[job]
		if !ok {
			t.Errorf("no job %s", job)
			continue
		}
		var j gitlabJob
		if err := node.Decode(&j); err != nil {
			t.Errorf("%s: %v", job, err)
			continue
		}
		if want := "ghcr.io/cybedefend/appsec-scanners-" + adapter + ":$CYBEDEFEND_SCANNERS_VERSION"; j.Image.Name != want {
			t.Errorf("%s: image %q, want %q", job, j.Image.Name, want)
		}
		if len(j.Image.Entrypoint) != 1 || j.Image.Entrypoint[0] != "" {
			t.Errorf("%s: entrypoint %v, want [\"\"]", job, j.Image.Entrypoint)
		}
		script := strings.Join(j.Script, "\n")
		if !strings.Contains(script, "appsec-scanner run "+adapter+" ") || !strings.Contains(script, `--source "$CI_PROJECT_DIR"`) ||
			!strings.Contains(script, "--upload") {
			t.Errorf("%s: script %q does not run %s on $CI_PROJECT_DIR with --upload", job, script, adapter)
		}
		sarif := "cybedefend-" + adapter + ".sarif"
		if !strings.Contains(script, `--out "$CI_PROJECT_DIR/`+sarif+`"`) {
			t.Errorf("%s: script does not write %s", job, sarif)
		}
		if len(j.Artifacts.Paths) != 1 || j.Artifacts.Paths[0] != sarif {
			t.Errorf("%s: artifacts %v, want [%s]", job, j.Artifacts.Paths, sarif)
		}
		if strings.Contains(script, "CYBEDEFEND_TOKEN") {
			t.Errorf("%s: the script names the token", job)
		}
		if _, ok := j.Variables["CYBEDEFEND_TOKEN"]; ok {
			t.Errorf("%s: the template sets CYBEDEFEND_TOKEN; it is a masked CI/CD variable", job)
		}
		if adapter == "trivy-image" {
			if !strings.Contains(script, `--image "$CYBEDEFEND_IMAGE"`) {
				t.Errorf("%s: script does not pass --image \"$CYBEDEFEND_IMAGE\"", job)
			}
			if j.Variables["TRIVY_USERNAME"] != "$CI_REGISTRY_USER" || j.Variables["TRIVY_PASSWORD"] != "$CI_REGISTRY_PASSWORD" {
				t.Errorf("%s: variables %v, want the GitLab registry credentials", job, j.Variables)
			}
		} else {
			if strings.Contains(script, "--image") {
				t.Errorf("%s: only the container job passes --image", job)
			}
			// A global CYBEDEFEND_IMAGE would refuse every other adapter.
			if v, ok := j.Variables["CYBEDEFEND_IMAGE"]; !ok || v != "" {
				t.Errorf("%s: CYBEDEFEND_IMAGE is not cleared", job)
			}
		}
	}
	for _, v := range []string{"CYBEDEFEND_API_URL", "CYBEDEFEND_TOKEN", "CYBEDEFEND_PROJECT_ID", "masked"} {
		if !strings.Contains(string(data), v) {
			t.Errorf("the template does not document %s", v)
		}
	}
	var vars struct {
		Variables map[string]string `yaml:"variables"`
	}
	if err := yaml.Unmarshal(data, &vars); err != nil {
		t.Fatal(err)
	}
	if vars.Variables["CYBEDEFEND_SCANNERS_VERSION"] == "" {
		t.Error("the template gives CYBEDEFEND_SCANNERS_VERSION no default")
	}
}

func TestExamplesUseTheTemplates(t *testing.T) {
	gh := string(read(t, "examples/github/cybedefend-appsec.yml"))
	if !strings.Contains(gh, "uses: CybeDefend/cybedefend-scanners@") {
		t.Error("the GitHub example does not use CybeDefend/cybedefend-scanners@")
	}
	if !strings.Contains(gh, "GH_TOKEN: ${{ github.token }}") {
		t.Error("the GitHub example does not give zizmor GH_TOKEN")
	}
	if !strings.Contains(gh, "token: ${{ secrets.") {
		t.Error("the GitHub example does not take the token from a secret")
	}
	var wf map[string]any
	if err := yaml.Unmarshal([]byte(gh), &wf); err != nil {
		t.Fatalf("the GitHub example is not YAML: %v", err)
	}
	for _, m := range usesLine.FindAllStringSubmatch(gh, -1) {
		if strings.HasPrefix(m[1], "CybeDefend/cybedefend-scanners@") {
			continue
		}
		if !pinned.MatchString(m[1]) {
			t.Errorf("the GitHub example uses %s, not pinned by commit sha", m[1])
		}
	}

	gl := read(t, "examples/gitlab/.gitlab-ci.yml")
	if !strings.Contains(string(gl), "templates/gitlab/appsec-scanners.gitlab-ci.yml") {
		t.Error("the GitLab example does not include the template")
	}
	var glDoc struct {
		Include []map[string]string `yaml:"include"`
	}
	if err := yaml.Unmarshal(gl, &glDoc); err != nil || len(glDoc.Include) == 0 {
		t.Fatalf("the GitLab example has no include list: %v", err)
	}
	for _, hidden := range []string{".cybedefend-sast", ".cybedefend-container"} {
		if !strings.Contains(string(gl), "extends: "+hidden) {
			t.Errorf("the GitLab example does not extend %s", hidden)
		}
	}
}

// TestSelfTestCoversEveryScanner: the self-test runs the action once per
// adapter and checks the six types and the container's image.
func TestSelfTestCoversEveryScanner(t *testing.T) {
	data := string(read(t, ".github/workflows/action-self-test.yml"))
	if n := strings.Count(data, "uses: ./"); n != len(adapters) {
		t.Errorf("the self-test runs the action %d times, want %d", n, len(adapters))
	}
	for name, typ := range adapters {
		if !strings.Contains(data, "scanner: "+name+"\n") {
			t.Errorf("the self-test does not run %s", name)
		}
		if !strings.Contains(data, typ) {
			t.Errorf("the self-test does not check type %s", typ)
		}
	}
	if strings.Contains(data, "localhost:8080\n") && strings.Contains(data, "api-url: http://localhost") {
		t.Error("the self-test points the action at localhost, which the container cannot reach")
	}
	for _, v := range []string{"FAKE_API_TOKEN: test-token", "FAKE_API_ADDR: 0.0.0.0:8080", "api-url: http://host.docker.internal:8080", "version: dev",
		"image: appsec-scanners-sample:test", "testdata/samples/sca-npm", "FAKE_API_DUMP"} {
		if !strings.Contains(data, v) {
			t.Errorf("the self-test does not hold %q", v)
		}
	}
}
