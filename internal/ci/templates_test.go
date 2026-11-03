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

type workflowStep struct {
	Name string            `yaml:"name"`
	ID   string            `yaml:"id"`
	If   string            `yaml:"if"`
	Uses string            `yaml:"uses"`
	Run  string            `yaml:"run"`
	With map[string]string `yaml:"with"`
	Env  map[string]string `yaml:"env"`
}

type workflowJob struct {
	Needs       yaml.Node         `yaml:"needs"`
	Permissions map[string]string `yaml:"permissions"`
	Strategy    struct {
		Matrix struct {
			Include []map[string]string `yaml:"include"`
		} `yaml:"matrix"`
	} `yaml:"strategy"`
	Steps []workflowStep `yaml:"steps"`
}

type workflow struct {
	On          map[string]yaml.Node   `yaml:"on"`
	Permissions yaml.Node              `yaml:"permissions"`
	Jobs        map[string]workflowJob `yaml:"jobs"`
}

func (s workflowStep) uses(action string) bool { return strings.HasPrefix(s.Uses, action+"@") }

// pushes is a build-push-action step that pushes.
func (s workflowStep) pushes() bool {
	return s.uses("docker/build-push-action") && s.With["push"] == "true"
}

// TestReleaseWorkflow: a v* tag a maintainer pushes publishes the six images,
// multi-arch, under :<version>, :<major> and :latest, after the integration
// suite passed on the amd64 image, then creates the release with the digests.
func TestReleaseWorkflow(t *testing.T) {
	data := read(t, ".github/workflows/release.yml")
	var wf workflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("release.yml: %v", err)
	}

	// Trigger: push of a vX.Y.Z tag, nothing else. A moving major tag (v1,
	// moved by hand for the Action's users) must not start a release.
	if len(wf.On) != 1 {
		t.Errorf("release.yml triggers on %d events, want push only", len(wf.On))
	}
	push, ok := wf.On["push"]
	if !ok {
		t.Fatal("release.yml does not trigger on push")
	}
	var pushFilter map[string][]string
	if err := push.Decode(&pushFilter); err != nil {
		t.Fatalf("on.push: %v", err)
	}
	if len(pushFilter) != 1 || strings.Join(pushFilter["tags"], ",") != "v[0-9]+.[0-9]+.[0-9]+" {
		t.Errorf("on.push = %v, want tags: ['v[0-9]+.[0-9]+.[0-9]+'] only", pushFilter)
	}

	// Permissions: nothing at the workflow level; each job asks for its own,
	// and the release as a whole writes contents and packages only.
	var top map[string]string
	if wf.Permissions.Kind != 0 {
		if err := wf.Permissions.Decode(&top); err != nil {
			t.Fatalf("top-level permissions: %v", err)
		}
	}
	for k, v := range top {
		if v != "read" && v != "none" {
			t.Errorf("top-level permission %s: %s, want read or none (each job asks for its writes)", k, v)
		}
	}
	writes := map[string]bool{}
	var imagesJob, releaseJob string
	for name, job := range wf.Jobs {
		if job.Permissions == nil {
			t.Errorf("job %s declares no permissions", name)
		}
		pushesImages, createsRelease := false, false
		for _, s := range job.Steps {
			if s.pushes() {
				pushesImages = true
			}
			if strings.Contains(s.Run, "gh release create") {
				createsRelease = true
			}
		}
		if pushesImages {
			imagesJob = name
		}
		if createsRelease {
			releaseJob = name
		}
		for scope, level := range job.Permissions {
			if level != "write" {
				continue
			}
			writes[scope] = true
			switch {
			case scope == "packages" && !pushesImages:
				t.Errorf("job %s writes packages but pushes no image", name)
			case scope == "contents" && !createsRelease:
				t.Errorf("job %s writes contents but creates no release", name)
			case scope != "packages" && scope != "contents":
				t.Errorf("job %s writes %s", name, scope)
			}
		}
	}
	if !writes["contents"] || !writes["packages"] || len(writes) != 2 {
		t.Errorf("write permissions = %v, want contents and packages", writes)
	}
	if imagesJob == "" {
		t.Fatal("no job pushes the images")
	}
	if releaseJob == "" {
		t.Fatal("no job creates the GitHub release")
	}
	if imagesJob == releaseJob {
		t.Error("the job that pushes the images also creates the release: packages and contents writes would share a token")
	}

	// A matrix over the six adapters, each with its own integration tests.
	images := wf.Jobs[imagesJob]
	var got []string
	for _, entry := range images.Strategy.Matrix.Include {
		got = append(got, entry["adapter"])
		if entry["tests"] == "" {
			t.Errorf("matrix entry %s names no integration tests", entry["adapter"])
		}
	}
	sort.Strings(got)
	var want []string
	for a := range adapters {
		want = append(want, a)
	}
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("matrix adapters = %v, want %v", got, want)
	}

	// The version is the tag without its leading v, the major its first number.
	versionStep := -1
	for i, s := range images.Steps {
		if strings.Contains(s.Run, "${GITHUB_REF_NAME#v}") && strings.Contains(s.Run, "GITHUB_OUTPUT") {
			versionStep = i
		}
	}
	if versionStep < 0 {
		t.Fatal("no step derives the version from ${GITHUB_REF_NAME#v}")
	}
	vs := images.Steps[versionStep]
	if vs.ID == "" || !strings.Contains(vs.Run, "version=") || !strings.Contains(vs.Run, "major=") {
		t.Errorf("the version step (id %q) does not output version and major", vs.ID)
	}
	if !strings.Contains(vs.Run, "exit 1") {
		t.Error("the version step does not refuse a tag that is not vMAJOR.MINOR.PATCH")
	}
	version := "${{ steps." + vs.ID + ".outputs.version }}"
	major := "${{ steps." + vs.ID + ".outputs.major }}"
	repo := "ghcr.io/cybedefend/appsec-scanners-${{ matrix.adapter }}"

	// amd64 build loaded locally, then the integration suite, then the push.
	load, integration, pushStep := -1, -1, -1
	for i, s := range images.Steps {
		switch {
		case s.uses("docker/build-push-action") && s.With["load"] == "true":
			load = i
			if s.With["platforms"] != "linux/amd64" {
				t.Errorf("the local build is for %q, want linux/amd64", s.With["platforms"])
			}
			if !strings.Contains(s.With["tags"], "appsec-scanners-${{ matrix.adapter }}:dev") {
				t.Errorf("the local build tags %q, want the tag the integration suite runs", s.With["tags"])
			}
			if s.With["push"] == "true" {
				t.Error("the local build pushes")
			}
		case strings.Contains(s.Run, "go test") && strings.Contains(s.Run, "-tags integration") && strings.Contains(s.Run, "./test/integration/"):
			integration = i
			if !strings.Contains(s.Run, "-run") || s.Env["TESTS"] != "${{ matrix.tests }}" {
				t.Error("the integration step does not run the matrix entry's tests")
			}
		case s.pushes():
			pushStep = i
		}
	}
	if load < 0 || integration < 0 || pushStep < 0 {
		t.Fatalf("steps: local build %d, integration %d, push %d; want all three", load, integration, pushStep)
	}
	if !(load < integration && integration < pushStep) {
		t.Errorf("order: local build %d, integration %d, push %d; want build, then tests, then push", load, integration, pushStep)
	}
	for _, i := range []int{load, pushStep} {
		s := images.Steps[i]
		if s.With["file"] != "images/${{ matrix.adapter }}/Dockerfile" || s.With["context"] != "." {
			t.Errorf("step %q builds file %q in %q, want images/${{ matrix.adapter }}/Dockerfile in .", s.Name, s.With["file"], s.With["context"])
		}
		if strings.TrimSpace(s.With["build-args"]) != "VERSION="+version {
			t.Errorf("step %q: build-args %q, want VERSION=%s", s.Name, s.With["build-args"], version)
		}
	}
	ps := images.Steps[pushStep]
	if ps.With["platforms"] != "linux/amd64,linux/arm64" {
		t.Errorf("the push builds %q, want linux/amd64,linux/arm64", ps.With["platforms"])
	}
	var tags []string
	for _, line := range strings.Split(ps.With["tags"], "\n") {
		if line = strings.TrimSpace(line); line != "" {
			tags = append(tags, line)
		}
	}
	sort.Strings(tags)
	wantTags := []string{repo + ":" + major, repo + ":" + version, repo + ":latest"}
	sort.Strings(wantTags)
	if strings.Join(tags, " ") != strings.Join(wantTags, " ") {
		t.Errorf("the push tags %v, want %v", tags, wantTags)
	}
	if ps.ID == "" {
		t.Error("the push step has no id, so its digest cannot be read")
	}
	login := -1
	for i, s := range images.Steps {
		if s.uses("docker/login-action") {
			login = i
			if s.With["registry"] != "ghcr.io" || s.With["password"] != "${{ secrets.GITHUB_TOKEN }}" {
				t.Errorf("the login step: registry %q, password %q; want ghcr.io with the job's GITHUB_TOKEN", s.With["registry"], s.With["password"])
			}
		}
	}
	if login < 0 || login < integration || login > pushStep {
		t.Errorf("the registry login (step %d) is not between the integration suite (%d) and the push (%d)", login, integration, pushStep)
	}

	// The digest of each image reaches the release notes.
	digestRef := "steps." + ps.ID + ".outputs.digest"
	carried := false
	for _, s := range images.Steps[pushStep+1:] {
		for _, v := range s.Env {
			if strings.Contains(v, digestRef) {
				carried = true
			}
		}
	}
	if !carried {
		t.Errorf("no step after the push reads %s", digestRef)
	}
	rel := wf.Jobs[releaseJob]
	var needs []string
	if rel.Needs.Kind == yaml.ScalarNode {
		needs = []string{rel.Needs.Value}
	} else if err := rel.Needs.Decode(&needs); err != nil {
		t.Fatalf("jobs.%s.needs: %v", releaseJob, err)
	}
	if !strings.Contains(strings.Join(needs, ","), imagesJob) {
		t.Errorf("the release job needs %v, want %s", needs, imagesJob)
	}
	downloads, notes := false, false
	for _, s := range rel.Steps {
		if s.uses("actions/download-artifact") {
			downloads = true
		}
		if strings.Contains(s.Run, "gh release create") && strings.Contains(s.Run, "--notes-file") && strings.Contains(s.Run, "--verify-tag") {
			notes = true
		}
	}
	if !downloads || !notes {
		t.Errorf("the release job: downloads the digests %v, creates the release from a notes file on the pushed tag %v", downloads, notes)
	}

	// Every action pinned by commit, no expression inside a script, no secret
	// in a script.
	for name, job := range wf.Jobs {
		for _, s := range job.Steps {
			if s.Uses != "" && !pinned.MatchString(s.Uses) {
				t.Errorf("job %s step %q uses %s, want <owner>/<repo>@<40-hex sha>", name, s.Name, s.Uses)
			}
			if strings.Contains(s.Run, "${{") {
				t.Errorf("job %s step %q substitutes an expression into its script", name, s.Name)
			}
			if s.uses("actions/checkout") && s.With["persist-credentials"] != "false" {
				t.Errorf("job %s: checkout keeps the token in .git/config", name)
			}
		}
	}
}
