// Package images holds the checks on the image definitions and on the files
// around them: every images/<adapter>/Dockerfile, and the samples next to
// them. It has no code of its own.
package images

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// root is the repository root, from this package's directory.
const root = "../.."

// instruction is one Dockerfile instruction, continuation lines joined.
type instruction struct {
	keyword string // upper case
	args    string
	line    int
}

func parse(t *testing.T, path string) []instruction {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []instruction
	var cur strings.Builder
	start := 0
	for i, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if cur.Len() == 0 {
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			start = i + 1
		} else if strings.HasPrefix(line, "#") {
			continue // a comment inside a continued instruction
		}
		cont := strings.HasSuffix(line, "\\")
		cur.WriteString(strings.TrimSuffix(line, "\\"))
		cur.WriteString(" ")
		if cont {
			continue
		}
		text := strings.TrimSpace(cur.String())
		cur.Reset()
		kw, args, _ := strings.Cut(text, " ")
		out = append(out, instruction{keyword: strings.ToUpper(kw), args: strings.TrimSpace(args), line: start})
	}
	if cur.Len() > 0 {
		t.Fatalf("%s: the last instruction ends with a continuation", path)
	}
	return out
}

func dockerfiles(t *testing.T) map[string]string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(root, "images", "*", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no images/*/Dockerfile found")
	}
	byAdapter := make(map[string]string, len(paths))
	for _, p := range paths {
		byAdapter[filepath.Base(filepath.Dir(p))] = p
	}
	return byAdapter
}

var (
	fromRe     = regexp.MustCompile(`(?i)^(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?$`)
	downloadRe = regexp.MustCompile(`\b(curl|wget)\b`)
	checkRe    = regexp.MustCompile(`sha256sum\s+(-c|--check)\b`)
	urlRe      = regexp.MustCompile(`(?i)\bhttps?://`)
)

func TestDockerfilesPinEverything(t *testing.T) {
	for adapter, path := range dockerfiles(t) {
		if data, err := os.ReadFile(path); err == nil {
			// A syntax directive pulls a frontend image: pinned like a FROM.
			for _, l := range strings.Split(string(data), "\n") {
				if d := strings.ToLower(strings.ReplaceAll(l, " ", "")); strings.HasPrefix(d, "#syntax=") && !strings.Contains(d, "@sha256:") {
					t.Errorf("%s: %q is not pinned by digest", path, strings.TrimSpace(l))
				}
			}
		}
		ins := parse(t, path)
		stages := map[string]bool{}
		lastFrom := -1
		for i, in := range ins {
			switch in.keyword {
			case "FROM":
				m := fromRe.FindStringSubmatch(in.args)
				if m == nil {
					t.Errorf("%s:%d: cannot read FROM %q", path, in.line, in.args)
					continue
				}
				if ref := m[1]; !stages[strings.ToLower(ref)] && !strings.Contains(ref, "@sha256:") {
					t.Errorf("%s:%d: FROM %s is not pinned by digest", path, in.line, ref)
				}
				if m[2] != "" {
					stages[strings.ToLower(m[2])] = true
				}
				lastFrom = i
			case "RUN":
				if loc := downloadRe.FindStringIndex(in.args); loc != nil {
					check := checkRe.FindStringIndex(in.args[loc[1]:])
					if check == nil {
						t.Errorf("%s:%d: a download is not followed by sha256sum -c in the same RUN", path, in.line)
					}
				}
			case "ADD":
				if urlRe.MatchString(in.args) && !strings.Contains(in.args, "--checksum=sha256:") {
					t.Errorf("%s:%d: ADD of a URL without --checksum=sha256:", path, in.line)
				}
			}
		}
		if lastFrom < 0 {
			t.Errorf("%s: no FROM", path)
			continue
		}
		final := ins[lastFrom+1:]
		wantEntry := `["/usr/local/bin/appsec-scanner","run","` + adapter + `"]`
		var user, entry string
		for _, in := range final {
			switch in.keyword {
			case "USER":
				user = in.args
			case "ENTRYPOINT":
				entry = strings.Join(strings.Fields(in.args), "")
			}
		}
		if user != "65532:65532" {
			t.Errorf("%s: the final stage's USER is %q, want 65532:65532", path, user)
		}
		if entry != wantEntry {
			t.Errorf("%s: the final stage's ENTRYPOINT is %s, want %s", path, entry, wantEntry)
		}
	}
}

func TestOpengrepImageBundlesOnlyOurRules(t *testing.T) {
	path := filepath.Join(root, "images", "opengrep", "Dockerfile")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	var copied bool
	for _, in := range parse(t, path) {
		if in.keyword == "COPY" && in.args == "rules/opengrep /opt/cybedefend-scanners/rules/opengrep" {
			copied = true
		}
	}
	if !copied {
		t.Error("the image does not COPY rules/opengrep /opt/cybedefend-scanners/rules/opengrep")
	}
	for _, banned := range []string{"git clone", "semgrep-rules", "opengrep-rules"} {
		if strings.Contains(text, banned) {
			t.Errorf("the Dockerfile names %q: only our own rules may be bundled", banned)
		}
	}
}

// filesContaining lists the files under dir whose content holds term.
func filesContaining(t *testing.T, dir, term string) []string {
	t.Helper()
	var hits []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(data), term) {
			hits = append(hits, path)
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("walk %s: %v", dir, err)
	}
	return hits
}

// The vulnerable sample workflow of the zizmor adapter must never run here:
// under .github/workflows/ a pull_request_target trigger would run a fork's
// code with this repository's secrets.
func TestNoSampleWorkflowRunsInThisRepository(t *testing.T) {
	// The check would pass on nothing: make sure it finds the sample's trigger.
	sample := filepath.Join(root, "testdata", "samples", "cicd-github-actions", ".github", "workflows")
	if len(filesContaining(t, sample, "pull_request_target")) == 0 {
		t.Fatalf("no file under %s holds pull_request_target: the check finds nothing", sample)
	}
	if hits := filesContaining(t, filepath.Join(root, ".github", "workflows"), "pull_request_target"); len(hits) > 0 {
		t.Fatalf("pull_request_target found in this repository's workflows: %v", hits)
	}
}

var (
	// ownOutDirRe is a RUN that creates the default --out directory and hands
	// that directory (not a tree) to uid 65532.
	ownOutDirRe = regexp.MustCompile(`\bmkdir\s+-p\s+/tmp/appsec-scanner(/\S*)?(\s|$)[\s\S]*\bchown\s+65532:65532\s+(\S+\s+)*/tmp/appsec-scanner(\s|$)`)
	// copyOutDirRe is a COPY that brings an empty appsec-scanner directory
	// under /tmp, owned by uid 65532, for a tool image built without a RUN.
	copyOutDirRe = regexp.MustCompile(`^--from=\S+\s+--chown=65532:65532\s+\S+/tmp/\s+/tmp/$`)
	recursiveRe  = regexp.MustCompile(`\bchown\s+(-\S*R|--recursive)\b`)
)

// The default --out is /tmp/appsec-scanner/results.sarif: every image creates
// that directory for uid 65532, so that it runs without a mounted --out.
func TestImagesGiveTheDefaultOutDirToTheScannerUser(t *testing.T) {
	for _, path := range dockerfiles(t) {
		ins := parse(t, path)
		lastFrom := -1
		for i, in := range ins {
			if in.keyword == "FROM" {
				lastFrom = i
			}
			if in.keyword == "RUN" && recursiveRe.MatchString(in.args) {
				t.Errorf("%s:%d: a recursive chown", path, in.line)
			}
		}
		var owned bool
		for _, in := range ins[lastFrom+1:] {
			switch in.keyword {
			case "RUN":
				owned = owned || ownOutDirRe.MatchString(in.args)
			case "COPY":
				owned = owned || copyOutDirRe.MatchString(in.args)
			}
		}
		if !owned {
			t.Errorf("%s: the final stage does not create /tmp/appsec-scanner owned by 65532:65532", path)
		}
	}
}

// minGoPatch is the oldest Go 1.26 patch release a build stage may use. The
// appsec-scanner binary carries the toolchain's standard library: built with
// golang:1.26.0, the images shipped every stdlib fix of 1.26.1 to 1.26.10,
// and trivy-image reported 47 of them in usr/local/bin/appsec-scanner
// (2026-11-03). Raise it with the golang digests when a patch release lands.
const minGoPatch = 10

var goImageRe = regexp.MustCompile(`^golang:1\.26\.(\d+)(?:-\S+)?@sha256:`)

func TestBuildStagesUseAPatchedGo(t *testing.T) {
	var seen int
	for _, path := range dockerfiles(t) {
		for _, in := range parse(t, path) {
			if in.keyword != "FROM" {
				continue
			}
			m := fromRe.FindStringSubmatch(in.args)
			if m == nil || !strings.HasPrefix(m[1], "golang:") {
				continue
			}
			seen++
			g := goImageRe.FindStringSubmatch(m[1])
			if g == nil {
				t.Errorf("%s:%d: FROM %s is not golang:1.26.<patch>…@sha256:", path, in.line, m[1])
				continue
			}
			if patch, _ := strconv.Atoi(g[1]); patch < minGoPatch {
				t.Errorf("%s:%d: FROM %s: Go 1.26.%d predates 1.26.%d", path, in.line, m[1], patch, minGoPatch)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no golang build stage found: the check finds nothing")
	}
}

// wantToolEnv is where every image points the tools' home and temporary
// directory: under the default --out directory, the one place a hardened run
// (--read-only --tmpfs /tmp/appsec-scanner) leaves writable. appsec-scanner
// creates both before it starts the tool (runner.ensureToolDirs).
var wantToolEnv = map[string]string{
	"HOME":   "/tmp/appsec-scanner/home",
	"TMPDIR": "/tmp/appsec-scanner/tmp",
}

// finalEnv reads the ENV instructions of the final stage, KEY=VALUE form.
func finalEnv(t *testing.T, ins []instruction) map[string]string {
	t.Helper()
	env := map[string]string{}
	for _, in := range ins {
		if in.keyword != "ENV" {
			continue
		}
		for _, kv := range strings.Fields(in.args) {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				t.Fatalf("line %d: ENV %q is not KEY=VALUE", in.line, in.args)
			}
			env[k] = strings.Trim(v, `"`)
		}
	}
	return env
}

func TestImagesPointHomeAndTmpdirUnderTheOutDir(t *testing.T) {
	for _, path := range dockerfiles(t) {
		ins := parse(t, path)
		lastFrom := -1
		for i, in := range ins {
			if in.keyword == "FROM" {
				lastFrom = i
			}
		}
		final := ins[lastFrom+1:]
		env := finalEnv(t, final)
		for k, want := range wantToolEnv {
			if env[k] != want {
				t.Errorf("%s: the final stage's %s is %q, want %q", path, k, env[k], want)
			}
		}
		// A WORKDIR after USER is created owned by uid 65532: a writable
		// directory outside /tmp/appsec-scanner.
		var userSeen bool
		for _, in := range final {
			switch in.keyword {
			case "USER":
				userSeen = true
			case "WORKDIR":
				if userSeen {
					t.Errorf("%s:%d: WORKDIR %s comes after USER", path, in.line, in.args)
				}
			}
		}
	}
}

// gitleaksModuleSum is the go.sum hash of github.com/zricethezav/gitleaks/v8
// v8.30.1, as https://sum.golang.org/lookup/github.com/zricethezav/gitleaks/v8@v8.30.1
// serves it (commit 83d9cd684c87d95d656c1458ef04895a7f1cbd8e of the tag).
const gitleaksModuleSum = "h1:PmEvCfVI7ti9dV3s5aMZUY7sS2GxRvG3yzih7E+cS3w="

// The upstream gitleaks image ships a binary built with Go 1.24.13 and
// modules with known vulnerabilities (69 trivy-image results, 2026-11-03):
// the image builds it from source with the patched Go of every build stage.
func TestGitleaksIsBuiltFromVerifiedSource(t *testing.T) {
	path := filepath.Join(root, "images", "gitleaks", "Dockerfile")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, in := range parse(t, path) {
		if in.keyword == "FROM" && strings.Contains(in.args, "zricethezav/gitleaks") {
			t.Errorf("%s:%d: FROM %s: the upstream binary is copied, not built", path, in.line, in.args)
		}
	}
	for _, want := range []string{
		"go mod download -json",
		gitleaksModuleSum,
		"GOTOOLCHAIN=local",
		"github.com/zricethezav/gitleaks/v8/version.Version=",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("%s does not hold %q", path, want)
		}
	}
}

var (
	goDirectiveRe = regexp.MustCompile(`(?m)^go\s+(1\.26\.(\d+))\s*$`)
	goVersionRe   = regexp.MustCompile(`(?m)^\s*go-version:\s*['"]?([^'"\s]+)['"]?\s*$`)
)

// The tests, the vet and the images build with one Go: go.mod's directive,
// which every workflow's setup-go names too.
func TestGoVersionIsTheSameEverywhere(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	m := goDirectiveRe.FindStringSubmatch(string(data))
	if m == nil {
		t.Fatal("go.mod has no go 1.26.<patch> directive")
	}
	if patch, _ := strconv.Atoi(m[2]); patch < minGoPatch {
		t.Errorf("go.mod's go directive %s predates 1.26.%d", m[1], minGoPatch)
	}
	workflows, err := filepath.Glob(filepath.Join(root, ".github", "workflows", "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var seen int
	for _, w := range workflows {
		text, err := os.ReadFile(w)
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range goVersionRe.FindAllStringSubmatch(string(text), -1) {
			seen++
			if v[1] != m[1] {
				t.Errorf("%s: go-version %s, want go.mod's %s", w, v[1], m[1])
			}
		}
	}
	if seen == 0 {
		t.Fatal("no go-version in .github/workflows: the check finds nothing")
	}
}

// opengrepCache is where the image unpacks Opengrep's one-file binary at build
// time. Unpacked at run time, it lands under HOME (/tmp/appsec-scanner/home):
// 244 MB per run, and a tmpfs mounted noexec (Docker's default) cannot run it.
const opengrepCache = "/opt/cybedefend-scanners/opengrep-cache"

func TestOpengrepIsUnpackedAtBuildTime(t *testing.T) {
	path := filepath.Join(root, "images", "opengrep", "Dockerfile")
	ins := parse(t, path)
	lastFrom := -1
	for i, in := range ins {
		if in.keyword == "FROM" {
			lastFrom = i
		}
	}
	final := ins[lastFrom+1:]
	if got := finalEnv(t, final)["XDG_CACHE_HOME"]; got != opengrepCache {
		t.Errorf("the final stage's XDG_CACHE_HOME is %q, want %s", got, opengrepCache)
	}
	var unpacked bool
	for _, in := range final {
		if in.keyword == "RUN" && strings.Contains(in.args, "XDG_CACHE_HOME="+opengrepCache) && strings.Contains(in.args, "opengrep --version") {
			unpacked = true
		}
		if in.keyword == "USER" && !unpacked {
			t.Errorf("%s: USER comes before the RUN that unpacks opengrep into %s", path, opengrepCache)
			return
		}
	}
	if !unpacked {
		t.Errorf("%s: no RUN unpacks opengrep with XDG_CACHE_HOME=%s", path, opengrepCache)
	}
}

// A tool run directly (`--entrypoint opengrep`, no appsec-scanner to create
// them) still finds its HOME and TMPDIR: the image ships both, owned by uid
// 65532, under the default --out directory.
func TestImagesShipHomeAndTmpdir(t *testing.T) {
	for _, path := range dockerfiles(t) {
		ins := parse(t, path)
		lastFrom := -1
		for i, in := range ins {
			if in.keyword == "FROM" {
				lastFrom = i
			}
		}
		var text strings.Builder
		for _, in := range ins[lastFrom+1:] {
			if in.keyword == "RUN" || in.keyword == "COPY" {
				text.WriteString(in.args + "\n")
			}
		}
		// zizmor's image runs no RUN: its build stage prepares the tree it copies.
		for _, in := range ins[:lastFrom+1] {
			if in.keyword == "RUN" && strings.Contains(in.args, "/out/tmp/appsec-scanner") {
				text.WriteString(in.args + "\n")
			}
		}
		for _, d := range []string{wantToolEnv["HOME"], wantToolEnv["TMPDIR"]} {
			if !strings.Contains(text.String(), d) && !strings.Contains(text.String(), strings.Replace(d, "/tmp/", "/out/tmp/", 1)) {
				t.Errorf("%s: the image does not create %s", path, d)
			}
		}
	}
}

// licenceDir is where every image keeps the licences of what it ships.
const licenceDir = "/usr/share/licenses/cybedefend-scanners"

// imageLicences gives, per adapter, the directory of licenses/ that holds its
// tool's licence and the SPDX expression of the image's own code: our
// Apache-2.0 program, its Go runtime (BSD-3-Clause) and the tool.
var imageLicences = map[string]struct{ tool, spdx string }{
	"opengrep":     {"opengrep", "Apache-2.0 AND BSD-3-Clause AND LGPL-2.1-only"},
	"gitleaks":     {"gitleaks", "Apache-2.0 AND BSD-3-Clause AND MIT"},
	"trivy-config": {"trivy", "Apache-2.0 AND BSD-3-Clause"},
	"trivy-fs":     {"trivy", "Apache-2.0 AND BSD-3-Clause"},
	"trivy-image":  {"trivy", "Apache-2.0 AND BSD-3-Clause"},
	"zizmor":       {"zizmor", "Apache-2.0 AND BSD-3-Clause AND MIT"},
}

// finalStage returns the instructions after the last FROM.
func finalStage(ins []instruction) []instruction {
	last := -1
	for i, in := range ins {
		if in.keyword == "FROM" {
			last = i
		}
	}
	return ins[last+1:]
}

// TestImagesShipTheLicences: an image redistributes our program, the Go
// runtime compiled into it and an upstream tool, so it carries each one's
// licence text (MIT, BSD and Apache-2.0 require it; Apache-2.0 also the
// NOTICE; LGPL-2.1 the licence and access to the source) and says so in its
// licenses label.
func TestImagesShipTheLicences(t *testing.T) {
	byAdapter := dockerfiles(t)
	for adapter := range imageLicences {
		if _, ok := byAdapter[adapter]; !ok {
			t.Errorf("no images/%s/Dockerfile", adapter)
		}
	}
	for adapter, path := range byAdapter {
		want, ok := imageLicences[adapter]
		if !ok {
			t.Errorf("%s: no expected licences for adapter %q", path, adapter)
			continue
		}
		var copies, labels strings.Builder
		for _, in := range finalStage(parse(t, path)) {
			switch in.keyword {
			case "COPY":
				copies.WriteString(in.args + "\n")
			case "LABEL":
				labels.WriteString(in.args + "\n")
			}
		}
		for _, c := range []string{
			"LICENSE NOTICE THIRD_PARTY_NOTICES.md " + licenceDir + "/",
			"licenses/go " + licenceDir + "/go/",
			"licenses/" + want.tool + " " + licenceDir + "/" + want.tool + "/",
		} {
			if !strings.Contains(copies.String(), c) {
				t.Errorf("%s: the final stage does not COPY %s", path, c)
			}
		}
		if l := `org.opencontainers.image.licenses="` + want.spdx + `"`; !strings.Contains(labels.String(), l) {
			t.Errorf("%s: the final stage does not LABEL %s", path, l)
		}
	}
}

// TestLicenceTextsArePresent: the texts the images copy are in the
// repository, taken from each project at the version the images ship.
func TestLicenceTextsArePresent(t *testing.T) {
	want := map[string]string{
		"licenses/opengrep/LICENSE": "GNU LESSER GENERAL PUBLIC LICENSE",
		"licenses/gitleaks/LICENSE": "Copyright (c) 2019 Zachary Rice",
		"licenses/trivy/LICENSE":    "Apache License",
		"licenses/trivy/NOTICE":     "Aqua Security",
		"licenses/zizmor/LICENSE":   "William Woodruff",
		"licenses/go/LICENSE":       "The Go Authors",
		"licenses/go/PATENTS":       "Additional IP Rights Grant (Patents)",
	}
	for f, s := range want {
		data, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			t.Error(err)
			continue
		}
		if !strings.Contains(string(data), s) {
			t.Errorf("%s does not contain %q", f, s)
		}
	}
}

// TestGitleaksShipsItsModulesLicences: gitleaks is rebuilt from source with
// raised dependencies, so the image carries the licence of every module
// compiled into it, collected at build time, and the build fails when one
// has none.
func TestGitleaksShipsItsModulesLicences(t *testing.T) {
	path := dockerfiles(t)["gitleaks"]
	ins := parse(t, path)
	collected := false
	for _, in := range ins {
		if in.keyword == "RUN" && strings.Contains(in.args, "go list -deps") && strings.Contains(in.args, "/out/licenses") {
			collected = true
		}
	}
	if !collected {
		t.Errorf("%s: no build step collects the modules' licences into /out/licenses", path)
	}
	copied := false
	for _, in := range finalStage(ins) {
		if in.keyword == "COPY" && strings.Contains(in.args, "/out/licenses "+licenceDir+"/gitleaks-modules/") {
			copied = true
		}
	}
	if !copied {
		t.Errorf("%s: the final stage does not COPY the modules' licences to %s/gitleaks-modules/", path, licenceDir)
	}
}

// TestGoStagesCrossCompile: every golang stage runs on the build machine's
// platform and has Go compile for the image's target (GOOS, GOARCH). An
// arm64 image built on an amd64 runner then compiles natively instead of
// under QEMU emulation, which made a release several times slower. The
// programs are static (CGO_ENABLED=0), so cross-compiling changes nothing in
// them.
func TestGoStagesCrossCompile(t *testing.T) {
	var seen int
	for _, path := range dockerfiles(t) {
		var inGo bool
		var stageLine int
		var args, env []string
		check := func() {
			if !inGo {
				return
			}
			for _, want := range []string{"TARGETOS", "TARGETARCH"} {
				if !contains(args, want) {
					t.Errorf("%s:%d: the golang stage does not declare ARG %s", path, stageLine, want)
				}
			}
			for _, want := range []string{"GOOS=${TARGETOS}", "GOARCH=${TARGETARCH}"} {
				if !contains(env, want) {
					t.Errorf("%s:%d: the golang stage does not set ENV %s", path, stageLine, want)
				}
			}
		}
		for _, in := range parse(t, path) {
			switch in.keyword {
			case "FROM":
				check()
				m := fromRe.FindStringSubmatch(in.args)
				inGo = m != nil && strings.HasPrefix(m[1], "golang:")
				stageLine, args, env = in.line, nil, nil
				if inGo {
					seen++
					if !strings.HasPrefix(in.args, "--platform=$BUILDPLATFORM ") {
						t.Errorf("%s:%d: FROM %s does not run on --platform=$BUILDPLATFORM", path, in.line, in.args)
					}
				}
			case "ARG":
				for _, f := range strings.Fields(in.args) {
					name, _, _ := strings.Cut(f, "=")
					args = append(args, name)
				}
			case "ENV":
				env = append(env, strings.Fields(in.args)...)
			}
		}
		check()
	}
	if seen == 0 {
		t.Fatal("no golang stage found: the check finds nothing")
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
