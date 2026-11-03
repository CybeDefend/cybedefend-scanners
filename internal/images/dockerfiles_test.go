// Package images holds the checks on the image definitions and on the files
// around them: every images/<adapter>/Dockerfile, and the samples next to
// them. It has no code of its own.
package images

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
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
		if in.keyword == "COPY" && in.args == "rules/opengrep /opt/appsec-scanners/rules/opengrep" {
			copied = true
		}
	}
	if !copied {
		t.Error("the image does not COPY rules/opengrep /opt/appsec-scanners/rules/opengrep")
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
