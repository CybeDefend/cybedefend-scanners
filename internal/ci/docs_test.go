package ci

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// adapterTools names the upstream tool each adapter runs.
var adapterTools = map[string]string{
	"opengrep":     "Opengrep",
	"gitleaks":     "Gitleaks",
	"trivy-config": "Trivy",
	"zizmor":       "zizmor",
	"trivy-fs":     "Trivy",
	"trivy-image":  "Trivy",
}

// section returns the Markdown section that starts at the heading line
// heading, up to the next heading of the same or a higher level.
func section(t *testing.T, doc, heading string) string {
	t.Helper()
	lines := strings.Split(doc, "\n")
	level := strings.Index(heading, " ")
	for i, l := range lines {
		if l != heading {
			continue
		}
		var out []string
		for _, m := range lines[i+1:] {
			if n := strings.Index(m, " "); n > 0 && n <= level && strings.Trim(m[:n], "#") == "" {
				break
			}
			out = append(out, m)
		}
		return strings.Join(out, "\n")
	}
	t.Fatalf("no heading %q", heading)
	return ""
}

func TestReadmeNamesEveryAdapter(t *testing.T) {
	readme := string(read(t, "README.md"))
	rows := map[string]string{}
	for _, l := range strings.Split(readme, "\n") {
		if !strings.HasPrefix(l, "| `") {
			continue
		}
		cell := strings.SplitN(strings.TrimPrefix(l, "| `"), "`", 2)[0]
		if _, ok := adapters[cell]; ok {
			rows[cell] = l
		}
	}
	for name, typ := range adapters {
		row, ok := rows[name]
		if !ok {
			t.Errorf("README.md has no table row starting with `%s`", name)
			continue
		}
		for _, want := range []string{
			"`ghcr.io/cybedefend/appsec-scanners-" + name + "`",
			adapterTools[name],
			"`" + typ + "`",
		} {
			if !strings.Contains(row, want) {
				t.Errorf("README.md row of %s lacks %s: %s", name, want, row)
			}
		}
		if typ == "sca" || typ == "container" {
			for _, want := range []string{"Community Edition only", "database"} {
				if !strings.Contains(row, want) {
					t.Errorf("README.md row of %s lacks %q: %s", name, want, row)
				}
			}
		}
	}
}

var pinnedVersion = regexp.MustCompile(`\bv?[0-9]+\.[0-9]+\.[0-9]+\b`)

func TestThirdPartyNoticesListEveryTool(t *testing.T) {
	notices := string(read(t, "THIRD_PARTY_NOTICES.md"))
	tools := map[string]string{
		"Opengrep": "LGPL-2.1",
		"Gitleaks": "MIT",
		"Trivy":    "Apache-2.0",
		"zizmor":   "MIT",
	}
	for tool, licence := range tools {
		found := false
		for _, l := range strings.Split(notices, "\n") {
			cells := strings.Split(l, "|")
			if len(cells) < 6 || strings.TrimSpace(cells[2]) != tool {
				continue
			}
			found = true
			if strings.TrimSpace(cells[4]) != licence {
				t.Errorf("%s: licence %q, want %s", tool, strings.TrimSpace(cells[4]), licence)
			}
			if !pinnedVersion.MatchString(cells[3]) {
				t.Errorf("%s: no pinned version in %q", tool, cells[3])
			}
		}
		if !found {
			t.Errorf("THIRD_PARTY_NOTICES.md has no table row for %s", tool)
		}
	}
	for name, tool := range adapterTools {
		if !strings.Contains(notices, "`appsec-scanners-"+name+"`") {
			t.Errorf("THIRD_PARTY_NOTICES.md does not name the image of %s (%s)", name, tool)
		}
	}

	trivy := section(t, notices, "## Trivy")
	for _, name := range []string{"trivy-config", "trivy-fs", "trivy-image"} {
		if !strings.Contains(trivy, name) {
			t.Errorf("the Trivy section does not name %s", name)
		}
	}
	db := section(t, trivy, "### Vulnerability database (trivy-db)")
	for _, want := range []string{
		"trivy-fs", "trivy-image",
		"https://github.com/aquasecurity/trivy-db",
		"Licence:",
		"own terms",
	} {
		if !strings.Contains(db, want) {
			t.Errorf("the trivy-db notice lacks %q", want)
		}
	}
}

func TestReadmeStatesTheReplaceSemantics(t *testing.T) {
	readme := string(read(t, "README.md"))
	for _, want := range []string{"whole dependency picture", "per image and branch"} {
		if !strings.Contains(readme, want) {
			t.Errorf("README.md does not say %q", want)
		}
	}
}

var tokenPattern = regexp.MustCompile(`cdp_[A-Za-z0-9_-]{20,}`)

func TestReadmeNeverPrintsAToken(t *testing.T) {
	files := []string{"README.md"}
	err := filepath.WalkDir(filepath.Join(root, "examples"), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			rel, rerr := filepath.Rel(root, p)
			if rerr != nil {
				return rerr
			}
			files = append(files, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		data, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			t.Fatal(err)
		}
		for i, l := range strings.Split(string(data), "\n") {
			if tokenPattern.MatchString(l) {
				t.Errorf("%s:%d looks like a personal access token", f, i+1)
			}
		}
	}
}
