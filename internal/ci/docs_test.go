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
		if (typ == "sca" || typ == "container") && !strings.Contains(row, "database") {
			t.Errorf("README.md row of %s lacks %q: %s", name, "database", row)
		}
	}
}

// firstParagraph returns the README's text between its title and the first
// blank line after it.
func firstParagraph(doc string) string {
	parts := strings.SplitN(strings.TrimLeft(doc, "\n"), "\n\n", 3)
	if len(parts) < 2 {
		return ""
	}
	return strings.Join(strings.Fields(parts[1]), " ")
}

func TestReadmeSaysCommunityEditionOnlyFirst(t *testing.T) {
	first := firstParagraph(string(read(t, "README.md")))
	for _, want := range []string{"Community Edition only", "CybeDefend Cloud does not take imports"} {
		if !strings.Contains(first, want) {
			t.Errorf("README.md's first paragraph does not say %q: %s", want, first)
		}
	}
}

// cloudAsTarget are phrasings that present CybeDefend Cloud as a place the
// results can be uploaded to, which it is not.
var cloudAsTarget = []string{"or CybeDefend Cloud", "Cloud accepts", "on Cloud,", "Cloud refuses them", "## CybeDefend Cloud"}

func TestNoTextPresentsCloudAsAnUploadTarget(t *testing.T) {
	files := []string{"README.md", "CONTRIBUTING.md", "SECURITY.md", "action.yml", "templates/gitlab/appsec-scanners.gitlab-ci.yml"}
	for _, dir := range []string{"examples", "rules"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			rel, rerr := filepath.Rel(root, p)
			files = append(files, rel)
			return rerr
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range files {
		text := strings.Join(strings.Fields(string(read(t, f))), " ")
		for _, bad := range cloudAsTarget {
			if strings.Contains(text, bad) {
				t.Errorf("%s says %q: CybeDefend Cloud takes no import", f, bad)
			}
		}
	}
	for _, f := range []string{"action.yml", "templates/gitlab/appsec-scanners.gitlab-ci.yml", "CONTRIBUTING.md"} {
		text := strings.Join(strings.Fields(string(read(t, f))), " ")
		if !strings.Contains(text, "Community Edition instance") {
			t.Errorf("%s does not say the results go to a Community Edition instance", f)
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

func TestReadmeDocumentsScanRuns(t *testing.T) {
	readme := string(read(t, "README.md"))
	i := strings.Index(readme, "## Scan runs (CybeDefend Community cluster)")
	if i < 0 {
		t.Fatal("README.md has no section « Scan runs (CybeDefend Community cluster) »")
	}
	section := readme[i:]
	if j := strings.Index(section[3:], "\n## "); j >= 0 {
		section = section[:j+3]
	}
	for _, want := range []string{
		"--scan-run", "`CYBEDEFEND_API_URL`", "`CYBEDEFEND_SCAN_ID`", "`CYBEDEFEND_SCAN_TOKEN`", "`CYBEDEFEND_ARCHIVE_URL`",
		"X-CybeDefend-Scan-Protocol: 1", "do not carry that folder's name", "| 5 |", "| 6 |", "POST <api-url>/scan-runs/<scan id>/results",
		"X-CybeDefend-Scan-Protocol: 2", "`sbom`", "results.cdx.json", "application/vnd.cyclonedx+json", "IMPORT_INVALID_SBOM", "SCAN_PROTOCOL_UNSUPPORTED",
	} {
		if !strings.Contains(section, want) {
			t.Errorf("the scan-run section lacks %q", want)
		}
	}
	if !strings.Contains(readme, "`--sbom-out`") {
		t.Error("README.md does not document --sbom-out")
	}
	for _, want := range []string{"| 5 |", "| 6 |"} {
		if !strings.Contains(readme[strings.Index(readme, "## Exit codes"):], want) {
			t.Errorf("the exit codes table lacks %q", want)
		}
	}
}

// TestReadmeNamesNoUnreleasedCliCommand: the public CybeDefend CLI has no
// import command, so the README sends a SARIF file with curl instead.
func TestReadmeNamesNoUnreleasedCliCommand(t *testing.T) {
	readme := string(read(t, "README.md"))
	if strings.Contains(readme, "cybedefend import") {
		t.Error("README.md names `cybedefend import`, which the public CLI does not have")
	}
	byo := section(t, readme, "## Bring your own tool")
	if !strings.Contains(byo, "/scan/import/start") {
		t.Error("« Bring your own tool » does not show the import route")
	}
}

// TestDcoChecksOnlyThePullRequestCommits: on a pull request the checkout is
// GitHub's merge commit, which carries no sign-off; the check skips merges.
func TestDcoChecksOnlyThePullRequestCommits(t *testing.T) {
	wf := string(read(t, ".github/workflows/dco.yml"))
	if !strings.Contains(wf, "git log --no-merges") {
		t.Error("dco.yml lists merge commits: GitHub's synthetic merge commit then fails the check")
	}
}

// TestRepositoryIsCybedefendScanners: the action, the GitLab template and the
// Go module are published as CybeDefend/cybedefend-scanners.
func TestRepositoryIsCybedefendScanners(t *testing.T) {
	if !strings.HasPrefix(string(read(t, "go.mod")), "module github.com/cybedefend/cybedefend-scanners\n") {
		t.Error("go.mod does not declare github.com/cybedefend/cybedefend-scanners")
	}
	for _, f := range []string{"README.md", "examples/gitlab/.gitlab-ci.yml", "templates/gitlab/appsec-scanners.gitlab-ci.yml"} {
		if strings.Contains(string(read(t, f)), "CybeDefend/appsec-scanners") {
			t.Errorf("%s names the repository CybeDefend/appsec-scanners", f)
		}
	}
}

// TestThirdPartyNoticesCoverRedistribution: the notices say where an image
// keeps the licences, offer Opengrep's source as LGPL-2.1 section 6 asks, and
// do not call the rebuilt gitleaks unmodified.
func TestThirdPartyNoticesCoverRedistribution(t *testing.T) {
	notices := string(read(t, "THIRD_PARTY_NOTICES.md"))
	for _, want := range []string{"/usr/share/licenses/cybedefend-scanners", "written offer", "opensource@cybedefend.com"} {
		if !strings.Contains(notices, want) {
			t.Errorf("THIRD_PARTY_NOTICES.md does not say %q", want)
		}
	}
	if strings.Contains(notices, "distributed unmodified") {
		t.Error("THIRD_PARTY_NOTICES.md says every tool is distributed unmodified; gitleaks is rebuilt with raised dependencies")
	}
}

// releasedExampleVersion is the release the documentation shows as its
// example: a version that exists, so that a copied example pulls.
const releasedExampleVersion = "1.0.0"

func TestExamplesNameAReleasedVersion(t *testing.T) {
	// The forms that name a scanners release: "such as 1.0.0", "version:
	// 1.0.0", "(`:1.0.0`)", "cybedefend-scanners@<full commit sha> # v1.0.0" and
	// "cybedefend-scanners/v1.0.0/". Other tools' versions are not matched.
	semver := regexp.MustCompile("(?:such as |version: |`:|cybedefend-scanners@[^#\\n]+# v|cybedefend-scanners/v)(\\d+\\.\\d+\\.\\d+)")
	files := []string{
		"README.md",
		"action.yml",
		"examples/github/cybedefend-appsec.yml",
		"examples/gitlab/.gitlab-ci.yml",
		"templates/gitlab/appsec-scanners.gitlab-ci.yml",
	}
	seen := 0
	for _, f := range files {
		for _, m := range semver.FindAllStringSubmatch(string(read(t, f)), -1) {
			seen++
			if m[1] != releasedExampleVersion {
				t.Errorf("%s names version %s (%q), want the released %s", f, m[1], m[0], releasedExampleVersion)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no example version found")
	}
}
