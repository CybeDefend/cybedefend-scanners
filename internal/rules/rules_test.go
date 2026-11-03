// Package rules checks the Opengrep rules the opengrep image bundles.
package rules

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// dir is rules/opengrep, from this package's directory.
var dir = filepath.Join("..", "..", "rules", "opengrep")

// wantIDs are the twelve starter rules.
var wantIDs = []string{
	"go-exec-command-shell",
	"java-runtime-exec-concat",
	"javascript-child-process-exec-concat",
	"javascript-eval",
	"javascript-innerhtml-assignment",
	"python-eval",
	"python-exec",
	"python-flask-debug-true",
	"python-pickle-loads",
	"python-sql-string-format",
	"python-subprocess-shell-true",
	"python-yaml-unsafe-load",
}

type rule struct {
	ID        string         `yaml:"id"`
	Message   string         `yaml:"message"`
	Languages []string       `yaml:"languages"`
	Severity  string         `yaml:"severity"`
	Metadata  map[string]any `yaml:"metadata"`
}

type ruleFile struct {
	path  string
	rules []rule
}

func ruleFiles(t *testing.T) []ruleFile {
	t.Helper()
	var paths []string
	for _, ext := range []string{"*.yaml", "*.yml"} {
		m, err := filepath.Glob(filepath.Join(dir, ext))
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, m...)
	}
	if len(paths) == 0 {
		t.Fatalf("no rules in %s", dir)
	}
	sort.Strings(paths)
	out := make([]ruleFile, 0, len(paths))
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Rules []rule `yaml:"rules"`
		}
		if err := yaml.Unmarshal(data, &doc); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if len(doc.Rules) == 0 {
			t.Errorf("%s: no rules", p)
		}
		out = append(out, ruleFile{path: p, rules: doc.Rules})
	}
	return out
}

var cweRe = regexp.MustCompile(`^CWE-\d+`)

// cwes returns metadata.cwe as a list, whether written as a string or a list.
func cwes(v any) []string {
	switch c := v.(type) {
	case string:
		return []string{c}
	case []any:
		out := make([]string, 0, len(c))
		for _, e := range c {
			s, _ := e.(string)
			out = append(out, s)
		}
		return out
	}
	return nil
}

func TestEveryBundledRuleCarriesApacheLicense(t *testing.T) {
	for _, f := range ruleFiles(t) {
		for _, r := range f.rules {
			where := f.path + ": " + r.ID
			if r.ID == "" {
				t.Errorf("%s: a rule has no id", f.path)
			}
			if strings.TrimSpace(r.Message) == "" {
				t.Errorf("%s: no message", where)
			}
			if len(r.Languages) == 0 {
				t.Errorf("%s: no languages", where)
			}
			switch r.Severity {
			case "ERROR", "WARNING", "INFO":
			default:
				t.Errorf("%s: severity %q, want ERROR, WARNING or INFO", where, r.Severity)
			}
			cs := cwes(r.Metadata["cwe"])
			if len(cs) == 0 {
				t.Errorf("%s: no metadata.cwe", where)
			}
			for _, c := range cs {
				if !cweRe.MatchString(c) {
					t.Errorf("%s: metadata.cwe %q does not start with CWE-<n>", where, c)
				}
			}
			sev, ok := r.Metadata["security-severity"].(string)
			if !ok {
				t.Errorf("%s: metadata.security-severity is %v, want a quoted number", where, r.Metadata["security-severity"])
			} else if v, err := strconv.ParseFloat(sev, 64); err != nil || v <= 0 || v > 10 {
				t.Errorf("%s: metadata.security-severity %q is not a number in (0, 10]", where, sev)
			}
			if lic, _ := r.Metadata["license"].(string); lic != "Apache-2.0" {
				t.Errorf("%s: metadata.license %q, want Apache-2.0", where, r.Metadata["license"])
			}
		}
	}
}

func TestRuleIdsAreTheTwelveListed(t *testing.T) {
	var got []string
	seen := map[string]bool{}
	for _, f := range ruleFiles(t) {
		for _, r := range f.rules {
			if seen[r.ID] {
				t.Errorf("rule id %q is declared twice", r.ID)
			}
			seen[r.ID] = true
			got = append(got, r.ID)
		}
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(wantIDs, ",") {
		t.Errorf("rule ids = %v\nwant %v", got, wantIDs)
	}
}

func TestEveryRuleHasAnAnnotatedTestFile(t *testing.T) {
	for _, f := range ruleFiles(t) {
		base := strings.TrimSuffix(f.path, filepath.Ext(f.path))
		siblings, err := filepath.Glob(base + ".*")
		if err != nil {
			t.Fatal(err)
		}
		var text strings.Builder
		for _, s := range siblings {
			if ext := filepath.Ext(s); ext == ".yaml" || ext == ".yml" {
				continue
			}
			data, err := os.ReadFile(s)
			if err != nil {
				t.Fatal(err)
			}
			text.Write(data)
			text.WriteString("\n")
		}
		for _, r := range f.rules {
			for _, tag := range []string{"ruleid", "ok"} {
				re := regexp.MustCompile(`(?m)\b` + tag + `:\s*(?:[\w-]+,\s*)*` + regexp.QuoteMeta(r.ID) + `(?:[\s,]|$)`)
				if !re.MatchString(text.String()) {
					t.Errorf("%s: no sibling test file holds a %q comment for %s", f.path, tag+": "+r.ID, r.ID)
				}
			}
		}
	}
}
