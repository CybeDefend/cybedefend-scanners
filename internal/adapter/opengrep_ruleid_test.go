package adapter

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cybedefend/cybedefend-scanners/internal/sarif"
)

func opengrepFixture(t *testing.T) *sarif.Log {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "sarif", "opengrep-prefixed-ids.sarif"))
	if err != nil {
		t.Fatal(err)
	}
	l, err := sarif.Parse(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return l
}

type ids struct{ rules, results, refs []string }

func ruleIDs(t *testing.T, l *sarif.Log, run int) ids {
	t.Helper()
	var buf bytes.Buffer
	if err := sarif.Write(&buf, l); err != nil {
		t.Fatal(err)
	}
	var v struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID string `json:"ruleId"`
				Rule   *struct {
					ID string `json:"id"`
				} `json:"rule"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	var out ids
	for _, r := range v.Runs[run].Tool.Driver.Rules {
		out.rules = append(out.rules, r.ID)
	}
	for _, r := range v.Runs[run].Results {
		out.results = append(out.results, r.RuleID)
		if r.Rule != nil {
			out.refs = append(out.refs, r.Rule.ID)
		}
	}
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

var _ SARIFRewriter = Opengrep{}

func TestOpengrepGivesThePlainRuleIDOfTheBundledRules(t *testing.T) {
	l := opengrepFixture(t)
	if n := (Opengrep{}).RewriteSARIF(l, "/src", map[string]string{}); n != 3 {
		t.Errorf("RewriteSARIF = %d, want 3", n)
	}
	got := ruleIDs(t, l, 0)
	wantRules := []string{"python-eval", "custom.rules.no-md5", "plain-rule", "opt.cybedefend-scanners.rules.opengrepx.other"}
	if !equal(got.rules, wantRules) {
		t.Errorf("rules = %q, want %q", got.rules, wantRules)
	}
	if !equal(got.results, wantRules) {
		t.Errorf("ruleIds = %q, want %q", got.results, wantRules)
	}
	if !equal(got.refs, []string{"python-eval"}) {
		t.Errorf("rule refs = %q, want [python-eval]", got.refs)
	}
	other := ruleIDs(t, l, 1)
	if !equal(other.rules, []string{"opt.cybedefend-scanners.rules.opengrep.python-eval"}) ||
		!equal(other.results, []string{"opt.cybedefend-scanners.rules.opengrep.python-eval"}) {
		t.Errorf("the run of another tool was changed: %+v", other)
	}
}

func TestOpengrepGivesThePlainRuleIDOfACustomConfigDir(t *testing.T) {
	l := opengrepFixture(t)
	env := map[string]string{OpengrepConfigEnv: "/custom/rules/, /opt/cybedefend-scanners/rules/opengrep"}
	if n := (Opengrep{}).RewriteSARIF(l, "/src", env); n != 5 {
		t.Errorf("RewriteSARIF = %d, want 5", n)
	}
	got := ruleIDs(t, l, 0)
	want := []string{"python-eval", "no-md5", "plain-rule", "opt.cybedefend-scanners.rules.opengrepx.other"}
	if !equal(got.rules, want) || !equal(got.results, want) {
		t.Errorf("rules = %q, ruleIds = %q, want %q", got.rules, got.results, want)
	}
}

func TestOpengrepOverrideReplacesTheBundledPrefix(t *testing.T) {
	// OPENGREP_CONFIG replaces the bundled rules: their directory is not a
	// --config any more, so its prefix is not stripped.
	l := opengrepFixture(t)
	(Opengrep{}).RewriteSARIF(l, "/src", map[string]string{OpengrepConfigEnv: "/custom/rules"})
	got := ruleIDs(t, l, 0)
	want := []string{"opt.cybedefend-scanners.rules.opengrep.python-eval", "no-md5", "plain-rule", "opt.cybedefend-scanners.rules.opengrepx.other"}
	if !equal(got.results, want) {
		t.Errorf("ruleIds = %q, want %q", got.results, want)
	}
}

func TestOpengrepRuleIDPrefixForms(t *testing.T) {
	for _, tc := range []struct {
		config, src string
		want        []string
	}{
		{"/opt/cybedefend-scanners/rules/opengrep", "/src", []string{"opt.cybedefend-scanners.rules.opengrep"}},
		{"/opt/cybedefend-scanners/rules/opengrep/python-eval.yaml", "/src", []string{"opt.cybedefend-scanners.rules.opengrep"}},
		// Opengrep runs in the source directory: a rule set under it is
		// named relative to it.
		{"/src/.rules", "/src", []string{"src..rules", "rules"}},
		{"rules/sast", "/src", []string{"rules.sast", "src.rules.sast"}},
		{"./rules", "/src", []string{"rules", "src.rules"}},
		{".", "/src", []string{"src"}},
	} {
		got := opengrepRulePrefixes(tc.config, tc.src)
		if !equal(got, tc.want) {
			t.Errorf("opengrepRulePrefixes(%q, %q) = %q, want %q", tc.config, tc.src, got, tc.want)
		}
	}
}
