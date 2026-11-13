package sarif

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

type idView struct {
	Runs []struct {
		Tool struct {
			Driver struct {
				Rules []struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID string `json:"ruleId"`
			Rule   *struct {
				ID    string `json:"id"`
				Index int    `json:"index"`
			} `json:"rule"`
		} `json:"results"`
	} `json:"runs"`
}

func viewIDs(t *testing.T, raw []byte) idView {
	t.Helper()
	var v idView
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, raw)
	}
	return v
}

func stripA(run *Run) func(string) (string, bool) {
	if run.Tool.Driver.Name == "gitleaks" {
		return nil
	}
	return func(id string) (string, bool) {
		const p = "opt.cybedefend-scanners.rules.opengrep."
		if strings.HasPrefix(id, p) && len(id) > len(p) {
			return id[len(p):], true
		}
		return "", false
	}
}

func TestRenameRuleIDsRewritesRulesResultsAndRuleReferences(t *testing.T) {
	l := parseFixture(t, "opengrep-prefixed-ids.sarif")
	n := RenameRuleIDs(l, stripA)
	if n != 3 {
		t.Errorf("RenameRuleIDs = %d, want 3 (rule id, ruleId, rule.id)", n)
	}
	v := viewIDs(t, writeString(t, l))
	r0 := v.Runs[0]
	if got := r0.Tool.Driver.Rules[0].ID; got != "python-eval" {
		t.Errorf("rules[0].id = %q, want python-eval", got)
	}
	// Only the id is the key; the rule's name is left as the tool wrote it.
	if got := r0.Tool.Driver.Rules[0].Name; got != "opt.cybedefend-scanners.rules.opengrep.python-eval" {
		t.Errorf("rules[0].name = %q, changed", got)
	}
	if got := r0.Results[0].RuleID; got != "python-eval" {
		t.Errorf("results[0].ruleId = %q, want python-eval", got)
	}
	if r0.Results[0].Rule == nil || r0.Results[0].Rule.ID != "python-eval" || r0.Results[0].Rule.Index != 0 {
		t.Errorf("results[0].rule = %+v, want {python-eval 0}", r0.Results[0].Rule)
	}
	for i, want := range []string{"custom.rules.no-md5", "plain-rule", "opt.cybedefend-scanners.rules.opengrepx.other"} {
		if got := r0.Tool.Driver.Rules[i+1].ID; got != want {
			t.Errorf("rules[%d].id = %q, want %q", i+1, got, want)
		}
		if got := r0.Results[i+1].RuleID; got != want {
			t.Errorf("results[%d].ruleId = %q, want %q", i+1, got, want)
		}
	}
	r1 := v.Runs[1]
	if r1.Tool.Driver.Rules[0].ID != "opt.cybedefend-scanners.rules.opengrep.python-eval" ||
		r1.Results[0].RuleID != "opt.cybedefend-scanners.rules.opengrep.python-eval" {
		t.Errorf("a run the callback skips was changed: %+v", r1)
	}
}

func TestRenameRuleIDsKeepsEverythingElseByteForByte(t *testing.T) {
	before := writeString(t, parseFixture(t, "opengrep-prefixed-ids.sarif"))
	l := parseFixture(t, "opengrep-prefixed-ids.sarif")
	if n := RenameRuleIDs(l, func(*Run) func(string) (string, bool) { return nil }); n != 0 {
		t.Errorf("RenameRuleIDs with no renamer = %d, want 0", n)
	}
	if after := writeString(t, l); !bytes.Equal(before, after) {
		t.Errorf("an unchanged log was rewritten:\n%s\nwant\n%s", after, before)
	}

	l = parseFixture(t, "opengrep-prefixed-ids.sarif")
	RenameRuleIDs(l, stripA)
	after := writeString(t, l)
	want := bytes.ReplaceAll(before, []byte(`"id":"opt.cybedefend-scanners.rules.opengrep.python-eval","name"`), []byte(`"id":"python-eval","name"`))
	want = bytes.Replace(want, []byte(`"ruleId":"opt.cybedefend-scanners.rules.opengrep.python-eval","ruleIndex"`), []byte(`"ruleId":"python-eval","ruleIndex"`), 1)
	want = bytes.Replace(want, []byte(`"rule":{"id":"opt.cybedefend-scanners.rules.opengrep.python-eval","index"`), []byte(`"rule":{"id":"python-eval","index"`), 1)
	if !bytes.Equal(after, want) {
		t.Errorf("more than the ids changed:\n%s\nwant\n%s", after, want)
	}
}
