package config

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestDefaults(t *testing.T) {
	c, err := Load([]string{"opengrep"}, envOf(nil))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Adapter != "opengrep" || c.Source != "/src" || c.Out != "/tmp/appsec-scanner/results.sarif" || c.Upload || c.Timeout != 30*time.Minute {
		t.Fatalf("unexpected defaults: %+v", c)
	}
}

func TestFlagsBeforeAndAfterTheAdapter(t *testing.T) {
	for _, args := range [][]string{
		{"gitleaks", "--source", "/work", "--out", "/o/r.sarif", "--timeout", "5m"},
		{"--source", "/work", "--out", "/o/r.sarif", "gitleaks", "--timeout", "5m"},
	} {
		c, err := Load(args, envOf(nil))
		if err != nil {
			t.Fatalf("Load(%q): %v", args, err)
		}
		if c.Adapter != "gitleaks" || c.Source != "/work" || c.Out != "/o/r.sarif" || c.Timeout != 5*time.Minute {
			t.Fatalf("Load(%q) = %+v", args, c)
		}
	}
}

func TestRefusesBadArguments(t *testing.T) {
	for name, args := range map[string][]string{
		"no adapter":      {},
		"two adapters":    {"opengrep", "gitleaks"},
		"unknown flag":    {"opengrep", "--commit", "abc"},
		"zero timeout":    {"opengrep", "--timeout", "0s"},
		"invalid timeout": {"opengrep", "--timeout", "soon"},
	} {
		if _, err := Load(args, envOf(nil)); err == nil {
			t.Errorf("%s: Load(%q) gave no error", name, args)
		}
	}
}

func TestRelativeSourceIsMadeAbsolute(t *testing.T) {
	c, err := Load([]string{"opengrep", "--source", "."}, envOf(nil))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !strings.HasPrefix(c.Source, "/") {
		t.Fatalf("Source = %q, want an absolute path", c.Source)
	}
}

func TestBranchFallsBackOnCIVariables(t *testing.T) {
	cases := []struct {
		env  map[string]string
		want string
	}{
		{map[string]string{"GITHUB_REF_NAME": "feat/x"}, "feat/x"},
		{map[string]string{"GITHUB_HEAD_REF": "pr-branch", "GITHUB_REF_NAME": "12/merge"}, "pr-branch"},
		{map[string]string{"CI_COMMIT_REF_NAME": "dev"}, "dev"},
		{map[string]string{"CYBEDEFEND_BRANCH": "main", "GITHUB_HEAD_REF": "pr-branch", "CI_COMMIT_REF_NAME": "dev"}, "main"},
		{map[string]string{"GITHUB_HEAD_REF": "", "GITHUB_REF_NAME": "main"}, "main"},
	}
	for _, tc := range cases {
		c, err := Load([]string{"opengrep"}, envOf(tc.env))
		if err != nil {
			t.Fatalf("Load(%v): %v", tc.env, err)
		}
		if c.Branch != tc.want {
			t.Errorf("env %v: Branch = %q, want %q", tc.env, c.Branch, tc.want)
		}
	}
}

func TestNoCommitIsRead(t *testing.T) {
	base := map[string]string{
		"CYBEDEFEND_API_URL": "https://appsec.example.com/api", "CYBEDEFEND_PROJECT_ID": "p1",
		"CYBEDEFEND_TOKEN": "cdp_x", "CYBEDEFEND_BRANCH": "main",
	}
	withSHA := map[string]string{"GITHUB_SHA": "0123456789abcdef", "CI_COMMIT_SHA": "fedcba9876543210"}
	for k, v := range base {
		withSHA[k] = v
	}
	a, err := Load([]string{"opengrep", "--upload"}, envOf(base))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	b, err := Load([]string{"opengrep", "--upload"}, envOf(withSHA))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("commit variables changed the config:\n%+v\n%+v", a, b)
	}
	if strings.Contains(strings.ToLower(reflect.TypeOf(a).String()+fieldNames(a)), "commit") {
		t.Fatalf("Config has a commit field: %s", fieldNames(a))
	}
}

func fieldNames(c Config) string {
	t := reflect.TypeOf(c)
	var names []string
	for i := 0; i < t.NumField(); i++ {
		names = append(names, t.Field(i).Name)
	}
	return strings.Join(names, ",")
}

func TestTokenAcceptsCYBEDEFEND_PAT(t *testing.T) {
	c, err := Load([]string{"opengrep"}, envOf(map[string]string{"CYBEDEFEND_PAT": "cdp_pat"}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Token != "cdp_pat" {
		t.Fatalf("Token = %q, want the CYBEDEFEND_PAT value", c.Token)
	}
	c, err = Load([]string{"opengrep"}, envOf(map[string]string{"CYBEDEFEND_PAT": "cdp_pat", "CYBEDEFEND_TOKEN": "cdp_tok"}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Token != "cdp_tok" {
		t.Fatalf("Token = %q, want CYBEDEFEND_TOKEN to win", c.Token)
	}
}

func TestUploadRequiresProjectTokenBranchAndURL(t *testing.T) {
	full := map[string]string{
		"CYBEDEFEND_API_URL": "https://appsec.example.com/api", "CYBEDEFEND_PROJECT_ID": "p1",
		"CYBEDEFEND_TOKEN": "cdp_secret_value", "CYBEDEFEND_BRANCH": "main",
	}
	c, err := Load([]string{"opengrep", "--upload"}, envOf(full))
	if err != nil {
		t.Fatalf("Load with every variable: %v", err)
	}
	if !c.Upload || c.APIURL != full["CYBEDEFEND_API_URL"] || c.ProjectID != "p1" || c.Branch != "main" || c.Token != full["CYBEDEFEND_TOKEN"] {
		t.Fatalf("unexpected config: %+v", c)
	}
	for _, missing := range []string{"CYBEDEFEND_API_URL", "CYBEDEFEND_PROJECT_ID", "CYBEDEFEND_TOKEN", "CYBEDEFEND_BRANCH"} {
		env := map[string]string{}
		for k, v := range full {
			if k != missing {
				env[k] = v
			}
		}
		_, err := Load([]string{"opengrep", "--upload"}, envOf(env))
		if err == nil {
			t.Errorf("missing %s: no error", missing)
			continue
		}
		if !strings.Contains(err.Error(), missing) {
			t.Errorf("missing %s: error %q does not name it", missing, err)
		}
		if strings.Contains(err.Error(), full["CYBEDEFEND_TOKEN"]) {
			t.Errorf("missing %s: error prints the token", missing)
		}
	}
	// Without --upload nothing is required.
	if _, err := Load([]string{"opengrep"}, envOf(nil)); err != nil {
		t.Fatalf("Load without --upload: %v", err)
	}
}

func TestAPIURLMustBeHTTPWithoutCredentials(t *testing.T) {
	for _, u := range []string{"ftp://x/api", "appsec.example.com", "https://user:pw@appsec.example.com/api", "https:///api"} {
		env := map[string]string{
			"CYBEDEFEND_API_URL": u, "CYBEDEFEND_PROJECT_ID": "p1",
			"CYBEDEFEND_TOKEN": "cdp_x", "CYBEDEFEND_BRANCH": "main",
		}
		_, err := Load([]string{"opengrep", "--upload"}, envOf(env))
		if err == nil {
			t.Errorf("API URL %q accepted", u)
			continue
		}
		if strings.Contains(err.Error(), "pw") {
			t.Errorf("error %q prints the URL's password", err)
		}
	}
}
