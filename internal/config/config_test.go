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
	if c.Adapter != "opengrep" || c.Source != "/src" || c.Out != "/tmp/cybedefend-scanner/results.sarif" || c.Upload || c.Timeout != 30*time.Minute {
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

func TestImageFromFlagOrEnv(t *testing.T) {
	env := envOf(map[string]string{"CYBEDEFEND_IMAGE": "y:2", "IMAGE_ARCHIVE": "/out/i.tar"})
	c, err := Load([]string{"trivy-image", "--image", "x:1"}, env)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Image != "x:1" {
		t.Errorf("Image = %q, want the --image value x:1", c.Image)
	}
	if c.ImageArchive != "/out/i.tar" {
		t.Errorf("ImageArchive = %q, want /out/i.tar", c.ImageArchive)
	}

	c, err = Load([]string{"trivy-image"}, env)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Image != "y:2" {
		t.Errorf("Image = %q, want CYBEDEFEND_IMAGE y:2", c.Image)
	}

	c, err = Load([]string{"trivy-image", "--image-archive", "/out/j.tar"}, env)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.ImageArchive != "/out/j.tar" {
		t.Errorf("ImageArchive = %q, want the --image-archive value", c.ImageArchive)
	}

	c, err = Load([]string{"trivy-image"}, envOf(nil))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Image != "" || c.ImageArchive != "" {
		t.Errorf("Image = %q, ImageArchive = %q, want both empty", c.Image, c.ImageArchive)
	}
}

// scanRunEnv is the environment a scanner pod receives.
func scanRunEnv() map[string]string {
	return map[string]string{
		"CYBEDEFEND_API_URL":     "https://appsec.example.com/api",
		"CYBEDEFEND_SCAN_ID":     "6f1c2a9e-1b2c-4d3e-8f00-000000000001",
		"CYBEDEFEND_SCAN_TOKEN":  "cdst_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_AbC",
		"CYBEDEFEND_ARCHIVE_URL": "https://storage.example.com/a.zip?X-Amz-Signature=s3cr3t",
	}
}

func TestScanRunReadsItsFourVariables(t *testing.T) {
	c, err := Load([]string{"opengrep", "--scan-run"}, envOf(scanRunEnv()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !c.ScanRun || c.Upload {
		t.Fatalf("ScanRun=%v Upload=%v, want true/false", c.ScanRun, c.Upload)
	}
	env := scanRunEnv()
	if c.APIURL != env["CYBEDEFEND_API_URL"] || c.ScanID != env["CYBEDEFEND_SCAN_ID"] ||
		c.ScanToken != env["CYBEDEFEND_SCAN_TOKEN"] || c.ArchiveURL != env["CYBEDEFEND_ARCHIVE_URL"] {
		t.Fatalf("scan-run fields not read: %+v", c)
	}
}

func TestScanRunNeedsItsFourVariables(t *testing.T) {
	for _, key := range []string{"CYBEDEFEND_API_URL", "CYBEDEFEND_SCAN_ID", "CYBEDEFEND_SCAN_TOKEN", "CYBEDEFEND_ARCHIVE_URL"} {
		t.Run(key, func(t *testing.T) {
			env := scanRunEnv()
			delete(env, key)
			_, err := Load([]string{"opengrep", "--scan-run"}, envOf(env))
			if err == nil {
				t.Fatalf("Load accepted a scan run without %s", key)
			}
			if !strings.Contains(err.Error(), key) {
				t.Errorf("error %q does not name %s", err, key)
			}
			assertNoSecret(t, err)
		})
	}
	// An empty value counts as unset, and an upload's variables do not stand in.
	env := scanRunEnv()
	env["CYBEDEFEND_SCAN_TOKEN"] = ""
	env["CYBEDEFEND_TOKEN"] = "cdp_personal_token"
	if _, err := Load([]string{"opengrep", "--scan-run"}, envOf(env)); err == nil {
		t.Fatal("Load took CYBEDEFEND_TOKEN for the scan token")
	}
}

func TestScanRunChecksTheValues(t *testing.T) {
	cases := map[string]string{
		"CYBEDEFEND_SCAN_ID":     "not-a-uuid",
		"CYBEDEFEND_API_URL":     "ftp://appsec.example.com/api",
		"CYBEDEFEND_ARCHIVE_URL": "file:///etc/passwd?X-Amz-Signature=s3cr3t",
	}
	for key, value := range cases {
		t.Run(key, func(t *testing.T) {
			env := scanRunEnv()
			env[key] = value
			_, err := Load([]string{"opengrep", "--scan-run"}, envOf(env))
			if err == nil {
				t.Fatalf("Load accepted %s=%s", key, value)
			}
			if !strings.Contains(err.Error(), key) {
				t.Errorf("error %q does not name %s", err, key)
			}
			assertNoSecret(t, err)
		})
	}
}

func TestScanRunAndUploadConflict(t *testing.T) {
	env := scanRunEnv()
	env["CYBEDEFEND_PROJECT_ID"] = "p1"
	env["CYBEDEFEND_TOKEN"] = "cdp_personal_token"
	env["CYBEDEFEND_BRANCH"] = "main"
	_, err := Load([]string{"opengrep", "--scan-run", "--upload"}, envOf(env))
	if err == nil {
		t.Fatal("Load accepted --scan-run with --upload")
	}
	if !strings.Contains(err.Error(), "--scan-run") || !strings.Contains(err.Error(), "--upload") {
		t.Errorf("error %q does not name both flags", err)
	}
}

func TestScanRunRefusedForTrivyImage(t *testing.T) {
	env := scanRunEnv()
	env["CYBEDEFEND_IMAGE"] = "alpine:3.20"
	_, err := Load([]string{"trivy-image", "--scan-run"}, envOf(env))
	if err == nil {
		t.Fatal("Load accepted trivy-image --scan-run")
	}
	if !strings.Contains(err.Error(), "trivy-image") {
		t.Errorf("error %q does not name trivy-image", err)
	}
}

func TestWithoutScanRunItsVariablesAreIgnored(t *testing.T) {
	c, err := Load([]string{"opengrep"}, envOf(scanRunEnv()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.ScanRun || c.ScanID != "" || c.ScanToken != "" || c.ArchiveURL != "" {
		t.Fatalf("scan-run fields read without --scan-run: %+v", c)
	}
}

// assertNoSecret fails when err quotes the scan token or the archive URL.
func assertNoSecret(t *testing.T, err error) {
	t.Helper()
	for _, s := range []string{"cdst_", "s3cr3t", "X-Amz-Signature", "storage.example.com"} {
		if strings.Contains(err.Error(), s) {
			t.Errorf("error %q quotes %q", err, s)
		}
	}
}

func TestScanRunAPIURLWithCredentialsNeverSpeaksOfPersonalTokens(t *testing.T) {
	env := scanRunEnv()
	env["CYBEDEFEND_API_URL"] = "https://user:pass@appsec.example.com/api"
	_, err := Load([]string{"opengrep", "--scan-run"}, envOf(env))
	if err == nil {
		t.Fatal("Load accepted an API URL with credentials")
	}
	if !strings.Contains(err.Error(), "CYBEDEFEND_API_URL") || !strings.Contains(err.Error(), "credentials") {
		t.Errorf("error %q", err)
	}
	if strings.Contains(err.Error(), "CYBEDEFEND_TOKEN") || strings.Contains(err.Error(), "pass") {
		t.Errorf("error %q names the personal token or quotes the URL", err)
	}
}

func TestSBOMOutIsOptional(t *testing.T) {
	c, err := Load([]string{"trivy-fs"}, envOf(nil))
	if err != nil || c.SBOMOut != "" {
		t.Fatalf("default SBOMOut = %q, err %v; want none", c.SBOMOut, err)
	}
	c, err = Load([]string{"trivy-fs", "--sbom-out", "/out/results.cdx.json"}, envOf(nil))
	if err != nil || c.SBOMOut != "/out/results.cdx.json" {
		t.Fatalf("SBOMOut = %q, err %v", c.SBOMOut, err)
	}
	if _, err := Load([]string{"trivy-fs", "--sbom-out", "/tmp/cybedefend-scanner/results.sarif"}, envOf(nil)); err == nil {
		t.Fatal("--sbom-out equal to --out was accepted")
	}
}
