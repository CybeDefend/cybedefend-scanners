package adapter

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/cybedefend/cybedefend-scanners/internal/sarif"
)

// DefaultOpengrepRulesDir is where the opengrep image bundles our rules.
const DefaultOpengrepRulesDir = "/opt/appsec-scanners/rules/opengrep"

// OpengrepConfigEnv overrides the rules: a path, or several, comma-separated.
const OpengrepConfigEnv = "OPENGREP_CONFIG"

// Opengrep runs Opengrep (LGPL-2.1) on our own rules only. Registry rule sets
// (`auto`, `p/…`, `r/…`) carry the Semgrep Rules License and are never named.
type Opengrep struct {
	// RulesDir is the --config used when OPENGREP_CONFIG is unset.
	RulesDir string
}

func init() { Register(Opengrep{}) }

// Name implements Adapter.
func (Opengrep) Name() string { return "opengrep" }

// Type implements Adapter.
func (Opengrep) Type() ImportType { return TypeSAST }

// ForwardedEnv implements EnvForwarder: OPENGREP_CONFIG, so that Command can
// read it, and XDG_CACHE_HOME, where the image unpacked Opengrep's one-file
// binary at build time (otherwise it unpacks itself under HOME at each run).
func (Opengrep) ForwardedEnv() []string { return []string{OpengrepConfigEnv, "XDG_CACHE_HOME"} }

// SuccessExitCodes implements Adapter: Opengrep exits 0 with findings unless
// --error is given, which this adapter never does.
func (Opengrep) SuccessExitCodes() []int { return []int{0} }

// Command implements Adapter. Opengrep has no --metrics flag (it sends no
// metrics); --disable-version-check keeps the run off the network.
func (o Opengrep) Command(src, out string, env map[string]string) ([]string, bool) {
	argv := []string{"opengrep", "scan"}
	for _, c := range o.configs(env[OpengrepConfigEnv]) {
		argv = append(argv, "--config", c)
	}
	argv = append(argv, "--sarif", "--output", out, "--disable-version-check", src)
	return argv, false
}

// configs returns the rule paths. A registry name in OPENGREP_CONFIG is
// dropped; when nothing is left, the bundled rules are used.
func (o Opengrep) configs(override string) []string {
	var paths []string
	for _, p := range strings.Split(override, ",") {
		p = strings.TrimSpace(p)
		if p == "" || isRegistryConfig(p) {
			continue
		}
		paths = append(paths, p)
	}
	if len(paths) > 0 {
		return paths
	}
	if o.RulesDir != "" {
		return []string{o.RulesDir}
	}
	return []string{DefaultOpengrepRulesDir}
}

// isRegistryConfig reports a --config value that Opengrep fetches from a
// rule registry rather than reads from disk.
func isRegistryConfig(c string) bool {
	return c == "auto" || strings.HasPrefix(c, "p/") || strings.HasPrefix(c, "r/") ||
		strings.HasPrefix(c, "s/") || strings.Contains(c, "://")
}

// RewriteSARIF implements SARIFRewriter. Opengrep, like Semgrep, prefixes the
// id of every rule with the dotted path of the directory of its rule file
// (relative to its working directory when under it): the bundled python-eval
// comes out as opt.appsec-scanners.rules.opengrep.python-eval. The platform
// keys findings on the rule id, so the prefix of each --config this adapter
// passed is removed from the rule ids of Opengrep's runs; any other id is kept.
func (o Opengrep) RewriteSARIF(l *sarif.Log, src string, env map[string]string) int {
	var prefixes []string
	seen := map[string]bool{}
	for _, c := range o.configs(env[OpengrepConfigEnv]) {
		for _, p := range opengrepRulePrefixes(c, src) {
			if !seen[p] {
				seen[p] = true
				prefixes = append(prefixes, p+".")
			}
		}
	}
	// The longest prefix first: /r and /r/sub may both be --config.
	sort.SliceStable(prefixes, func(i, j int) bool { return len(prefixes[i]) > len(prefixes[j]) })
	rename := func(id string) (string, bool) {
		for _, p := range prefixes {
			if strings.HasPrefix(id, p) && len(id) > len(p) {
				return id[len(p):], true
			}
		}
		return "", false
	}
	return sarif.RenameRuleIDs(l, func(run *sarif.Run) func(string) (string, bool) {
		name := strings.ToLower(run.Tool.Driver.Name)
		if !strings.Contains(name, "opengrep") && !strings.Contains(name, "semgrep") {
			return nil
		}
		return rename
	})
}

// opengrepRulePrefixes returns the dotted prefixes Opengrep may give the rules
// of one --config (without the trailing dot): the path as given, the absolute
// path, and the path relative to src, the tool's working directory. A rule
// file's prefix is its directory's. Each is the path with "/" read as "." and
// its leading dots and slashes removed, as Semgrep computes it.
func opengrepRulePrefixes(config, src string) []string {
	p := filepath.Clean(config)
	if ext := strings.ToLower(filepath.Ext(p)); ext == ".yaml" || ext == ".yml" {
		p = filepath.Dir(p)
	}
	forms := []string{p}
	abs := p
	if !filepath.IsAbs(p) && src != "" {
		abs = filepath.Join(src, p)
	}
	forms = append(forms, abs)
	if src != "" && filepath.IsAbs(abs) {
		if rel, err := filepath.Rel(filepath.Clean(src), abs); err == nil && rel != ".." && !strings.HasPrefix(rel, "../") {
			forms = append(forms, rel)
		}
	}
	var out []string
	seen := map[string]bool{}
	for _, f := range forms {
		d := strings.TrimLeft(strings.ReplaceAll(filepath.ToSlash(f), "/", "."), "./")
		if d != "" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}
