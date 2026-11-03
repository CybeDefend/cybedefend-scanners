package adapter

import "strings"

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
// read it.
func (Opengrep) ForwardedEnv() []string { return []string{OpengrepConfigEnv} }

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
