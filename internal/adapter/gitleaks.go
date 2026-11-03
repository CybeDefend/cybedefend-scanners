package adapter

// Gitleaks runs Gitleaks v8 on the files of the source directory, never on
// its git history: an import records current paths (spec §9). The match is
// redacted (--redact=100), so the SARIF never carries the secret; Normalize
// also drops every snippet of a secret scan. Gitleaks exits 1 when it finds
// a leak, so --exit-code 0 keeps findings a success.
type Gitleaks struct{}

func init() { Register(Gitleaks{}) }

// Name is the adapter's name.
func (Gitleaks) Name() string { return "gitleaks" }

// Type is secret.
func (Gitleaks) Type() ImportType { return TypeSecret }

// Command is `gitleaks dir <src>` with a redacted SARIF report written to out.
func (Gitleaks) Command(src, out string, _ map[string]string) ([]string, bool) {
	return []string{
		"gitleaks", "dir", src,
		"--report-format", "sarif",
		"--report-path", out,
		"--redact=100",
		"--no-banner",
		"--exit-code", "0",
	}, false
}

// SuccessExitCodes is 0 only: with --exit-code 0, any other code is a failure.
func (Gitleaks) SuccessExitCodes() []int { return []int{0} }
