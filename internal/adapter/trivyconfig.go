package adapter

// TrivyConfig runs `trivy config` on the source directory: Terraform,
// Kubernetes, Dockerfile, CloudFormation and Helm misconfigurations, uploaded
// as `iac`. Trivy writes `security-severity` on its rules.
//
// It reaches no network: the checks are the ones embedded in the binary
// (--skip-check-update), and Trivy neither checks for a newer version nor
// sends usage data to Aqua (--skip-version-check, --disable-telemetry).
type TrivyConfig struct{}

func init() { Register(TrivyConfig{}) }

// Name is the adapter's name on the command line and in the image name.
func (TrivyConfig) Name() string { return "trivy-config" }

// Type is the import type of a misconfiguration.
func (TrivyConfig) Type() ImportType { return TypeIaC }

// Command writes the SARIF to out. --exit-code 0 is Trivy's default, made
// explicit so that a finding never fails the run.
func (TrivyConfig) Command(src, out string, _ map[string]string) ([]string, bool) {
	return []string{
		"trivy", "config",
		"--format", "sarif",
		"--output", out,
		"--exit-code", "0",
		"--skip-check-update",
		"--skip-version-check",
		"--disable-telemetry",
		"--quiet",
		src,
	}, false
}

// SuccessExitCodes: with --exit-code 0, Trivy exits 0 whatever it found.
func (TrivyConfig) SuccessExitCodes() []int { return []int{0} }
