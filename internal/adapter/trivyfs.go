package adapter

// TrivyCacheDir is where Trivy keeps the vulnerability database it downloads
// at run time. The image creates it for uid 65532; it is never under /src.
const TrivyCacheDir = "/tmp/appsec-scanner/trivy-cache"

// TrivyFs runs `trivy fs` for vulnerabilities in dependency manifests and
// lockfiles (import type sca).
//
// An sca import is the branch's whole dependency picture: the server resolves
// every package it does not report. So the source root is the only target,
// nothing under it is skipped, and no other scanner is mixed in.
type TrivyFs struct{}

func init() { Register(TrivyFs{}) }

// Name implements Adapter.
func (TrivyFs) Name() string { return "trivy-fs" }

// Type implements Adapter.
func (TrivyFs) Type() ImportType { return TypeSCA }

// Command implements Adapter.
func (TrivyFs) Command(src, out string, _ map[string]string) ([]string, bool) {
	return []string{
		"trivy", "fs",
		"--scanners", "vuln",
		"--format", "sarif",
		"--output", out,
		"--exit-code", "0",
		"--cache-dir", TrivyCacheDir,
		// Trivy checks for updates and sends usage data to Aqua by default:
		// neither leaves the scanner.
		"--skip-version-check",
		"--disable-telemetry",
		"--quiet",
		src,
	}, false
}

// SuccessExitCodes implements Adapter: with --exit-code 0, findings exit 0.
func (TrivyFs) SuccessExitCodes() []int { return []int{0} }

// ForwardedEnv implements EnvForwarder: a mirror of the vulnerability
// databases, and TLS verification for that mirror.
func (TrivyFs) ForwardedEnv() []string {
	return []string{"TRIVY_DB_REPOSITORY", "TRIVY_JAVA_DB_REPOSITORY", "TRIVY_INSECURE"}
}
