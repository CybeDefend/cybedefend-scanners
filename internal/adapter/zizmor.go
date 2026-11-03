package adapter

// zizmorTokenKey is the one variable zizmor receives: with it, zizmor runs its
// online audits (it reads the token from its environment, never from argv).
const zizmorTokenKey = "GH_TOKEN"

// Zizmor audits GitHub Actions workflows and composite actions with zizmor
// (MIT). zizmor writes its SARIF to stdout, and with --no-exit-codes exits 0
// whatever it found. Without a GH_TOKEN it runs --offline: no network call,
// no online audit.
type Zizmor struct{}

func init() { Register(Zizmor{}) }

// Name implements Adapter.
func (Zizmor) Name() string { return "zizmor" }

// Type implements Adapter.
func (Zizmor) Type() ImportType { return TypeCICD }

// Command implements Adapter. src is a directory: zizmor collects its
// workflows and actions.
func (Zizmor) Command(src, _ string, env map[string]string) ([]string, bool) {
	argv := []string{"zizmor", "--format", "sarif", "--no-exit-codes"}
	if env[zizmorTokenKey] == "" {
		argv = append(argv, "--offline")
	}
	return append(argv, src), true
}

// SuccessExitCodes implements Adapter: --no-exit-codes leaves 0 for success
// and other codes for a tool failure.
func (Zizmor) SuccessExitCodes() []int { return []int{0} }

// EnvKeys implements EnvPassthrough.
func (Zizmor) EnvKeys() []string { return []string{zizmorTokenKey} }
