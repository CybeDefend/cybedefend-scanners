// Package adapter describes how each open-source tool is run, and keeps the
// registry of the adapters the command knows.
package adapter

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/cybedefend/cybedefend-scanners/internal/sarif"
)

// ImportType is the `type` part of the import route.
type ImportType string

// The six import types of the contract.
const (
	TypeSAST      ImportType = "sast"
	TypeIaC       ImportType = "iac"
	TypeSecret    ImportType = "secret"
	TypeCICD      ImportType = "cicd"
	TypeSCA       ImportType = "sca"
	TypeContainer ImportType = "container"
)

// Valid reports whether t is one of the six import types.
func (t ImportType) Valid() bool {
	switch t {
	case TypeSAST, TypeIaC, TypeSecret, TypeCICD, TypeSCA, TypeContainer:
		return true
	}
	return false
}

// Adapter runs one tool.
type Adapter interface {
	// Name is the adapter's name on the command line and in the image name.
	Name() string
	// Type is the import type its results are uploaded as.
	Type() ImportType
	// Command returns the tool's argv (never through a shell), and whether
	// the tool writes its SARIF to stdout instead of to out. env is exactly
	// the environment the tool will run with.
	Command(src, out string, env map[string]string) (argv []string, sarifOnStdout bool)
	// SuccessExitCodes are the exit codes that mean « ran », findings or not.
	SuccessExitCodes() []int
}

// QuietAdapter is an adapter whose tool says, by an exit code and its own
// words, that the source holds nothing it audits (zizmor on a repository
// without GitHub Actions). The runner then answers an empty SARIF instead of
// a failure: no input is no finding, not a broken scanner.
type QuietAdapter interface {
	Adapter
	// NothingToAudit reports whether this exit code and the end of the tool's
	// output mean « nothing to audit ». It must match the tool's own sentence,
	// never an exit code alone.
	NothingToAudit(exitCode int, output []byte) bool
}

// ImageAdapter is an adapter that scans a container image rather than the
// source directory (trivy-image). The command binds it to the image the user
// named before running it.
type ImageAdapter interface {
	Adapter
	// WithImage returns the adapter bound to one image; archive is the path
	// of a `docker save` tar inside the container, or "".
	WithImage(image, archive string) Adapter
	// SourceRoot is the root Normalize uses for this adapter's URIs: "/",
	// the image root, never the mounted source.
	SourceRoot() string
}

// maxImageLength is the contract's cap on the image part.
const maxImageLength = 255

// ImagePattern is the image reference the import route accepts
// (the import contract, verbatim): registry/name[:tag][@sha256:digest].
var ImagePattern = regexp.MustCompile(`^(?:[a-z0-9.-]+(?::[0-9]{1,5})?/)?[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*(?::[A-Za-z0-9_][A-Za-z0-9._-]{0,127})?(?:@sha256:[a-f0-9]{64})?$`)

// ValidImage reports whether ref may be sent as the image part: it matches
// ImagePattern and holds 255 characters at most.
func ValidImage(ref string) bool {
	return ref != "" && len(ref) <= maxImageLength && ImagePattern.MatchString(ref)
}

// EnvForwarder is implemented by an adapter whose tool needs environment
// variables besides PATH, HOME and TMPDIR (OPENGREP_CONFIG for opengrep,
// GH_TOKEN for zizmor, the database mirrors for trivy-fs, the database mirrors
// and registry credentials for trivy-image): the keys are copied
// from the runner's environment to the tool's when set. A CYBEDEFEND_* key is
// never copied, even when listed.
type EnvForwarder interface {
	ForwardedEnv() []string
}

// SARIFRewriter is implemented by an adapter whose tool writes something the
// platform must not read as is: the command calls RewriteSARIF after the SARIF
// was parsed and checked, before it is normalised and uploaded. src is the
// directory the tool ran in and scanned, env the tool's environment. It
// returns the number of values rewritten.
type SARIFRewriter interface {
	RewriteSARIF(l *sarif.Log, src string, env map[string]string) int
}

// forbiddenEnvPrefix marks this program's own variables, the token among them.
const forbiddenEnvPrefix = "CYBEDEFEND_"

// ToolEnvKeys returns the keys an adapter declares through EnvForwarder, in
// order, without duplicates, empty keys or CYBEDEFEND_* keys.
func ToolEnvKeys(a Adapter) []string {
	var declared []string
	if f, ok := a.(EnvForwarder); ok {
		declared = f.ForwardedEnv()
	}
	keys := make([]string, 0, len(declared))
	seen := make(map[string]bool, len(declared))
	for _, k := range declared {
		if k == "" || seen[k] || strings.HasPrefix(strings.ToUpper(k), forbiddenEnvPrefix) {
			continue
		}
		seen[k] = true
		keys = append(keys, k)
	}
	return keys
}

var (
	mu       sync.RWMutex
	registry = map[string]Adapter{}
)

// Register adds an adapter. It panics on a nil adapter, an empty or taken
// name, or an unknown import type: these are programming errors, found at
// start-up.
func Register(a Adapter) {
	if a == nil {
		panic("adapter: Register(nil)")
	}
	name := a.Name()
	if name == "" {
		panic("adapter: empty name")
	}
	if !a.Type().Valid() {
		panic(fmt.Sprintf("adapter: %s has unknown import type %q", name, a.Type()))
	}
	mu.Lock()
	defer mu.Unlock()
	if _, dup := registry[name]; dup {
		panic(fmt.Sprintf("adapter: %s registered twice", name))
	}
	registry[name] = a
}

// Get returns the adapter registered under name.
func Get(name string) (Adapter, bool) {
	mu.RLock()
	defer mu.RUnlock()
	a, ok := registry[name]
	return a, ok
}

// Names returns the registered names, sorted.
func Names() []string {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
