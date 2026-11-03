// Package adapter describes how each open-source tool is run, and keeps the
// registry of the adapters the command knows.
package adapter

import (
	"fmt"
	"sort"
	"sync"
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

// EnvPassthrough is implemented by an adapter whose tool needs environment
// variables besides PATH, HOME and TMPDIR (GH_TOKEN for zizmor, the registry
// credentials for trivy-image). CYBEDEFEND_* keys are never passed, even when
// listed.
type EnvPassthrough interface {
	EnvKeys() []string
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
