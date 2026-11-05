// Package sbom readies a CycloneDX JSON SBOM a tool wrote for the instance:
// a version the instance reads, no path of the pod, within its size limit.
package sbom

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path"
	"path/filepath"
	"strings"
)

// MaxBytes is the largest SBOM sent: the instance's 50 MB, in decimal units.
const MaxBytes = 50 * 1000 * 1000

// The refusals of Prepare. They name no path and no package.
var (
	ErrInvalid     = errors.New("the SBOM is not a CycloneDX JSON document")
	ErrUnsupported = errors.New("the SBOM's CycloneDX version is not one the instance reads (1.4 to 1.7)")
	ErrTooLarge    = errors.New("the SBOM is larger than 50 MB")
)

// specVersions are the CycloneDX versions the instance reads.
var specVersions = map[string]bool{"1.4": true, "1.5": true, "1.6": true, "1.7": true}

// Report counts what Prepare saw and changed.
type Report struct {
	// Components is the number of entries of the document's components.
	Components int
	// Rewritten is the number of strings rewritten relative to the root.
	Rewritten int
}

// Prepare checks that raw is a CycloneDX 1.4 to 1.7 JSON document and
// rewrites every string that is root, or a path under it, relative to root:
// root itself becomes « . » (Trivy names the scanned directory in
// metadata.component.name, and a file's absolute path in
// aquasecurity:trivy:FilePath). Numbers are kept as written. The result is
// MaxBytes at most.
func Prepare(raw []byte, root string) ([]byte, Report, error) {
	return prepare(raw, root, MaxBytes)
}

func prepare(raw []byte, root string, limit int) ([]byte, Report, error) {
	var rep Report
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, rep, ErrInvalid
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, rep, ErrInvalid
	}
	obj, ok := doc.(map[string]any)
	if !ok || obj["bomFormat"] != "CycloneDX" {
		return nil, rep, ErrInvalid
	}
	if v, _ := obj["specVersion"].(string); !specVersions[v] {
		return nil, rep, ErrUnsupported
	}
	if comps, ok := obj["components"].([]any); ok {
		rep.Components = len(comps)
	}

	r := path.Clean("/" + filepath.ToSlash(root))
	doc = relativize(doc, r, &rep.Rewritten)

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return nil, rep, ErrInvalid
	}
	out := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	if len(out) > limit {
		return nil, rep, ErrTooLarge
	}
	return out, rep, nil
}

// relativize walks v and rewrites the strings that are root or under it.
func relativize(v any, root string, n *int) any {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			x[k] = relativize(e, root, n)
		}
		return x
	case []any:
		for i, e := range x {
			x[i] = relativize(e, root, n)
		}
		return x
	case string:
		if rel, ok := under(x, root); ok {
			*n++
			return rel
		}
		return x
	default:
		return v
	}
}

// under returns s relative to root when s is root or a path under it.
func under(s, root string) (string, bool) {
	if root == "/" || !strings.HasPrefix(s, "/") {
		return "", false
	}
	if s == root || s == root+"/" {
		return ".", true
	}
	if rest, ok := strings.CutPrefix(s, root+"/"); ok {
		return rest, true
	}
	return "", false
}
