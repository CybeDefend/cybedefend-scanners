package sarif

import (
	"bytes"
	"encoding/json"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// maxBaseDepth bounds the walk through originalUriBaseIds, as the server does.
const maxBaseDepth = 5

// NormalizeOptions says what Normalize rewrites.
type NormalizeOptions struct {
	// SourceRoot is the directory the tool scanned (for an image: "/").
	SourceRoot string
	// DropSnippets removes every snippet and contextRegion (secret scans).
	DropSnippets bool
}

// NormalizeReport counts what Normalize changed.
type NormalizeReport struct {
	// Rewritten counts the location URIs that were rewritten.
	Rewritten int
	// Dropped counts the results removed because a location URI escapes the
	// source root (or names no file inside it).
	Dropped int
}

// Normalize makes every result location URI relative to the source root,
// percent-encoded and free of uriBaseId; it removes the results whose URI
// escapes the root, and with DropSnippets every snippet and contextRegion.
func Normalize(l *Log, o NormalizeOptions) NormalizeReport {
	var rep NormalizeReport
	root := cleanRoot(o.SourceRoot)
	for ri := range l.Runs {
		run := &l.Runs[ri]
		if run.Results == nil {
			continue
		}
		kept := run.Results[:0]
		for _, res := range run.Results {
			rewritten, ok := normalizeResult(&res, run.OriginalURIBaseIDs, root)
			if !ok {
				rep.Dropped++
				continue
			}
			rep.Rewritten += rewritten
			kept = append(kept, res)
		}
		// Clear the tail so dropped results are not reachable any more.
		for i := len(kept); i < len(run.Results); i++ {
			run.Results[i] = Result{}
		}
		run.Results = kept
	}
	if o.DropSnippets {
		dropSnippets(l)
	}
	return rep
}

func cleanRoot(sourceRoot string) string {
	if sourceRoot == "" {
		return ""
	}
	return path.Clean("/" + filepath.ToSlash(sourceRoot))
}

// normalizeResult rewrites every location of a result, or none of them when
// one escapes the root.
func normalizeResult(res *Result, bases map[string]ArtifactLocation, root string) (int, bool) {
	type change struct {
		al  *ArtifactLocation
		uri string
	}
	var changes []change
	for i := range res.Locations {
		pl := res.Locations[i].PhysicalLocation
		if pl == nil || pl.ArtifactLocation == nil || pl.ArtifactLocation.URI == "" {
			continue
		}
		al := pl.ArtifactLocation
		uri, ok := relativeURI(al, bases, root)
		if !ok {
			return 0, false
		}
		if uri != al.URI || al.URIBaseID != "" {
			changes = append(changes, change{al, uri})
		}
	}
	for _, c := range changes {
		c.al.URI = c.uri
		c.al.URIBaseID = ""
	}
	return len(changes), true
}

// relativeURI resolves a location against its base id and the source root,
// and returns it as a percent-encoded relative reference.
func relativeURI(al *ArtifactLocation, bases map[string]ArtifactLocation, root string) (string, bool) {
	p, ok := decodeURI(al.URI)
	if !ok {
		return "", false
	}
	if !strings.HasPrefix(p, "/") && al.URIBaseID != "" {
		dir, ok := resolveBase(al.URIBaseID, bases, map[string]bool{}, 0)
		if !ok {
			return "", false
		}
		p = joinPath(dir, p)
	}
	rel, ok := relativeTo(p, root)
	if !ok {
		return "", false
	}
	return (&url.URL{Path: rel}).EscapedPath(), true
}

// resolveBase returns the decoded directory a base id names: absolute, or
// relative to the source root. An unknown base id, or a cycle, is the source
// root. A base outside the local filesystem refuses the location.
func resolveBase(id string, bases map[string]ArtifactLocation, seen map[string]bool, depth int) (string, bool) {
	base, known := bases[id]
	if !known || seen[id] || depth >= maxBaseDepth {
		return "", true
	}
	seen[id] = true
	dir, ok := decodeURI(base.URI)
	if !ok {
		return "", false
	}
	if strings.HasPrefix(dir, "/") || base.URIBaseID == "" {
		return dir, true
	}
	parent, ok := resolveBase(base.URIBaseID, bases, seen, depth+1)
	if !ok {
		return "", false
	}
	return joinPath(parent, dir), true
}

func joinPath(dir, p string) string {
	if dir == "" {
		return p
	}
	return strings.TrimSuffix(dir, "/") + "/" + p
}

var otherScheme = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://`)

// decodeURI turns a URI into a decoded slash path: absolute when it starts
// with "/". It refuses a file URI on another host, and any other scheme.
func decodeURI(raw string) (string, bool) {
	s := raw
	if len(s) >= 5 && strings.EqualFold(s[:5], "file:") {
		s = s[5:]
		if strings.HasPrefix(s, "//") {
			s = s[2:]
			host := s
			if i := strings.IndexByte(s, '/'); i >= 0 {
				host, s = s[:i], s[i:]
			} else {
				s = "/"
			}
			if host != "" && !strings.EqualFold(host, "localhost") {
				return "", false
			}
		}
		if s == "" {
			s = "/"
		}
	} else if otherScheme.MatchString(s) {
		return "", false
	}
	// A literal "%" that is not an escape stays as typed.
	if dec, err := url.PathUnescape(s); err == nil {
		s = dec
	}
	return strings.ReplaceAll(s, `\`, "/"), true
}

// relativeTo makes a decoded path relative to root. It refuses a path that
// escapes the root, names the root itself, or holds a control character.
func relativeTo(p, root string) (string, bool) {
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return "", false
		}
	}
	var rel string
	if strings.HasPrefix(p, "/") {
		c := path.Clean(p)
		switch {
		case root == "":
			return "", false
		case root == "/":
			rel = strings.TrimPrefix(c, "/")
		case c == root:
			rel = ""
		case strings.HasPrefix(c, root+"/"):
			rel = c[len(root)+1:]
		default:
			return "", false
		}
	} else {
		rel = path.Clean(p)
		if rel == "." {
			rel = ""
		}
	}
	if rel == "" || rel == ".." || strings.HasPrefix(rel, "../") || strings.HasPrefix(rel, "/") {
		return "", false
	}
	return rel, true
}

// ---- snippets -------------------------------------------------------------

var snippetKeys = map[string]bool{"snippet": true, "contextRegion": true}

func dropSnippets(l *Log) {
	scrubExtra(l.Extra)
	for ri := range l.Runs {
		run := &l.Runs[ri]
		scrubExtra(run.Extra)
		scrubExtra(run.Tool.Extra)
		scrubExtra(run.Tool.Driver.Extra)
		for k, al := range run.OriginalURIBaseIDs {
			scrubExtra(al.Extra)
			run.OriginalURIBaseIDs[k] = al
		}
		for i := range run.Results {
			res := &run.Results[i]
			scrubExtra(res.Extra)
			for j := range res.Locations {
				loc := &res.Locations[j]
				scrubExtra(loc.Extra)
				if pl := loc.PhysicalLocation; pl != nil {
					scrubExtra(pl.Extra)
					if pl.ArtifactLocation != nil {
						scrubExtra(pl.ArtifactLocation.Extra)
					}
				}
			}
		}
	}
}

// scrubExtra removes the snippet keys from m and from every value below it.
func scrubExtra(m map[string]json.RawMessage) {
	for k, v := range m {
		if snippetKeys[k] {
			delete(m, k)
			continue
		}
		m[k] = scrubRaw(v)
	}
}

// scrubRaw rewrites a JSON value without any snippet key, at any depth. A
// value whose bytes cannot name such a key (no escape, no key text) is kept.
func scrubRaw(raw json.RawMessage) json.RawMessage {
	if !bytes.ContainsRune(raw, '\\') && !bytes.Contains(raw, []byte("snippet")) && !bytes.Contains(raw, []byte("contextRegion")) {
		return raw
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var out []byte
	out, err := scrubValue(dec, out)
	if err != nil {
		// Parse validated every value already; never keep a value we could
		// not read through.
		return json.RawMessage("null")
	}
	return out
}

func scrubValue(dec *json.Decoder, out []byte) ([]byte, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			out = append(out, '{')
			first := true
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, _ := kt.(string)
				if snippetKeys[key] {
					var skip json.RawMessage
					if err := dec.Decode(&skip); err != nil {
						return nil, err
					}
					continue
				}
				if !first {
					out = append(out, ',')
				}
				first = false
				out = append(out, encodeString(key)...)
				out = append(out, ':')
				if out, err = scrubValue(dec, out); err != nil {
					return nil, err
				}
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return append(out, '}'), nil
		case '[':
			out = append(out, '[')
			first := true
			for dec.More() {
				if !first {
					out = append(out, ',')
				}
				first = false
				if out, err = scrubValue(dec, out); err != nil {
					return nil, err
				}
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return append(out, ']'), nil
		}
	case string:
		return append(out, encodeString(t)...), nil
	case json.Number:
		return append(out, t.String()...), nil
	case bool:
		if t {
			return append(out, "true"...), nil
		}
		return append(out, "false"...), nil
	case nil:
		return append(out, "null"...), nil
	}
	return out, nil
}
