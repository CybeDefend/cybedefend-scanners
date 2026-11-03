// Package sarif reads, checks, normalises and writes SARIF 2.1.0 logs.
//
// Only the fields the scanner touches are typed. Every other member of an
// object is kept as raw JSON, in its original order, so that Write gives back
// what Parse read. Object keys are matched exactly (encoding/json would match
// "URI" to a "uri" field, which the server does not), and a repeated key keeps
// its last value, as JSON.parse does on the server.
//
// Everything in a SARIF file comes from a third-party tool and a user
// repository: sizes, nesting and paths are all treated as untrusted.
package sarif

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
)

// Limits shared with the import API (spec §9).
const (
	MaxDecompressedBytes = 200 << 20
	MaxResults           = 100_000
	MaxRuns              = 20
)

// Errors carry the import error codes, so that callers can print them as is.
var (
	ErrInvalid        = errors.New("IMPORT_INVALID_SARIF")
	ErrTooLarge       = errors.New("IMPORT_TOO_LARGE")
	ErrTooManyResults = errors.New("IMPORT_TOO_MANY_RESULTS")
	ErrTooManyRuns    = errors.New("IMPORT_TOO_MANY_RUNS")
)

const sarifVersion = "2.1.0"

// fields remembers the order of an object's keys and the raw value of each
// typed key, so that an unchanged typed value is written back byte for byte.
type fields struct {
	order []string
	orig  map[string]json.RawMessage
}

// Log is a SARIF log.
type Log struct {
	Version string                     `json:"version"`
	Schema  string                     `json:"$schema,omitempty"`
	Runs    []Run                      `json:"runs"`
	Extra   map[string]json.RawMessage `json:"-"`
	f       fields
}

// Run is one run of one tool.
type Run struct {
	Tool               Tool                        `json:"tool"`
	OriginalURIBaseIDs map[string]ArtifactLocation `json:"originalUriBaseIds,omitempty"`
	Results            []Result                    `json:"results"`
	Extra              map[string]json.RawMessage  `json:"-"`
	f                  fields
	baseOrder          []string
}

// Tool describes the tool of a run.
type Tool struct {
	Driver ToolComponent              `json:"driver"`
	Extra  map[string]json.RawMessage `json:"-"`
	f      fields
}

// ToolComponent is the tool's driver (rules and the rest stay in Extra).
type ToolComponent struct {
	Name  string                     `json:"name"`
	Extra map[string]json.RawMessage `json:"-"`
	f     fields
}

// Result keeps Locations typed and every other field in Extra, so Marshal
// round-trips what we do not touch.
type Result struct {
	Locations []Location                 `json:"locations,omitempty"`
	Extra     map[string]json.RawMessage `json:"-"`
	f         fields
}

// Location is a result location.
type Location struct {
	PhysicalLocation *PhysicalLocation          `json:"physicalLocation,omitempty"`
	Extra            map[string]json.RawMessage `json:"-"`
	f                fields
}

// PhysicalLocation keeps region and contextRegion in Extra.
type PhysicalLocation struct {
	ArtifactLocation *ArtifactLocation          `json:"artifactLocation,omitempty"`
	Extra            map[string]json.RawMessage `json:"-"`
	f                fields
}

// ArtifactLocation is a URI, possibly relative to a base id.
type ArtifactLocation struct {
	URI       string                     `json:"uri,omitempty"`
	URIBaseID string                     `json:"uriBaseId,omitempty"`
	Extra     map[string]json.RawMessage `json:"-"`
	f         fields
}

// Parse reads a SARIF 2.1.0 log. It strips a UTF-8 BOM, refuses more than
// MaxDecompressedBytes with ErrTooLarge, and refuses anything that is not a
// SARIF 2.1.0 JSON object with ErrInvalid.
func Parse(r io.Reader) (*Log, error) {
	lr := &io.LimitedReader{R: r, N: MaxDecompressedBytes + 1}
	br := bufio.NewReader(lr)
	if head, err := br.Peek(3); err == nil && bytes.Equal(head, []byte{0xEF, 0xBB, 0xBF}) {
		_, _ = br.Discard(3)
	}
	data, err := io.ReadAll(br)
	if lr.N <= 0 {
		return nil, ErrTooLarge
	}
	if err != nil {
		return nil, fmt.Errorf("%w: read: %v", ErrInvalid, err)
	}
	if !json.Valid(data) {
		return nil, fmt.Errorf("%w: not a JSON document", ErrInvalid)
	}
	l := &Log{}
	if err := l.UnmarshalJSON(data); err != nil {
		return nil, err
	}
	if l.Version != sarifVersion {
		return nil, fmt.Errorf("%w: version is not %s", ErrInvalid, sarifVersion)
	}
	return l, nil
}

// Check enforces the run and result limits of the import API.
func Check(l *Log) error {
	if len(l.Runs) > MaxRuns {
		return ErrTooManyRuns
	}
	total := 0
	for i := range l.Runs {
		total += len(l.Runs[i].Results)
		if total > MaxResults {
			return ErrTooManyResults
		}
	}
	return nil
}

// Write writes the log as compact JSON, without a BOM.
func Write(w io.Writer, l *Log) error {
	raw, err := l.appendJSON(nil)
	if err != nil {
		return err
	}
	var out bytes.Buffer
	out.Grow(len(raw))
	if err := json.Compact(&out, raw); err != nil {
		return fmt.Errorf("sarif: write: %w", err)
	}
	_, err = w.Write(out.Bytes())
	return err
}

// ---- decoding -------------------------------------------------------------

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// decodeObject splits a JSON object into its members. Keys are compared
// exactly; a repeated key keeps the position of its first occurrence and the
// value of its last one.
func decodeObject(raw json.RawMessage, what string) ([]string, map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, nil, invalid("%s: %v", what, err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, nil, invalid("%s is not an object", what)
	}
	var order []string
	vals := map[string]json.RawMessage{}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, nil, invalid("%s: %v", what, err)
		}
		key, ok := kt.(string)
		if !ok {
			return nil, nil, invalid("%s: key is not a string", what)
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, nil, invalid("%s.%s: %v", what, key, err)
		}
		if _, seen := vals[key]; !seen {
			order = append(order, key)
		}
		vals[key] = v
	}
	if _, err := dec.Token(); err != nil {
		return nil, nil, invalid("%s: %v", what, err)
	}
	return order, vals, nil
}

// take removes the typed keys from vals and records their raw value.
func (f *fields) take(order []string, vals map[string]json.RawMessage, typed ...string) map[string]json.RawMessage {
	f.order = order
	f.orig = map[string]json.RawMessage{}
	for _, k := range typed {
		if v, ok := vals[k]; ok {
			f.orig[k] = v
			delete(vals, k)
		}
	}
	return vals
}

func isNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func decodeString(raw json.RawMessage, what string) (string, error) {
	if isNull(raw) {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", invalid("%s is not a string", what)
	}
	return s, nil
}

// decodeArray returns nil for null, a non-nil slice for an array.
func decodeArray(raw json.RawMessage, what string) ([]json.RawMessage, error) {
	if isNull(raw) {
		return nil, nil
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return nil, invalid("%s is not an array", what)
	}
	items := []json.RawMessage{}
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, invalid("%s: %v", what, err)
	}
	return items, nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (l *Log) UnmarshalJSON(raw []byte) error {
	order, vals, err := decodeObject(raw, "log")
	if err != nil {
		return err
	}
	*l = Log{}
	l.Extra = l.f.take(order, vals, "version", "$schema", "runs")
	if v, ok := l.f.orig["version"]; ok {
		if l.Version, err = decodeString(v, "version"); err != nil {
			return err
		}
	}
	if v, ok := l.f.orig["$schema"]; ok {
		if l.Schema, err = decodeString(v, "$schema"); err != nil {
			return err
		}
	}
	if v, ok := l.f.orig["runs"]; ok {
		items, err := decodeArray(v, "runs")
		if err != nil {
			return err
		}
		if items != nil {
			l.Runs = make([]Run, len(items))
		}
		for i, it := range items {
			if err := l.Runs[i].UnmarshalJSON(it); err != nil {
				return err
			}
		}
	}
	return nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (r *Run) UnmarshalJSON(raw []byte) error {
	order, vals, err := decodeObject(raw, "run")
	if err != nil {
		return err
	}
	*r = Run{}
	r.Extra = r.f.take(order, vals, "tool", "originalUriBaseIds", "results")
	if v, ok := r.f.orig["tool"]; ok && !isNull(v) {
		if err := r.Tool.UnmarshalJSON(v); err != nil {
			return err
		}
	}
	if v, ok := r.f.orig["originalUriBaseIds"]; ok && !isNull(v) {
		keys, bases, err := decodeObject(v, "originalUriBaseIds")
		if err != nil {
			return err
		}
		r.baseOrder = keys
		r.OriginalURIBaseIDs = make(map[string]ArtifactLocation, len(bases))
		for _, k := range keys {
			var al ArtifactLocation
			if err := al.UnmarshalJSON(bases[k]); err != nil {
				return err
			}
			r.OriginalURIBaseIDs[k] = al
		}
	}
	if v, ok := r.f.orig["results"]; ok {
		items, err := decodeArray(v, "results")
		if err != nil {
			return err
		}
		if items != nil {
			r.Results = make([]Result, len(items))
		}
		for i, it := range items {
			if err := r.Results[i].UnmarshalJSON(it); err != nil {
				return err
			}
		}
	}
	return nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (t *Tool) UnmarshalJSON(raw []byte) error {
	order, vals, err := decodeObject(raw, "tool")
	if err != nil {
		return err
	}
	*t = Tool{}
	t.Extra = t.f.take(order, vals, "driver")
	if v, ok := t.f.orig["driver"]; ok && !isNull(v) {
		return t.Driver.UnmarshalJSON(v)
	}
	return nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (c *ToolComponent) UnmarshalJSON(raw []byte) error {
	order, vals, err := decodeObject(raw, "driver")
	if err != nil {
		return err
	}
	*c = ToolComponent{}
	c.Extra = c.f.take(order, vals, "name")
	if v, ok := c.f.orig["name"]; ok {
		c.Name, err = decodeString(v, "driver.name")
	}
	return err
}

// UnmarshalJSON implements json.Unmarshaler.
func (res *Result) UnmarshalJSON(raw []byte) error {
	order, vals, err := decodeObject(raw, "result")
	if err != nil {
		return err
	}
	*res = Result{}
	res.Extra = res.f.take(order, vals, "locations")
	if v, ok := res.f.orig["locations"]; ok {
		items, err := decodeArray(v, "locations")
		if err != nil {
			return err
		}
		if items != nil {
			res.Locations = make([]Location, len(items))
		}
		for i, it := range items {
			if err := res.Locations[i].UnmarshalJSON(it); err != nil {
				return err
			}
		}
	}
	return nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (loc *Location) UnmarshalJSON(raw []byte) error {
	order, vals, err := decodeObject(raw, "location")
	if err != nil {
		return err
	}
	*loc = Location{}
	loc.Extra = loc.f.take(order, vals, "physicalLocation")
	if v, ok := loc.f.orig["physicalLocation"]; ok && !isNull(v) {
		loc.PhysicalLocation = &PhysicalLocation{}
		return loc.PhysicalLocation.UnmarshalJSON(v)
	}
	return nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (p *PhysicalLocation) UnmarshalJSON(raw []byte) error {
	order, vals, err := decodeObject(raw, "physicalLocation")
	if err != nil {
		return err
	}
	*p = PhysicalLocation{}
	p.Extra = p.f.take(order, vals, "artifactLocation")
	if v, ok := p.f.orig["artifactLocation"]; ok && !isNull(v) {
		p.ArtifactLocation = &ArtifactLocation{}
		return p.ArtifactLocation.UnmarshalJSON(v)
	}
	return nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (a *ArtifactLocation) UnmarshalJSON(raw []byte) error {
	order, vals, err := decodeObject(raw, "artifactLocation")
	if err != nil {
		return err
	}
	*a = ArtifactLocation{}
	a.Extra = a.f.take(order, vals, "uri", "uriBaseId")
	if v, ok := a.f.orig["uri"]; ok {
		if a.URI, err = decodeString(v, "artifactLocation.uri"); err != nil {
			return err
		}
	}
	if v, ok := a.f.orig["uriBaseId"]; ok {
		if a.URIBaseID, err = decodeString(v, "artifactLocation.uriBaseId"); err != nil {
			return err
		}
	}
	return nil
}

// ---- encoding -------------------------------------------------------------

// member is one typed member to write: absent ones are skipped.
type member struct {
	key     string
	present bool
	encode  func() ([]byte, error)
}

func encodeString(s string) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s) // a Go string always encodes
	return bytes.TrimRight(buf.Bytes(), "\n")
}

// str writes a typed string: its original bytes when unchanged, nothing when
// emptied, its new value otherwise.
func (f *fields) str(key, val string) member {
	if raw, ok := f.orig[key]; ok {
		if s, err := decodeString(raw, key); err == nil && s == val {
			return member{key: key, present: true, encode: func() ([]byte, error) { return raw, nil }}
		}
	}
	return member{key: key, present: val != "", encode: func() ([]byte, error) { return encodeString(val), nil }}
}

// writeObject writes the members in the original key order, then typed
// members added since, then Extra members added since (sorted).
func writeObject(dst []byte, f *fields, typed []member, extra map[string]json.RawMessage) ([]byte, error) {
	byKey := make(map[string]member, len(typed))
	for _, m := range typed {
		byKey[m.key] = m
	}
	written := make(map[string]bool, len(f.order))
	first := true
	emit := func(key string, val []byte) {
		if !first {
			dst = append(dst, ',')
		}
		first = false
		dst = append(dst, encodeString(key)...)
		dst = append(dst, ':')
		dst = append(dst, val...)
	}
	put := func(key string) error {
		if written[key] {
			return nil
		}
		if m, ok := byKey[key]; ok {
			written[key] = true
			if !m.present {
				return nil
			}
			v, err := m.encode()
			if err != nil {
				return err
			}
			emit(key, v)
			return nil
		}
		if v, ok := extra[key]; ok {
			written[key] = true
			emit(key, v)
		}
		return nil
	}
	dst = append(dst, '{')
	for _, k := range f.order {
		if err := put(k); err != nil {
			return nil, err
		}
	}
	for _, m := range typed {
		if err := put(m.key); err != nil {
			return nil, err
		}
	}
	rest := make([]string, 0)
	for k := range extra {
		if !written[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	for _, k := range rest {
		if err := put(k); err != nil {
			return nil, err
		}
	}
	return append(dst, '}'), nil
}

func (f *fields) has(key string) bool {
	_, ok := f.orig[key]
	return ok
}

// array writes a slice: null for nil, [] for empty.
func array[T any](items []T, enc func(*T, []byte) ([]byte, error)) ([]byte, error) {
	if items == nil {
		return []byte("null"), nil
	}
	out := []byte{'['}
	for i := range items {
		if i > 0 {
			out = append(out, ',')
		}
		var err error
		if out, err = enc(&items[i], out); err != nil {
			return nil, err
		}
	}
	return append(out, ']'), nil
}

func (l *Log) appendJSON(dst []byte) ([]byte, error) {
	return writeObject(dst, &l.f, []member{
		l.f.str("version", l.Version),
		l.f.str("$schema", l.Schema),
		{key: "runs", present: l.Runs != nil || l.f.has("runs"), encode: func() ([]byte, error) {
			return array(l.Runs, (*Run).appendJSON)
		}},
	}, l.Extra)
}

func (r *Run) appendJSON(dst []byte) ([]byte, error) {
	return writeObject(dst, &r.f, []member{
		{key: "tool", present: r.f.has("tool") || !r.Tool.isZero(), encode: func() ([]byte, error) {
			if raw := r.f.orig["tool"]; isNull(raw) && r.Tool.isZero() {
				return raw, nil
			}
			return r.Tool.appendJSON(nil)
		}},
		{key: "originalUriBaseIds", present: r.OriginalURIBaseIDs != nil || r.f.has("originalUriBaseIds"), encode: r.encodeBases},
		{key: "results", present: r.Results != nil || r.f.has("results"), encode: func() ([]byte, error) {
			return array(r.Results, (*Result).appendJSON)
		}},
	}, r.Extra)
}

func (r *Run) encodeBases() ([]byte, error) {
	if r.OriginalURIBaseIDs == nil {
		return []byte("null"), nil
	}
	keys := make([]string, 0, len(r.OriginalURIBaseIDs))
	seen := map[string]bool{}
	for _, k := range r.baseOrder {
		if _, ok := r.OriginalURIBaseIDs[k]; ok {
			keys = append(keys, k)
			seen[k] = true
		}
	}
	var added []string
	for k := range r.OriginalURIBaseIDs {
		if !seen[k] {
			added = append(added, k)
		}
	}
	sort.Strings(added)
	keys = append(keys, added...)
	out := []byte{'{'}
	for i, k := range keys {
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, encodeString(k)...)
		out = append(out, ':')
		al := r.OriginalURIBaseIDs[k]
		var err error
		if out, err = al.appendJSON(out); err != nil {
			return nil, err
		}
	}
	return append(out, '}'), nil
}

func (t *Tool) isZero() bool {
	return t.Driver.Name == "" && len(t.Driver.Extra) == 0 && len(t.Extra) == 0 && len(t.f.order) == 0 && len(t.Driver.f.order) == 0
}

func (t *Tool) appendJSON(dst []byte) ([]byte, error) {
	return writeObject(dst, &t.f, []member{
		{key: "driver", present: true, encode: func() ([]byte, error) {
			if raw, ok := t.f.orig["driver"]; ok && isNull(raw) && t.Driver.Name == "" && len(t.Driver.Extra) == 0 {
				return raw, nil
			}
			return t.Driver.appendJSON(nil)
		}},
	}, t.Extra)
}

func (c *ToolComponent) appendJSON(dst []byte) ([]byte, error) {
	return writeObject(dst, &c.f, []member{c.f.str("name", c.Name)}, c.Extra)
}

func (res *Result) appendJSON(dst []byte) ([]byte, error) {
	return writeObject(dst, &res.f, []member{
		{key: "locations", present: res.Locations != nil || res.f.has("locations"), encode: func() ([]byte, error) {
			return array(res.Locations, (*Location).appendJSON)
		}},
	}, res.Extra)
}

func (loc *Location) appendJSON(dst []byte) ([]byte, error) {
	return writeObject(dst, &loc.f, []member{
		{key: "physicalLocation", present: loc.PhysicalLocation != nil || loc.f.has("physicalLocation"), encode: func() ([]byte, error) {
			if loc.PhysicalLocation == nil {
				return []byte("null"), nil
			}
			return loc.PhysicalLocation.appendJSON(nil)
		}},
	}, loc.Extra)
}

func (p *PhysicalLocation) appendJSON(dst []byte) ([]byte, error) {
	return writeObject(dst, &p.f, []member{
		{key: "artifactLocation", present: p.ArtifactLocation != nil || p.f.has("artifactLocation"), encode: func() ([]byte, error) {
			if p.ArtifactLocation == nil {
				return []byte("null"), nil
			}
			return p.ArtifactLocation.appendJSON(nil)
		}},
	}, p.Extra)
}

func (a *ArtifactLocation) appendJSON(dst []byte) ([]byte, error) {
	return writeObject(dst, &a.f, []member{
		a.f.str("uri", a.URI),
		a.f.str("uriBaseId", a.URIBaseID),
	}, a.Extra)
}

// MarshalJSON implements json.Marshaler.
func (l Log) MarshalJSON() ([]byte, error) { return l.appendJSON(nil) }

// MarshalJSON implements json.Marshaler.
func (r Run) MarshalJSON() ([]byte, error) { return r.appendJSON(nil) }

// MarshalJSON implements json.Marshaler.
func (t Tool) MarshalJSON() ([]byte, error) { return t.appendJSON(nil) }

// MarshalJSON implements json.Marshaler.
func (c ToolComponent) MarshalJSON() ([]byte, error) { return c.appendJSON(nil) }

// MarshalJSON implements json.Marshaler.
func (res Result) MarshalJSON() ([]byte, error) { return res.appendJSON(nil) }

// MarshalJSON implements json.Marshaler.
func (loc Location) MarshalJSON() ([]byte, error) { return loc.appendJSON(nil) }

// MarshalJSON implements json.Marshaler.
func (p PhysicalLocation) MarshalJSON() ([]byte, error) { return p.appendJSON(nil) }

// MarshalJSON implements json.Marshaler.
func (a ArtifactLocation) MarshalJSON() ([]byte, error) { return a.appendJSON(nil) }
