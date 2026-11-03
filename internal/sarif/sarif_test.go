package sarif

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "sarif", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

func parseFixture(t *testing.T, name string) *Log {
	t.Helper()
	l, err := Parse(bytes.NewReader(fixture(t, name)))
	if err != nil {
		t.Fatalf("Parse(%s): %v", name, err)
	}
	return l
}

func writeString(t *testing.T, l *Log) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := Write(&buf, l); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return buf.Bytes()
}

func TestParseAcceptsMinimal(t *testing.T) {
	l := parseFixture(t, "minimal.sarif")
	if l.Version != "2.1.0" {
		t.Fatalf("version = %q", l.Version)
	}
	if len(l.Runs) != 1 || len(l.Runs[0].Results) != 1 {
		t.Fatalf("runs/results = %d", len(l.Runs))
	}
	if l.Runs[0].Tool.Driver.Name != "example" {
		t.Fatalf("driver name = %q", l.Runs[0].Tool.Driver.Name)
	}
	loc := l.Runs[0].Results[0].Locations[0]
	if loc.PhysicalLocation == nil || loc.PhysicalLocation.ArtifactLocation == nil ||
		loc.PhysicalLocation.ArtifactLocation.URI != "app/main.py" {
		t.Fatalf("location not parsed: %+v", loc)
	}
	if err := Check(l); err != nil {
		t.Fatalf("Check: %v", err)
	}
}

func TestParseStripsBOM(t *testing.T) {
	raw := fixture(t, "bom.sarif")
	if !bytes.HasPrefix(raw, []byte{0xEF, 0xBB, 0xBF}) {
		t.Fatal("fixture bom.sarif must start with a UTF-8 BOM")
	}
	l, err := Parse(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	out := writeString(t, l)
	if bytes.HasPrefix(out, []byte{0xEF, 0xBB, 0xBF}) {
		t.Fatal("Write must not emit a BOM")
	}
	if !bytes.HasPrefix(out, []byte("{")) {
		t.Fatalf("Write output starts with %q", out[:1])
	}
}

func TestParseRefusesNonJSON(t *testing.T) {
	_, err := Parse(bytes.NewReader(fixture(t, "not-json.txt")))
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
}

func TestParseRefusesWrongVersion(t *testing.T) {
	_, err := Parse(bytes.NewReader(fixture(t, "wrong-version.sarif")))
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
}

func TestParseRefusesMalformedShapes(t *testing.T) {
	cases := map[string]string{
		"empty":             ``,
		"array top level":   `[]`,
		"trailing content":  `{"version":"2.1.0","runs":[]} {}`,
		"version not text":  `{"version":2.1,"runs":[]}`,
		"no version":        `{"runs":[]}`,
		"runs not an array": `{"version":"2.1.0","runs":{}}`,
		"results an object": `{"version":"2.1.0","runs":[{"results":{}}]}`,
		"uri a number":      `{"version":"2.1.0","runs":[{"results":[{"locations":[{"physicalLocation":{"artifactLocation":{"uri":1}}}]}]}]}`,
		"too deep":          `{"version":"2.1.0","runs":[],"properties":` + strings.Repeat("[", 20000) + strings.Repeat("]", 20000) + `}`,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(in))
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("err = %v, want ErrInvalid", err)
			}
		})
	}
}

// countingReader yields prefix, then n spaces, counting every byte handed out.
type countingReader struct {
	prefix []byte
	spaces int64
	read   int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n := 0
	for n < len(p) && len(c.prefix) > 0 {
		p[n] = c.prefix[0]
		c.prefix = c.prefix[1:]
		n++
	}
	for n < len(p) && c.spaces > 0 {
		p[n] = ' '
		c.spaces--
		n++
	}
	c.read += int64(n)
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}

func TestParseRefusesAbove200MB(t *testing.T) {
	r := &countingReader{
		prefix: []byte(`{"version":"2.1.0","runs":[{"results":[`),
		spaces: MaxDecompressedBytes + 1,
	}
	_, err := Parse(r)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	if r.read > MaxDecompressedBytes+1 {
		t.Fatalf("read %d bytes, want at most %d", r.read, MaxDecompressedBytes+1)
	}
}

func TestParseAcceptsExactly200MB(t *testing.T) {
	prefix := `{"version":"2.1.0","runs":[]`
	r := &countingReader{prefix: []byte(prefix), spaces: MaxDecompressedBytes - int64(len(prefix)) - 1}
	// Close the object as the very last byte.
	l, err := Parse(io.MultiReader(r, strings.NewReader("}")))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if l.Version != "2.1.0" {
		t.Fatalf("version = %q", l.Version)
	}
}

func logWithResults(runs, resultsPerRun int) *Log {
	l := &Log{Version: "2.1.0"}
	for i := 0; i < runs; i++ {
		r := Run{Results: make([]Result, resultsPerRun)}
		l.Runs = append(l.Runs, r)
	}
	return l
}

func TestCheckRefuses21Runs(t *testing.T) {
	if err := Check(logWithResults(MaxRuns+1, 0)); !errors.Is(err, ErrTooManyRuns) {
		t.Fatalf("err = %v, want ErrTooManyRuns", err)
	}
	if err := Check(logWithResults(MaxRuns, 0)); err != nil {
		t.Fatalf("20 runs: %v", err)
	}
}

func TestCheckRefuses100001Results(t *testing.T) {
	if err := Check(logWithResults(1, MaxResults+1)); !errors.Is(err, ErrTooManyResults) {
		t.Fatalf("err = %v, want ErrTooManyResults", err)
	}
	// The limit is the sum over every run.
	l := logWithResults(2, MaxResults/2)
	l.Runs[1].Results = append(l.Runs[1].Results, Result{})
	if err := Check(l); !errors.Is(err, ErrTooManyResults) {
		t.Fatalf("summed: err = %v, want ErrTooManyResults", err)
	}
}

func TestCheckAccepts100000Results(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[`)
	for i := 0; i < MaxResults; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"message":{"text":"m"}}`)
	}
	b.WriteString(`]}]}`)
	l, err := Parse(strings.NewReader(b.String()))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := Check(l); err != nil {
		t.Fatalf("Check: %v", err)
	}
}

func compact(t *testing.T, b []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := json.Compact(&out, b); err != nil {
		t.Fatalf("compact: %v", err)
	}
	return out.Bytes()
}

func TestWriteRoundTripsUnknownFields(t *testing.T) {
	for _, name := range []string{"two-runs.sarif", "minimal.sarif", "srcroot.sarif", "secret-with-snippet.sarif"} {
		t.Run(name, func(t *testing.T) {
			raw := fixture(t, name)
			l, err := Parse(bytes.NewReader(raw))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			got := writeString(t, l)
			want := compact(t, raw)
			if !bytes.Equal(got, want) {
				t.Fatalf("round trip differs\n got: %s\nwant: %s", got, want)
			}
		})
	}
}

func TestWriteIsMarshalCompatible(t *testing.T) {
	l := parseFixture(t, "two-runs.sarif")
	viaMarshal, err := json.Marshal(l)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	// json.Marshal HTML-escapes what a Marshaler returns, so compare values.
	var a, b any
	if err := json.Unmarshal(viaMarshal, &a); err != nil {
		t.Fatalf("unmarshal Marshal output: %v", err)
	}
	if err := json.Unmarshal(writeString(t, l), &b); err != nil {
		t.Fatalf("unmarshal Write output: %v", err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatal("json.Marshal and Write disagree")
	}
}

func TestDuplicateKeysKeepTheLastValue(t *testing.T) {
	// JSON.parse on the server keeps the last value of a repeated key; the
	// scanner must read and write the same one.
	in := `{"version":"2.1.0","runs":[{"results":[{"locations":[{"physicalLocation":{"artifactLocation":{"uri":"ok.py","uri":"../etc/passwd"}}}]}]}]}`
	l, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got := l.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI
	if got != "../etc/passwd" {
		t.Fatalf("uri = %q, want the last value", got)
	}
	out := writeString(t, l)
	if bytes.Count(out, []byte(`"uri"`)) != 1 {
		t.Fatalf("a repeated key must be written once: %s", out)
	}
}

func TestKeysAreMatchedExactly(t *testing.T) {
	// encoding/json would read "URI" into the uri field; the server would not.
	in := `{"version":"2.1.0","runs":[{"results":[{"locations":[{"physicalLocation":{"artifactLocation":{"URI":"../x"}}}]}]}]}`
	l, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := l.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI; got != "" {
		t.Fatalf("uri = %q, want empty", got)
	}
}
