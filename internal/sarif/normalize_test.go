package sarif

import (
	"bytes"
	"strings"
	"testing"
)

func uris(l *Log) []string {
	var out []string
	for _, run := range l.Runs {
		for _, res := range run.Results {
			for _, loc := range res.Locations {
				if loc.PhysicalLocation != nil && loc.PhysicalLocation.ArtifactLocation != nil {
					out = append(out, loc.PhysicalLocation.ArtifactLocation.URI)
				}
			}
		}
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestNormalizeMakesURIsRelativeToTheSourceRoot(t *testing.T) {
	abs := parseFixture(t, "absolute-uri.sarif")
	r1 := Normalize(abs, NormalizeOptions{SourceRoot: "/src"})
	want := []string{"app/main.py", "app/x.tf", "app/y", "app/z.go"}
	if got := uris(abs); !equalStrings(got, want) {
		t.Fatalf("uris = %q, want %q", got, want)
	}

	base := parseFixture(t, "srcroot.sarif")
	r2 := Normalize(base, NormalizeOptions{SourceRoot: "/src"})
	if got := uris(base); !equalStrings(got, []string{"a.py"}) {
		t.Fatalf("uris = %q, want [a.py]", got)
	}
	al := base.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation
	if al.URIBaseID != "" {
		t.Fatalf("uriBaseId = %q, want it removed", al.URIBaseID)
	}
	if bytes.Contains(writeString(t, base), []byte(`"uriBaseId"`)) {
		t.Fatal("uriBaseId still written")
	}

	if r1.Rewritten+r2.Rewritten != 4 {
		t.Fatalf("Rewritten = %d + %d, want 4", r1.Rewritten, r2.Rewritten)
	}
	if r1.Dropped+r2.Dropped != 0 {
		t.Fatalf("Dropped = %d + %d, want 0", r1.Dropped, r2.Dropped)
	}
}

func TestNormalizeDropsResultsThatEscapeTheRoot(t *testing.T) {
	l := parseFixture(t, "escaping.sarif")
	rep := Normalize(l, NormalizeOptions{SourceRoot: "/src"})
	if rep.Dropped != 2 {
		t.Fatalf("Dropped = %d, want 2", rep.Dropped)
	}
	if n := len(l.Runs[0].Results); n != 2 {
		t.Fatalf("results left = %d, want 2", n)
	}
	if got := uris(l); !equalStrings(got, []string{"app/ok.py"}) {
		t.Fatalf("uris = %q", got)
	}
	out := writeString(t, l)
	if bytes.Contains(out, []byte("passwd")) {
		t.Fatalf("a dropped result was written: %s", out)
	}
}

func TestNormalizeKeepsResultsWithoutLocation(t *testing.T) {
	l := parseFixture(t, "escaping.sarif")
	Normalize(l, NormalizeOptions{SourceRoot: "/src"})
	var found bool
	for _, r := range l.Runs[0].Results {
		if len(r.Locations) == 0 {
			found = true
		}
	}
	if !found {
		t.Fatal("the result without a location was removed")
	}
}

func TestNormalizeDropsEveryEscapingShape(t *testing.T) {
	cases := map[string]string{
		"encoded dots":         `%2e%2e/etc/passwd`,
		"encoded slash":        `app%2f..%2f..%2fetc`,
		"backslashes":          `..\\..\\etc\\passwd`,
		"dots after a folder":  `app/../../etc`,
		"absolute elsewhere":   `/srcother/a.py`,
		"remote file host":     `file://evil.example/src/a.py`,
		"other scheme":         `https://example.com/src/a.py`,
		"the root itself":      `file:///src`,
		"control character":    `app/a%00.py`,
		"relative base climbs": `../`,
	}
	for name, uri := range cases {
		t.Run(name, func(t *testing.T) {
			in := `{"version":"2.1.0","runs":[{"results":[{"locations":[{"physicalLocation":{"artifactLocation":{"uri":"` + uri + `"}}}]}]}]}`
			l, err := Parse(strings.NewReader(in))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			rep := Normalize(l, NormalizeOptions{SourceRoot: "/src"})
			if rep.Dropped != 1 || len(l.Runs[0].Results) != 0 {
				t.Fatalf("Dropped = %d, results = %d (uri %q kept as %q)", rep.Dropped, len(l.Runs[0].Results), uri, uris(l))
			}
		})
	}
}

func TestNormalizeResultIsDroppedWhenAnyLocationEscapes(t *testing.T) {
	in := `{"version":"2.1.0","runs":[{"results":[{"locations":[` +
		`{"physicalLocation":{"artifactLocation":{"uri":"/src/a.py"}}},` +
		`{"physicalLocation":{"artifactLocation":{"uri":"/etc/b"}}}]}]}]}`
	l, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	rep := Normalize(l, NormalizeOptions{SourceRoot: "/src"})
	if rep.Dropped != 1 || rep.Rewritten != 0 || len(l.Runs[0].Results) != 0 {
		t.Fatalf("report = %+v, results = %d", rep, len(l.Runs[0].Results))
	}
}

func TestNormalizeResolvesBaseIDs(t *testing.T) {
	cases := []struct {
		name  string
		bases string
		uri   string
		base  string
		want  string
	}{
		{"chained relative base", `{"ROOT":{"uri":"file:///src/"},"SUB":{"uri":"lib/","uriBaseId":"ROOT"}}`, "x.go", "SUB", "lib/x.go"},
		{"unknown base is the source root", `{}`, "x.go", "MISSING", "x.go"},
		{"base without trailing slash", `{"ROOT":{"uri":"file:///src/app"}}`, "x.go", "ROOT", "app/x.go"},
		{"absolute uri ignores its base", `{"ROOT":{"uri":"file:///elsewhere/"}}`, "/src/x.go", "ROOT", "x.go"},
		{"cycle falls back to the root", `{"A":{"uri":"a/","uriBaseId":"B"},"B":{"uri":"b/","uriBaseId":"A"}}`, "x.go", "A", "b/a/x.go"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := `{"version":"2.1.0","runs":[{"originalUriBaseIds":` + c.bases + `,"results":[{"locations":[{"physicalLocation":{"artifactLocation":{"uri":"` + c.uri + `","uriBaseId":"` + c.base + `"}}}]}]}]}`
			l, err := Parse(strings.NewReader(in))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			Normalize(l, NormalizeOptions{SourceRoot: "/src"})
			if got := uris(l); !equalStrings(got, []string{c.want}) {
				t.Fatalf("uris = %q, want %q", got, c.want)
			}
		})
	}
}

func TestNormalizeKeepsURIsPercentEncoded(t *testing.T) {
	in := `{"version":"2.1.0","runs":[{"results":[` +
		`{"locations":[{"physicalLocation":{"artifactLocation":{"uri":"file:///src/my%20dir/caf%C3%A9.py"}}}]},` +
		`{"locations":[{"physicalLocation":{"artifactLocation":{"uri":"/src/100%.txt"}}}]}]}]}`
	l, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	Normalize(l, NormalizeOptions{SourceRoot: "/src/"})
	want := []string{"my%20dir/caf%C3%A9.py", "100%25.txt"}
	if got := uris(l); !equalStrings(got, want) {
		t.Fatalf("uris = %q, want %q", got, want)
	}
}

func TestNormalizeAgainstTheFilesystemRoot(t *testing.T) {
	in := `{"version":"2.1.0","runs":[{"originalUriBaseIds":{"ROOTPATH":{"uri":"file:///"}},"results":[` +
		`{"locations":[{"physicalLocation":{"artifactLocation":{"uri":"usr/lib/x","uriBaseId":"ROOTPATH"}}}]},` +
		`{"locations":[{"physicalLocation":{"artifactLocation":{"uri":"app/package-lock.json"}}}]}]}]}`
	l, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	rep := Normalize(l, NormalizeOptions{SourceRoot: "/"})
	if rep.Dropped != 0 {
		t.Fatalf("Dropped = %d", rep.Dropped)
	}
	if got := uris(l); !equalStrings(got, []string{"usr/lib/x", "app/package-lock.json"}) {
		t.Fatalf("uris = %q", got)
	}
}

func TestNormalizeDropsSnippetsForSecrets(t *testing.T) {
	l := parseFixture(t, "secret-with-snippet.sarif")
	Normalize(l, NormalizeOptions{SourceRoot: "/src", DropSnippets: true})
	out := writeString(t, l)
	for _, needle := range []string{"snippet", "contextRegion", "EXAMPLE_PLACEHOLDER_VALUE", `ippet`} {
		if bytes.Contains(out, []byte(needle)) {
			t.Fatalf("%q still written: %s", needle, out)
		}
	}
	// The rest of the location survives.
	if !bytes.Contains(out, []byte(`"startLine":2`)) || !bytes.Contains(out, []byte(`config/app.env`)) {
		t.Fatalf("location data lost: %s", out)
	}
}

func TestNormalizeKeepsSnippetsOtherwise(t *testing.T) {
	l := parseFixture(t, "secret-with-snippet.sarif")
	Normalize(l, NormalizeOptions{SourceRoot: "/src"})
	out := writeString(t, l)
	for _, needle := range []string{`"snippet"`, `"contextRegion"`} {
		if !bytes.Contains(out, []byte(needle)) {
			t.Fatalf("%s removed without DropSnippets: %s", needle, out)
		}
	}
}
