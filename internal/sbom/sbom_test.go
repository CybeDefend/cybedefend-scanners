package sbom

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// trivyDoc is the shape `trivy convert --format cyclonedx` writes for a
// source scanned at /src/repo-abc123 (the archive's top folder).
const trivyDoc = `{
  "$schema": "http://cyclonedx.org/schema/bom-1.7.schema.json",
  "bomFormat": "CycloneDX",
  "specVersion": "1.7",
  "version": 1,
  "metadata": {
    "component": {"bom-ref": "root", "type": "application", "name": "/src/repo-abc123",
      "properties": [{"name": "aquasecurity:trivy:SchemaVersion", "value": "2"}]}
  },
  "components": [
    {"bom-ref": "app", "type": "application", "name": "web/package-lock.json"},
    {"bom-ref": "pkg:npm/lodash@4.17.20", "type": "library", "name": "lodash", "version": "4.17.20",
      "purl": "pkg:npm/lodash@4.17.20", "licenses": [{"license": {"id": "MIT"}}]},
    {"bom-ref": "jar", "type": "library", "name": "log4j-core", "version": "2.14.1",
      "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
      "properties": [{"name": "aquasecurity:trivy:FilePath", "value": "/src/repo-abc123/lib/log4j-core-2.14.1.jar"},
        {"name": "note", "value": "/src/repo-abc123-other/x"},
        {"name": "size", "value": 12345678901234567890}]}
  ],
  "dependencies": [{"ref": "root", "dependsOn": ["app"]}, {"ref": "app", "dependsOn": ["pkg:npm/lodash@4.17.20"]}]
}`

func TestPrepareMakesThePathsRelativeToTheSourceRoot(t *testing.T) {
	out, rep, err := Prepare([]byte(trivyDoc), "/src/repo-abc123")
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if strings.Contains(string(out), "/src/repo-abc123/") || strings.Contains(string(out), `"/src/repo-abc123"`) {
		t.Fatalf("the SBOM still names the pod's path:\n%s", out)
	}
	var doc struct {
		Metadata struct {
			Component struct{ Name string } `json:"component"`
		} `json:"metadata"`
		Components []struct {
			Name       string `json:"name"`
			Properties []struct {
				Name  string          `json:"name"`
				Value json.RawMessage `json:"value"`
			} `json:"properties"`
		} `json:"components"`
		Dependencies []struct {
			Ref string `json:"ref"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("the prepared SBOM does not parse: %v", err)
	}
	if doc.Metadata.Component.Name != "." {
		t.Errorf("root component name = %q, want .", doc.Metadata.Component.Name)
	}
	props := map[string]string{}
	for _, p := range doc.Components[2].Properties {
		props[p.Name] = string(p.Value)
	}
	if props["aquasecurity:trivy:FilePath"] != `"lib/log4j-core-2.14.1.jar"` {
		t.Errorf("FilePath = %s, want the path relative to the source", props["aquasecurity:trivy:FilePath"])
	}
	// a sibling folder sharing the prefix is not under the root
	if props["note"] != `"/src/repo-abc123-other/x"` {
		t.Errorf("note = %s, want it untouched", props["note"])
	}
	// numbers are kept as written, not through a float64
	if props["size"] != "12345678901234567890" {
		t.Errorf("size = %s, want 12345678901234567890", props["size"])
	}
	if doc.Components[0].Name != "web/package-lock.json" || len(doc.Dependencies) != 2 {
		t.Errorf("relative names or the graph changed: %+v", doc)
	}
	if rep.Components != 3 || rep.Rewritten != 2 {
		t.Errorf("report = %+v, want 3 components, 2 rewritten", rep)
	}
}

func TestPrepareKeepsAnHTMLCharacterAsWritten(t *testing.T) {
	in := strings.Replace(trivyDoc, `"name": "lodash"`, `"name": "a<b>&c"`, 1)
	out, _, err := Prepare([]byte(in), "/src/repo-abc123")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"a<b>&c"`) {
		t.Fatalf("the name was escaped:\n%s", out)
	}
}

func TestPrepareAcceptsTheVersionsTheInstanceReads(t *testing.T) {
	for _, v := range []string{"1.4", "1.5", "1.6", "1.7"} {
		in := strings.Replace(trivyDoc, `"specVersion": "1.7"`, `"specVersion": "`+v+`"`, 1)
		if _, _, err := Prepare([]byte(in), "/src/repo-abc123"); err != nil {
			t.Errorf("specVersion %s: %v", v, err)
		}
	}
	for _, v := range []string{"1.3", "1.8", "2.0", ""} {
		in := strings.Replace(trivyDoc, `"specVersion": "1.7"`, `"specVersion": "`+v+`"`, 1)
		if _, _, err := Prepare([]byte(in), "/src/repo-abc123"); !errors.Is(err, ErrUnsupported) {
			t.Errorf("specVersion %q: err = %v, want ErrUnsupported", v, err)
		}
	}
}

func TestPrepareRefusesWhatIsNotCycloneDXJSON(t *testing.T) {
	for name, in := range map[string]string{
		"not JSON":       `{"bomFormat":`,
		"not an object":  `[1,2]`,
		"SPDX":           `{"spdxVersion":"SPDX-2.3"}`,
		"other format":   `{"bomFormat":"SPDX","specVersion":"1.6"}`,
		"trailing data":  `{"bomFormat":"CycloneDX","specVersion":"1.6"} {}`,
		"empty document": ``,
	} {
		if _, _, err := Prepare([]byte(in), "/src"); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
}

func TestPrepareRefusesAnSBOMAboveTheLimit(t *testing.T) {
	if MaxBytes != 50*1000*1000 {
		t.Fatalf("MaxBytes = %d, want 50 MB (the instance's limit)", MaxBytes)
	}
	if _, _, err := prepare([]byte(trivyDoc), "/src/repo-abc123", 100); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
}
