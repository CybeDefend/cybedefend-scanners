//go:build integration

package integration

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

const (
	trivyImageImage = "cybedefend-scanners/trivy-image:dev"
	sampleImage     = "cybedefend-scanners-sample:test"
)

// lodashInstalled is the installed metadata of the vulnerable lodash: in an
// image, Trivy reads node_modules/*/package.json, never package-lock.json.
const lodashInstalled = `{"name":"lodash","version":"4.17.20","license":"MIT"}` + "\n"

// buildSampleArchive builds testdata/samples/container-image from a temp
// context (the Dockerfile, the sca-npm lockfiles, lodash's installed
// metadata), saves it to <dir>/image.tar and returns dir.
func buildSampleArchive(t *testing.T) string {
	t.Helper()
	ctx := t.TempDir()
	copyFile := func(from, to string) {
		data, err := os.ReadFile(from)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(ctx, to), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	copyFile("../../testdata/samples/container-image/Dockerfile", "Dockerfile")
	copyFile("../../testdata/samples/sca-npm/package.json", "package.json")
	copyFile("../../testdata/samples/sca-npm/package-lock.json", "package-lock.json")
	if err := os.MkdirAll(filepath.Join(ctx, "node_modules", "lodash"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ctx, "node_modules", "lodash", "package.json"), []byte(lodashInstalled), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("docker", "build", "-t", sampleImage, ctx).CombinedOutput(); err != nil {
		t.Fatalf("docker build: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rmi", "-f", sampleImage).Run() })

	dir := writableDir(t)
	archive := filepath.Join(dir, "image.tar")
	if out, err := exec.Command("docker", "save", "-o", archive, sampleImage).CombinedOutput(); err != nil {
		t.Fatalf("docker save: %v\n%s", err, out)
	}
	// The scanner runs as uid 65532.
	if err := os.Chmod(archive, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

type trivyImageSARIF struct {
	Runs []struct {
		Properties map[string]any `json:"properties"`
		Results    []struct {
			RuleID    string `json:"ruleId"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

func TestTrivyImageOnArchive(t *testing.T) {
	trivyFsSkip(t)
	outDir := buildSampleArchive(t)

	var (
		mu      sync.Mutex
		uploads []trivyFsUpload
	)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/project/11111111-2222-3333-4444-555555555555/scan/import/start" {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseMultipartForm(64 << 20); err != nil {
			http.Error(w, `{"code":"IMPORT_INVALID_REQUEST"}`, http.StatusBadRequest)
			return
		}
		up := trivyFsUpload{fields: r.MultipartForm.Value, auth: r.Header.Get("Authorization")}
		if fh := r.MultipartForm.File["file"]; len(fh) == 1 {
			up.fileName = fh[0].Filename
			f, err := fh[0].Open()
			if err == nil {
				up.file, _ = io.ReadAll(f)
				f.Close()
			}
		}
		mu.Lock()
		uploads = append(uploads, up)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"scanId":"0a1b2c3d-0000-4000-8000-000000000002"}`))
	}))
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	srv.Listener = ln
	srv.Start()
	defer srv.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	argv := []string{"run", "--rm", "--network", "host",
		"-v", outDir + ":/out",
		"-e", "CYBEDEFEND_API_URL=http://127.0.0.1:" + strconv.Itoa(port) + "/api",
		"-e", "CYBEDEFEND_PROJECT_ID=11111111-2222-3333-4444-555555555555",
		"-e", "CYBEDEFEND_TOKEN=cdp_integration_test_token",
		"-e", "CYBEDEFEND_BRANCH=main",
		"-e", "CYBEDEFEND_IMAGE=" + sampleImage,
		"-e", "IMAGE_ARCHIVE=/out/image.tar",
		trivyImageImage, "--upload"}
	out, err := exec.Command("docker", argv...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "cdp_integration_test_token") {
		t.Error("the token was printed")
	}
	if !zeroDropped.MatchString(string(out)) {
		t.Errorf("the normalise report did not log 0 dropped:\n%s", out)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(uploads) != 1 {
		t.Fatalf("%d uploads, want 1", len(uploads))
	}
	up := uploads[0]
	if got := up.fields["type"]; len(got) != 1 || got[0] != "container" {
		t.Errorf("type = %q, want container", got)
	}
	if got := up.fields["image"]; len(got) != 1 || got[0] != sampleImage {
		t.Errorf("image = %q, want %s (the reference, never the archive path)", got, sampleImage)
	}
	if got := up.fields["branch"]; len(got) != 1 || got[0] != "main" {
		t.Errorf("branch = %q, want main", got)
	}
	file := up.file
	if strings.HasSuffix(up.fileName, ".gz") {
		zr, err := gzip.NewReader(bytes.NewReader(file))
		if err != nil {
			t.Fatal(err)
		}
		if file, err = io.ReadAll(zr); err != nil {
			t.Fatal(err)
		}
	}
	if bytes.Contains(file, []byte("cdp_integration_test_token")) {
		t.Error("the token is in the uploaded SARIF")
	}
	var log trivyImageSARIF
	if err := json.Unmarshal(file, &log); err != nil {
		t.Fatalf("the SARIF does not parse: %v", err)
	}
	if len(log.Runs) == 0 || log.Runs[0].Properties["imageName"] == nil || log.Runs[0].Properties["imageID"] == nil {
		t.Errorf("run properties imageName and imageID not kept: %+v", log.Runs)
	}
	found := false
	for _, run := range log.Runs {
		for _, res := range run.Results {
			if res.RuleID == "CVE-2021-23337" && len(res.Locations) > 0 &&
				res.Locations[0].PhysicalLocation.ArtifactLocation.URI == "app/node_modules/lodash/package.json" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("no CVE-2021-23337 result at app/node_modules/lodash/package.json:\n%s", file)
	}
}
