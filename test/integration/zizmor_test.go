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
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// zizmorImage is the tag `make images` gives the zizmor image.
const zizmorImage = "cybedefend-scanners/zizmor:dev"

// zizmorUpload is one request the inline import API received.
type zizmorUpload struct {
	Path, Auth, UserAgent string
	Fields                map[string]string
	FileName              string
	SARIF                 []byte
}

// zizmorFakeAPI answers the import route with 202, on every interface so that
// a container on the host network reaches it, and records each upload.
func zizmorFakeAPI(t *testing.T) (string, func() []zizmorUpload) {
	t.Helper()
	var (
		mu      sync.Mutex
		uploads []zizmorUpload
	)
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up := zizmorUpload{Path: r.URL.Path, Auth: r.Header.Get("Authorization"), UserAgent: r.UserAgent(), Fields: map[string]string{}}
		mr, err := r.MultipartReader()
		if err != nil {
			http.Error(w, `{"code":"IMPORT_INVALID_REQUEST"}`, http.StatusBadRequest)
			return
		}
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				http.Error(w, `{"code":"IMPORT_INVALID_REQUEST"}`, http.StatusBadRequest)
				return
			}
			data, _ := io.ReadAll(part)
			if part.FormName() == "file" {
				up.FileName = part.FileName()
				if strings.HasSuffix(up.FileName, ".gz") {
					zr, err := gzip.NewReader(bytes.NewReader(data))
					if err != nil {
						http.Error(w, `{"code":"IMPORT_INVALID_SARIF"}`, http.StatusBadRequest)
						return
					}
					data, _ = io.ReadAll(zr)
				}
				up.SARIF = data
				continue
			}
			up.Fields[part.FormName()] = string(data)
		}
		mu.Lock()
		uploads = append(uploads, up)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"scanId":"00000000-0000-4000-8000-000000000009"}`))
	}))
	srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	port := ln.Addr().(*net.TCPAddr).Port
	return "http://127.0.0.1:" + strconv.Itoa(port), func() []zizmorUpload {
		mu.Lock()
		defer mu.Unlock()
		return append([]zizmorUpload(nil), uploads...)
	}
}

func TestZizmorImageOnWorkflowSample(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not on PATH")
	}
	if err := exec.Command("docker", "image", "inspect", zizmorImage).Run(); err != nil {
		t.Fatalf("image %s is missing: run `make images` first", zizmorImage)
	}
	sample, err := filepath.Abs("../../testdata/samples/cicd-github-actions")
	if err != nil {
		t.Fatal(err)
	}
	apiURL, uploads := zizmorFakeAPI(t)

	const projectID = "00000000-0000-4000-8000-000000000001"
	cmd := exec.Command("docker", "run", "--rm", "--network", "host",
		"-v", sample+":/src:ro",
		"-e", "CYBEDEFEND_API_URL="+apiURL,
		"-e", "CYBEDEFEND_PROJECT_ID="+projectID,
		"-e", "CYBEDEFEND_TOKEN=cdp_integration-test-token",
		"-e", "CYBEDEFEND_BRANCH=main",
		zizmorImage, "--upload")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("docker run: %v\n%s", err, out.String())
	}

	got := uploads()
	if len(got) != 1 {
		t.Fatalf("uploads = %d, want 1\n%s", len(got), out.String())
	}
	up := got[0]
	if up.Path != "/project/"+projectID+"/scan/import/start" {
		t.Errorf("path = %q", up.Path)
	}
	if up.Fields["type"] != "cicd" || up.Fields["format"] != "sarif" || up.Fields["branch"] != "main" {
		t.Errorf("fields = %v, want type=cicd format=sarif branch=main", up.Fields)
	}
	if _, ok := up.Fields["image"]; ok {
		t.Error("a cicd upload carries an image part")
	}
	if !strings.HasPrefix(up.UserAgent, "cybedefend-scanner/") {
		t.Errorf("User-Agent = %q", up.UserAgent)
	}

	var log struct {
		Runs []struct {
			Results []struct {
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
	if err := json.Unmarshal(up.SARIF, &log); err != nil {
		t.Fatalf("uploaded SARIF: %v", err)
	}
	const uri = ".github/workflows/triage.yml"
	found := map[string]bool{}
	for _, run := range log.Runs {
		for _, res := range run.Results {
			for _, loc := range res.Locations {
				if loc.PhysicalLocation.ArtifactLocation.URI != uri {
					continue
				}
				for _, rule := range []string{"dangerous-triggers", "template-injection"} {
					if strings.Contains(res.RuleID, rule) {
						found[rule] = true
					}
				}
			}
		}
	}
	for _, rule := range []string{"dangerous-triggers", "template-injection"} {
		if !found[rule] {
			t.Errorf("no result with a ruleId containing %q at %s", rule, uri)
		}
	}
	if strings.Contains(string(up.SARIF), "cdp_integration-test-token") {
		t.Error("the token is in the uploaded SARIF")
	}
}
