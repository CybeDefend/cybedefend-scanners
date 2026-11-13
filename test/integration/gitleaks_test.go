//go:build integration

package integration

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/json"
	"io"
	"math/big"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
)

const (
	gitleaksImage     = "cybedefend-scanners/gitleaks:dev"
	gitleaksProjectID = "3f8c2a1e-7b4d-4c9e-9a6f-0d1e2f3a4b5c"
	gitleaksToken     = "cdp_integration-test-token"
)

// TestGitleaksImageRedactsAndUploads runs the gitleaks image on a copy of
// testdata/samples/secret-config holding a key generated now, and checks that
// the import API receives the finding but never the key.
func TestGitleaksImageRedactsAndUploads(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not on PATH")
	}
	if err := exec.Command("docker", "image", "inspect", gitleaksImage).Run(); err != nil {
		t.Fatalf("image %s is missing: run `make images` first", gitleaksImage)
	}

	src := copySecretSample(t)
	secret := generateStripeKey(t)
	appendLine(t, filepath.Join(src, "settings.env"), "STRIPE_KEY="+secret)

	api := startSecretFakeAPI(t)
	args := []string{"run", "--rm", "-v", src + ":/src:ro"}
	if runtime.GOOS == "linux" {
		args = append(args, "--network", "host")
	} else {
		args = append(args, "--add-host", "host.docker.internal:host-gateway")
	}
	args = append(args,
		"-e", "CYBEDEFEND_API_URL="+api.url,
		"-e", "CYBEDEFEND_PROJECT_ID="+gitleaksProjectID,
		"-e", "CYBEDEFEND_BRANCH=main",
		"-e", "CYBEDEFEND_TOKEN", // value from this process: not on the docker command line
		gitleaksImage, "--upload",
	)
	cmd := exec.Command("docker", args...)
	cmd.Env = append(os.Environ(), "CYBEDEFEND_TOKEN="+gitleaksToken)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the image failed: %v\n%s", err, output)
	}
	leaks := [][]byte{[]byte(secret), []byte(secret[len(secret)-8:])}
	for _, leak := range append(leaks, []byte(gitleaksToken)) {
		if bytes.Contains(output, leak) {
			t.Fatal("the container printed the secret or the token")
		}
	}

	uploads := api.recorded()
	if len(uploads) != 1 {
		t.Fatalf("the fake API received %d uploads, want 1\n%s", len(uploads), output)
	}
	u := uploads[0]
	if u.fields["type"] != "secret" || u.fields["format"] != "sarif" || u.fields["branch"] != "main" {
		t.Errorf("fields = %v, want type=secret format=sarif branch=main", u.fields)
	}
	if _, ok := u.fields["image"]; ok {
		t.Error("a secret upload carries an image part")
	}
	for _, leak := range leaks {
		for name, data := range map[string][]byte{"request body": u.raw, "SARIF": u.sarif} {
			if bytes.Contains(data, leak) {
				t.Fatalf("the %s holds the secret", name)
			}
		}
	}
	if bytes.Contains(u.sarif, []byte(`"snippet"`)) {
		t.Fatal("the uploaded SARIF holds a snippet")
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
	if err := json.Unmarshal(u.sarif, &log); err != nil {
		t.Fatalf("the uploaded SARIF is not JSON: %v", err)
	}
	for _, run := range log.Runs {
		for _, r := range run.Results {
			for _, l := range r.Locations {
				if r.RuleID == "stripe-access-token" && l.PhysicalLocation.ArtifactLocation.URI == "settings.env" {
					return
				}
			}
		}
	}
	t.Fatalf("no stripe-access-token result at settings.env in the uploaded SARIF:\n%s", u.sarif)
}

// copySecretSample copies the sample to a directory the image's user (uid
// 65532) can read once mounted.
func copySecretSample(t *testing.T) string {
	t.Helper()
	sample, err := filepath.Abs(filepath.Join("..", "..", "testdata", "samples", "secret-config"))
	if err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	if err := os.Chmod(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(sample)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(sample, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

func appendLine(t *testing.T, path, line string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(line + "\n"); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
}

const stripeKeyAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// generateStripeKey builds a Stripe-shaped key from crypto/rand at run time:
// nothing secret-shaped is committed.
func generateStripeKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 24)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(stripeKeyAlphabet))))
		if err != nil {
			t.Fatal(err)
		}
		b[i] = stripeKeyAlphabet[n.Int64()]
	}
	return "sk_" + "live_" + string(b)
}

// secretUpload is one request the fake API accepted.
type secretUpload struct {
	raw    []byte            // the request body as received
	fields map[string]string // every non-file part
	sarif  []byte            // the file part, gunzipped when gzipped
}

type secretFakeAPI struct {
	url     string
	mu      sync.Mutex
	uploads []secretUpload
}

func (a *secretFakeAPI) recorded() []secretUpload {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]secretUpload(nil), a.uploads...)
}

// startSecretFakeAPI serves the import route on every interface, so that the
// container reaches it through the host network (Linux) or
// host.docker.internal (Docker Desktop). internal/fakeapi replaces it in
// a later change.
func startSecretFakeAPI(t *testing.T) *secretFakeAPI {
	t.Helper()
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	api := &secretFakeAPI{}
	host := "host.docker.internal"
	if runtime.GOOS == "linux" {
		host = "127.0.0.1"
	}
	api.url = "http://" + host + ":" + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	route := "/project/" + gitleaksProjectID + "/scan/import/start"
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != route {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+gitleaksToken {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"statusCode":401,"error":"Unauthorized","message":"Invalid token"}`)
			return
		}
		up, err := readSecretUpload(r)
		if err != nil {
			t.Errorf("fake API: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		api.mu.Lock()
		api.uploads = append(api.uploads, up)
		api.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"scanId":"0b9d4c1e-2f3a-4b5c-8d7e-6f5a4b3c2d1e"}`)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return api
}

func readSecretUpload(r *http.Request) (secretUpload, error) {
	up := secretUpload{fields: map[string]string{}}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 60<<20))
	if err != nil {
		return up, err
	}
	up.raw = raw
	_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return up, err
	}
	mr := multipart.NewReader(bytes.NewReader(raw), params["boundary"])
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			return up, nil
		}
		if err != nil {
			return up, err
		}
		data, err := io.ReadAll(p)
		if err != nil {
			return up, err
		}
		if p.FormName() != "file" {
			up.fields[p.FormName()] = string(data)
			continue
		}
		if strings.HasSuffix(p.FileName(), ".gz") || bytes.HasPrefix(data, []byte{0x1f, 0x8b}) {
			zr, err := gzip.NewReader(bytes.NewReader(data))
			if err != nil {
				return up, err
			}
			if data, err = io.ReadAll(zr); err != nil {
				return up, err
			}
		}
		up.sarif = data
	}
}
