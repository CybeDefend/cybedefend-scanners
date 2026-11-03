package upload

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"sync/atomic"
	"testing"
)

// receivedPart is one multipart part as the fake server read it.
type receivedPart struct {
	filename string
	content  []byte
}

// received is what the fake server saw of one request.
type received struct {
	method, path, auth, userAgent string
	values                        map[string]string
	files                         map[string]receivedPart
}

// readRequest parses a multipart request into a received value.
func readRequest(t *testing.T, r *http.Request) received {
	t.Helper()
	got := received{
		method:    r.Method,
		path:      r.URL.Path,
		auth:      r.Header.Get("Authorization"),
		userAgent: r.Header.Get("User-Agent"),
		values:    map[string]string{},
		files:     map[string]receivedPart{},
	}
	mr, err := r.MultipartReader()
	if err != nil {
		t.Errorf("MultipartReader: %v", err)
		return got
	}
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Errorf("NextPart: %v", err)
			return got
		}
		body, err := io.ReadAll(p)
		if err != nil {
			t.Errorf("read part: %v", err)
			return got
		}
		if p.FileName() != "" {
			got.files[p.FormName()] = receivedPart{filename: p.FileName(), content: body}
		} else {
			got.values[p.FormName()] = string(body)
		}
	}
	return got
}

// fakeServer answers 202 {"scanId":"s1"} and hands what it received to the test.
func fakeServer(t *testing.T) (*httptest.Server, *received, *atomic.Int32) {
	t.Helper()
	var got received
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		got = readRequest(t, r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"scanId":"s1"}`)
	}))
	t.Cleanup(srv.Close)
	return srv, &got, &calls
}

func newClient(baseURL string) *Client {
	return &Client{BaseURL: baseURL, Token: "cdp_x", UserAgent: "appsec-scanner/test"}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestImportSendsTheMultipartContract(t *testing.T) {
	srv, got, _ := fakeServer(t)
	sarif := []byte(`{"version":"2.1.0","runs":[]}`)

	resp, err := newClient(srv.URL).Import(context.Background(), Request{ProjectID: "p1", Type: "sast", Branch: "main", SARIF: sarif})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if resp.ScanID != "s1" {
		t.Fatalf("ScanID = %q, want s1", resp.ScanID)
	}
	if got.method != http.MethodPost || got.path != "/project/p1/scan/import/start" {
		t.Fatalf("request = %s %s", got.method, got.path)
	}
	if got.auth != "Bearer cdp_x" {
		t.Fatalf("Authorization header not as expected")
	}
	if got.userAgent != "appsec-scanner/test" {
		t.Fatalf("User-Agent = %q", got.userAgent)
	}
	wantValues := map[string]string{"type": "sast", "branch": "main", "format": "sarif"}
	if !reflect.DeepEqual(got.values, wantValues) {
		t.Fatalf("form values = %v, want %v", got.values, wantValues)
	}
	if len(got.files) != 1 {
		t.Fatalf("file parts = %d, want 1", len(got.files))
	}
	f, ok := got.files["file"]
	if !ok {
		t.Fatalf("no part named file")
	}
	if f.filename != PartName {
		t.Fatalf("filename = %q, want %q", f.filename, PartName)
	}
	if !bytes.Equal(f.content, sarif) {
		t.Fatalf("file content differs from the input")
	}
}

func TestUploadGzipsAboveOneMiB(t *testing.T) {
	srv, got, _ := fakeServer(t)
	sarif := bytes.Repeat([]byte("a"), GzipThresholdBytes+1)

	if _, err := newClient(srv.URL).Import(context.Background(), Request{ProjectID: "p1", Type: "sast", Branch: "main", SARIF: sarif}); err != nil {
		t.Fatalf("Import: %v", err)
	}
	f := got.files["file"]
	if f.filename != PartNameGzip {
		t.Fatalf("filename = %q, want %q", f.filename, PartNameGzip)
	}
	if len(f.content) < 2 || f.content[0] != 0x1f || f.content[1] != 0x8b {
		t.Fatalf("part does not start with the gzip magic")
	}
	zr, err := gzip.NewReader(bytes.NewReader(f.content))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	plain, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("gunzip: %v", err)
	}
	if !bytes.Equal(plain, sarif) {
		t.Fatalf("gunzipped content differs from the input")
	}
}

func TestUploadDoesNotGzipAtOneMiB(t *testing.T) {
	srv, got, _ := fakeServer(t)
	sarif := bytes.Repeat([]byte("a"), GzipThresholdBytes)

	if _, err := newClient(srv.URL).Import(context.Background(), Request{ProjectID: "p1", Type: "sast", Branch: "main", SARIF: sarif}); err != nil {
		t.Fatalf("Import: %v", err)
	}
	f := got.files["file"]
	if f.filename != PartName {
		t.Fatalf("filename = %q, want %q", f.filename, PartName)
	}
	if !bytes.Equal(f.content, sarif) {
		t.Fatalf("content was not sent as is")
	}
}

func TestUploadRefusesAbove50MBCompressed(t *testing.T) {
	srv, _, calls := fakeServer(t)
	sarif := make([]byte, 60*1000*1000)
	if _, err := rand.Read(sarif); err != nil {
		t.Fatalf("rand: %v", err)
	}

	_, err := newClient(srv.URL).Import(context.Background(), Request{ProjectID: "p1", Type: "sast", Branch: "main", SARIF: sarif})
	if !errors.Is(err, ErrTooLargeToUpload) {
		t.Fatalf("err = %v, want ErrTooLargeToUpload", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("the server was called %d times", calls.Load())
	}
}

func TestImportStripsTrailingSlashOfBaseURL(t *testing.T) {
	srv, got, _ := fakeServer(t)

	if _, err := newClient(srv.URL+"/").Import(context.Background(), Request{ProjectID: "p1", Type: "sast", Branch: "main", SARIF: []byte("{}")}); err != nil {
		t.Fatalf("Import: %v", err)
	}
	if got.path != "/project/p1/scan/import/start" {
		t.Fatalf("path = %q", got.path)
	}
}

func TestImportSendsTheImagePartForContainerOnly(t *testing.T) {
	t.Run("container with an image", func(t *testing.T) {
		srv, got, _ := fakeServer(t)
		_, err := newClient(srv.URL).Import(context.Background(), Request{ProjectID: "p1", Type: "container", Branch: "main", Image: "ghcr.io/acme/api:1.4.2", SARIF: []byte("{}")})
		if err != nil {
			t.Fatalf("Import: %v", err)
		}
		want := map[string]string{"type": "container", "branch": "main", "format": "sarif", "image": "ghcr.io/acme/api:1.4.2"}
		if !reflect.DeepEqual(got.values, want) {
			t.Fatalf("form values = %v, want %v", got.values, want)
		}
	})
	t.Run("sca without an image", func(t *testing.T) {
		srv, got, _ := fakeServer(t)
		if _, err := newClient(srv.URL).Import(context.Background(), Request{ProjectID: "p1", Type: "sca", Branch: "main", SARIF: []byte("{}")}); err != nil {
			t.Fatalf("Import: %v", err)
		}
		if want := []string{"branch", "format", "type"}; !reflect.DeepEqual(keys(got.values), want) {
			t.Fatalf("form fields = %v, want %v", keys(got.values), want)
		}
	})
	for _, r := range []Request{
		{ProjectID: "p1", Type: "container", Branch: "main", SARIF: []byte("{}")},
		{ProjectID: "p1", Type: "sca", Branch: "main", Image: "ghcr.io/acme/api:1.4.2", SARIF: []byte("{}")},
	} {
		t.Run("misplaced "+r.Type, func(t *testing.T) {
			srv, _, calls := fakeServer(t)
			_, err := newClient(srv.URL).Import(context.Background(), r)
			if !errors.Is(err, ErrImageMisplaced) {
				t.Fatalf("err = %v, want ErrImageMisplaced", err)
			}
			if calls.Load() != 0 {
				t.Fatalf("the server was called %d times", calls.Load())
			}
		})
	}
}
