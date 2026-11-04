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
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// scanToken has the shape of a real per-scan token: no error may quote it.
const scanToken = "cdst_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_AbC"

// fastRetries shortens the retry delays for the duration of the test.
func fastRetries(t *testing.T) {
	t.Helper()
	old := scanRunRetryDelays
	scanRunRetryDelays = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	t.Cleanup(func() { scanRunRetryDelays = old })
}

// scanRunClient returns a client for srv carrying the scan token.
func scanRunClient(srv *httptest.Server) *Client {
	return &Client{BaseURL: srv.URL + "/api/", Token: scanToken, HTTP: srv.Client(), UserAgent: "appsec-scanner/test"}
}

// answer writes a JSON refusal with the given code.
func answer(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if code != "" {
		_, _ = io.WriteString(w, `{"statusCode":`+strconv.Itoa(status)+`,"code":"`+code+`","message":"`+scanToken+`"}`)
	}
}

func TestScanRunRetryDelays(t *testing.T) {
	want := []time.Duration{time.Second, 5 * time.Second, 15 * time.Second}
	if len(scanRunRetryDelays) != len(want) {
		t.Fatalf("retry delays = %v, want %v", scanRunRetryDelays, want)
	}
	for i := range want {
		if scanRunRetryDelays[i] != want[i] {
			t.Errorf("retry delay %d = %v, want %v", i, scanRunRetryDelays[i], want[i])
		}
	}
	if ScanProtocolVersion != 1 {
		t.Errorf("ScanProtocolVersion = %d, want 1", ScanProtocolVersion)
	}
}

func TestScanRunSendsHeadersAndFile(t *testing.T) {
	var got received
	var protocol, accept string
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		protocol = r.Header.Get("X-CybeDefend-Scan-Protocol")
		accept = r.Header.Get("Accept")
		got = readRequest(t, r)
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"accepted":true}`)
	}))
	defer srv.Close()
	sarif := []byte(`{"version":"2.1.0","runs":[]}`)

	if err := scanRunClient(srv).SubmitScanRun(context.Background(), "scan-1", sarif); err != nil {
		t.Fatalf("SubmitScanRun: %v", err)
	}
	if calls.Load() != 1 {
		t.Errorf("requests = %d, want 1", calls.Load())
	}
	if got.method != http.MethodPost {
		t.Errorf("method = %s", got.method)
	}
	if got.path != "/api/scan-runs/scan-1/results" {
		t.Errorf("path = %s", got.path)
	}
	if got.auth != "Bearer "+scanToken {
		t.Errorf("Authorization = %q", got.auth)
	}
	if protocol != "1" {
		t.Errorf("X-CybeDefend-Scan-Protocol = %q, want 1", protocol)
	}
	if accept != "application/json" {
		t.Errorf("Accept = %q", accept)
	}
	if got.userAgent != "appsec-scanner/test" {
		t.Errorf("User-Agent = %q", got.userAgent)
	}
	if len(got.values) != 0 {
		t.Errorf("unexpected form fields %v: the route takes the file part only", got.values)
	}
	part, ok := got.files["file"]
	if !ok || len(got.files) != 1 {
		t.Fatalf("file parts = %v, want exactly one part named file", got.files)
	}
	if part.filename != PartName || !bytes.Equal(part.content, sarif) {
		t.Errorf("file part = %s %q", part.filename, part.content)
	}
}

func TestScanRunPathEscapesScanID(t *testing.T) {
	var rawPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawPath = r.URL.EscapedPath()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	if err := scanRunClient(srv).SubmitScanRun(context.Background(), "../x", []byte(`{}`)); err != nil {
		t.Fatalf("SubmitScanRun: %v", err)
	}
	if rawPath != "/api/scan-runs/..%2Fx/results" {
		t.Errorf("escaped path = %s", rawPath)
	}
}

func TestScanRunGzipsLargeSARIF(t *testing.T) {
	var got received
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = readRequest(t, r)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	sarif := bytes.Repeat([]byte("a"), GzipThresholdBytes+1)

	if err := scanRunClient(srv).SubmitScanRun(context.Background(), "s1", sarif); err != nil {
		t.Fatalf("SubmitScanRun: %v", err)
	}
	part := got.files["file"]
	if part.filename != PartNameGzip {
		t.Fatalf("filename = %q, want %q", part.filename, PartNameGzip)
	}
	zr, err := gzip.NewReader(bytes.NewReader(part.content))
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := io.ReadAll(zr)
	if !bytes.Equal(plain, sarif) {
		t.Errorf("gunzipped part differs from the SARIF")
	}
}

func TestScanRunUploadTreatsConflictAsDone(t *testing.T) {
	fastRetries(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		if n == 1 {
			// The upload landed, its answer is lost.
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			_ = conn.Close()
			return
		}
		answer(w, http.StatusConflict, "SCAN_RESULTS_ALREADY_SUBMITTED")
	}))
	defer srv.Close()

	if err := scanRunClient(srv).SubmitScanRun(context.Background(), "s1", []byte(`{}`)); err != nil {
		t.Fatalf("SubmitScanRun = %v, want nil", err)
	}
	if calls.Load() != 2 {
		t.Errorf("requests = %d, want exactly 2", calls.Load())
	}
}

func TestScanRunOtherConflictIsAnAPIError(t *testing.T) {
	fastRetries(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		answer(w, http.StatusConflict, "SOMETHING_ELSE")
	}))
	defer srv.Close()

	err := scanRunClient(srv).SubmitScanRun(context.Background(), "s1", []byte(`{}`))
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 409 || apiErr.Code != "SOMETHING_ELSE" {
		t.Fatalf("SubmitScanRun = %v, want a 409 *APIError", err)
	}
	if calls.Load() != 1 {
		t.Errorf("requests = %d, a 409 is not retried", calls.Load())
	}
}

func TestScanRunRetries5xx(t *testing.T) {
	fastRetries(t)
	for _, status := range []int{http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusTooManyRequests} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if calls.Add(1) < 3 {
					answer(w, status, "IMPORT_BUSY")
					return
				}
				w.WriteHeader(http.StatusAccepted)
			}))
			defer srv.Close()

			if err := scanRunClient(srv).SubmitScanRun(context.Background(), "s1", []byte(`{}`)); err != nil {
				t.Fatalf("SubmitScanRun = %v, want nil after retries", err)
			}
			if calls.Load() != 3 {
				t.Errorf("requests = %d, want 3", calls.Load())
			}
		})
	}
}

func TestScanRunGivesUpAfterThreeRetries(t *testing.T) {
	fastRetries(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		answer(w, http.StatusServiceUnavailable, "IMPORT_STORAGE_UNAVAILABLE")
	}))
	defer srv.Close()

	err := scanRunClient(srv).SubmitScanRun(context.Background(), "s1", []byte(`{}`))
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 503 || apiErr.Code != "IMPORT_STORAGE_UNAVAILABLE" {
		t.Fatalf("SubmitScanRun = %v, want the last 503 *APIError", err)
	}
	if calls.Load() != 4 {
		t.Errorf("requests = %d, want 4 (one try and three retries)", calls.Load())
	}
}

func TestScanRunDoesNotRetry4xx(t *testing.T) {
	fastRetries(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		answer(w, http.StatusBadRequest, "IMPORT_INVALID_SARIF")
	}))
	defer srv.Close()

	err := scanRunClient(srv).SubmitScanRun(context.Background(), "s1", []byte(`{}`))
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "IMPORT_INVALID_SARIF" {
		t.Fatalf("SubmitScanRun = %v, want IMPORT_INVALID_SARIF", err)
	}
	if calls.Load() != 1 {
		t.Errorf("requests = %d, want 1", calls.Load())
	}
}

func TestScanRunStopsRetryingWhenCancelled(t *testing.T) {
	old := scanRunRetryDelays
	scanRunRetryDelays = []time.Duration{time.Hour, time.Hour, time.Hour}
	t.Cleanup(func() { scanRunRetryDelays = old })
	ctx, cancel := context.WithCancel(context.Background())
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		cancel()
		answer(w, http.StatusServiceUnavailable, "")
	}))
	defer srv.Close()

	start := time.Now()
	err := scanRunClient(srv).SubmitScanRun(ctx, "s1", []byte(`{}`))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("SubmitScanRun = %v, want context.Canceled", err)
	}
	if time.Since(start) > 10*time.Second || calls.Load() != 1 {
		t.Errorf("waited %v over %d requests", time.Since(start), calls.Load())
	}
}

func TestScanRunProtocolRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		answer(w, http.StatusBadRequest, "SCAN_PROTOCOL_UNSUPPORTED")
	}))
	defer srv.Close()

	err := scanRunClient(srv).SubmitScanRun(context.Background(), "s1", []byte(`{}`))
	if !errors.Is(err, ErrProtocolRefused) {
		t.Fatalf("SubmitScanRun = %v, want ErrProtocolRefused", err)
	}
	if !strings.Contains(ErrProtocolRefused.Error(), "CYBEDEFEND_SCANNER_IMAGE_TAG") {
		t.Errorf("ErrProtocolRefused does not tell the fix: %v", ErrProtocolRefused)
	}
}

func TestScanRunTokenRefused(t *testing.T) {
	for _, code := range []string{"SCAN_TOKEN_INVALID", ""} {
		t.Run("code="+code, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				answer(w, http.StatusUnauthorized, code)
			}))
			defer srv.Close()

			err := scanRunClient(srv).SubmitScanRun(context.Background(), "s1", []byte(`{}`))
			if !errors.Is(err, ErrScanTokenRefused) {
				t.Fatalf("SubmitScanRun = %v, want ErrScanTokenRefused", err)
			}
			if calls.Load() != 1 {
				t.Errorf("requests = %d, a 401 is not retried", calls.Load())
			}
		})
	}
}

func TestScanRunRefusesOversizeBeforeAnyRequest(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	random := make([]byte, MaxUploadBytes+1)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}

	err := scanRunClient(srv).SubmitScanRun(context.Background(), "s1", random)
	if !errors.Is(err, ErrTooLargeToUpload) {
		t.Fatalf("SubmitScanRun = %v, want ErrTooLargeToUpload", err)
	}
	if calls.Load() != 0 {
		t.Errorf("requests = %d, want 0", calls.Load())
	}
}

func TestScanRunNeverPrintsToken(t *testing.T) {
	fastRetries(t)
	closed := httptest.NewServer(http.NotFoundHandler())
	closedURL := closed.URL
	closed.Close()

	statuses := []int{400, 401, 403, 404, 409, 413, 422, 429, 500, 503}
	for _, status := range statuses {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			answer(w, status, "CODE_"+http.StatusText(status)[:1])
		}))
		err := scanRunClient(srv).SubmitScanRun(context.Background(), "s1", []byte(`{}`))
		srv.Close()
		if err == nil {
			t.Errorf("HTTP %d: no error", status)
			continue
		}
		if strings.Contains(err.Error(), scanToken) || strings.Contains(err.Error(), "cdst_") {
			t.Errorf("HTTP %d: error %q quotes the token", status, err.Error())
		}
	}

	c := &Client{BaseURL: closedURL, Token: scanToken}
	err := c.SubmitScanRun(context.Background(), "s1", []byte(`{}`))
	if err == nil {
		t.Fatal("a closed server gave no error")
	}
	if strings.Contains(err.Error(), scanToken) || strings.Contains(err.Error(), "cdst_") {
		t.Errorf("network error %q quotes the token", err.Error())
	}
	for _, e := range []error{ErrProtocolRefused, ErrScanTokenRefused} {
		if strings.Contains(e.Error(), "cdst_") {
			t.Errorf("%v quotes a token", e)
		}
	}
}
