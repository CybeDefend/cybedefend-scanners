package upload

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// sbomRequest is what the server saw of one results upload.
type sbomRequest struct {
	protocol string
	parts    map[string]sbomPart
	order    []string
}

type sbomPart struct {
	filename, contentType string
	content               []byte
}

// recordSBOMUploads answers each upload with the next of answers (the last
// one repeats), and records the requests.
func recordSBOMUploads(t *testing.T, answers ...func(w http.ResponseWriter)) (*httptest.Server, func() []sbomRequest) {
	t.Helper()
	var mu sync.Mutex
	var reqs []sbomRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := sbomRequest{protocol: r.Header.Get(ScanProtocolHeader), parts: map[string]sbomPart{}}
		mr, err := r.MultipartReader()
		if err != nil {
			t.Errorf("MultipartReader: %v", err)
		} else {
			for {
				p, err := mr.NextPart()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Errorf("NextPart: %v", err)
					break
				}
				body, _ := io.ReadAll(p)
				got.parts[p.FormName()] = sbomPart{p.FileName(), p.Header.Get("Content-Type"), body}
				got.order = append(got.order, p.FormName())
			}
		}
		mu.Lock()
		n := len(reqs)
		reqs = append(reqs, got)
		mu.Unlock()
		answers[min(n, len(answers)-1)](w)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []sbomRequest {
		mu.Lock()
		defer mu.Unlock()
		return append([]sbomRequest(nil), reqs...)
	}
}

func accepted(w http.ResponseWriter) { w.WriteHeader(http.StatusAccepted) }

func refuseWith(status int, code string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) { answer(w, status, code) }
}

var (
	testSARIF = []byte(`{"version":"2.1.0","runs":[]}`)
	testSBOM  = []byte(`{"bomFormat":"CycloneDX","specVersion":"1.7","components":[]}`)
)

func TestScanRunWithSBOMSendsProtocol2AndTheSBOMPart(t *testing.T) {
	if ScanProtocolVersionSBOM != 2 {
		t.Fatalf("ScanProtocolVersionSBOM = %d, want 2", ScanProtocolVersionSBOM)
	}
	srv, reqs := recordSBOMUploads(t, accepted)
	out, err := scanRunClient(srv).SubmitScanRunWithSBOM(context.Background(), "scan-1", testSARIF, testSBOM)
	if err != nil {
		t.Fatalf("SubmitScanRunWithSBOM: %v", err)
	}
	if !out.Accepted || out.Declined != "" {
		t.Fatalf("outcome = %+v, want the SBOM accepted", out)
	}
	got := reqs()
	if len(got) != 1 || got[0].protocol != "2" {
		t.Fatalf("requests = %+v, want one with protocol 2", got)
	}
	if len(got[0].order) != 2 || got[0].order[0] != "file" || got[0].order[1] != "sbom" {
		t.Fatalf("parts = %v, want file then sbom", got[0].order)
	}
	f, s := got[0].parts["file"], got[0].parts["sbom"]
	if f.filename != PartName || !bytes.Equal(f.content, testSARIF) {
		t.Errorf("file part = %s %q", f.filename, f.content)
	}
	if s.filename != SBOMPartName || s.contentType != SBOMContentType || !bytes.Equal(s.content, testSBOM) {
		t.Errorf("sbom part = %s %s %q", s.filename, s.contentType, s.content)
	}
	if SBOMPartName != "results.cdx.json" || SBOMContentType != "application/vnd.cyclonedx+json" {
		t.Errorf("SBOM part constants: %q %q", SBOMPartName, SBOMContentType)
	}
}

func TestScanRunWithoutSBOMIsProtocol1(t *testing.T) {
	srv, reqs := recordSBOMUploads(t, accepted)
	out, err := scanRunClient(srv).SubmitScanRunWithSBOM(context.Background(), "scan-1", testSARIF, nil)
	if err != nil || out.Accepted {
		t.Fatalf("outcome %+v, err %v", out, err)
	}
	got := reqs()
	if len(got) != 1 || got[0].protocol != "1" || len(got[0].parts) != 1 {
		t.Fatalf("requests = %+v, want one with protocol 1 and the file part only", got)
	}
}

// An instance older than protocol 2 refuses it: the same SARIF goes again,
// once, as protocol 1 and without the SBOM.
func TestScanRunResendsAsProtocol1WhenTheInstanceRefuses2(t *testing.T) {
	srv, reqs := recordSBOMUploads(t, refuseWith(http.StatusBadRequest, "SCAN_PROTOCOL_UNSUPPORTED"), accepted)
	out, err := scanRunClient(srv).SubmitScanRunWithSBOM(context.Background(), "scan-1", testSARIF, testSBOM)
	if err != nil {
		t.Fatalf("SubmitScanRunWithSBOM: %v", err)
	}
	if out.Accepted || out.Declined != "SCAN_PROTOCOL_UNSUPPORTED" {
		t.Fatalf("outcome = %+v, want the SBOM declined by the protocol", out)
	}
	got := reqs()
	if len(got) != 2 || got[0].protocol != "2" || got[1].protocol != "1" {
		t.Fatalf("requests = %+v, want protocol 2 then 1", got)
	}
	if _, has := got[1].parts["sbom"]; has || !bytes.Equal(got[1].parts["file"].content, testSARIF) {
		t.Fatalf("the protocol 1 request = %+v, want the same SARIF and no SBOM", got[1])
	}
}

// The instance could refuse the SBOM itself: the SARIF must still arrive.
func TestScanRunResendsWithoutTheSBOMWhenTheInstanceRefusesIt(t *testing.T) {
	for _, c := range []struct {
		status int
		code   string
	}{{http.StatusBadRequest, "IMPORT_INVALID_SBOM"}} {
		srv, reqs := recordSBOMUploads(t, refuseWith(c.status, c.code), accepted)
		out, err := scanRunClient(srv).SubmitScanRunWithSBOM(context.Background(), "scan-1", testSARIF, testSBOM)
		if err != nil || out.Declined != c.code {
			t.Fatalf("%s: outcome %+v, err %v", c.code, out, err)
		}
		if got := reqs(); len(got) != 2 || got[1].protocol != "1" || len(got[1].parts) != 1 {
			t.Fatalf("%s: requests = %+v", c.code, got)
		}
	}
}

func TestScanRunProtocol1RefusalAfterTheResendIsErrProtocolRefused(t *testing.T) {
	srv, reqs := recordSBOMUploads(t, refuseWith(http.StatusBadRequest, "SCAN_PROTOCOL_UNSUPPORTED"))
	_, err := scanRunClient(srv).SubmitScanRunWithSBOM(context.Background(), "scan-1", testSARIF, testSBOM)
	if !errors.Is(err, ErrProtocolRefused) {
		t.Fatalf("err = %v, want ErrProtocolRefused", err)
	}
	if n := len(reqs()); n != 2 {
		t.Fatalf("requests = %d, want 2: protocol 2, then 1 once", n)
	}
}

func TestScanRunWithSBOMKeepsEveryOtherRefusal(t *testing.T) {
	srv, reqs := recordSBOMUploads(t, refuseWith(http.StatusUnauthorized, "SCAN_TOKEN_INVALID"))
	if _, err := scanRunClient(srv).SubmitScanRunWithSBOM(context.Background(), "scan-1", testSARIF, testSBOM); !errors.Is(err, ErrScanTokenRefused) {
		t.Fatalf("err = %v, want ErrScanTokenRefused", err)
	}
	if n := len(reqs()); n != 1 {
		t.Fatalf("requests = %d, want 1", n)
	}
	srv, _ = recordSBOMUploads(t, refuseWith(http.StatusConflict, "SCAN_RESULTS_ALREADY_SUBMITTED"))
	if _, err := scanRunClient(srv).SubmitScanRunWithSBOM(context.Background(), "scan-1", testSARIF, testSBOM); err != nil {
		t.Fatalf("409 already submitted: %v", err)
	}
}

// Only SCAN_PROTOCOL_UNSUPPORTED and IMPORT_INVALID_SBOM leave the token
// unspent: every other refusal of a protocol 2 upload is final, as today.
func TestScanRunWithSBOMDoesNotResendOnAnyOtherRefusal(t *testing.T) {
	for _, c := range []struct {
		status int
		code   string
	}{
		{http.StatusBadRequest, "IMPORT_INVALID_SARIF"},
		{http.StatusBadRequest, "IMPORT_INVALID_REQUEST"},
		{http.StatusRequestEntityTooLarge, "IMPORT_UPLOAD_TOO_LARGE"},
	} {
		srv, reqs := recordSBOMUploads(t, refuseWith(c.status, c.code), accepted)
		out, err := scanRunClient(srv).SubmitScanRunWithSBOM(context.Background(), "scan-1", testSARIF, testSBOM)
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.Code != c.code || out.Declined != "" {
			t.Fatalf("%s: outcome %+v, err %v, want the refusal itself", c.code, out, err)
		}
		if n := len(reqs()); n != 1 {
			t.Fatalf("%s: requests = %d, want 1", c.code, n)
		}
	}
}

// At most one resend: an IMPORT_INVALID_SBOM, then a protocol 1 refusal, ends there.
func TestScanRunResendsOnceAtMost(t *testing.T) {
	srv, reqs := recordSBOMUploads(t, refuseWith(http.StatusBadRequest, "IMPORT_INVALID_SBOM"), refuseWith(http.StatusBadRequest, "SCAN_PROTOCOL_UNSUPPORTED"))
	_, err := scanRunClient(srv).SubmitScanRunWithSBOM(context.Background(), "scan-1", testSARIF, testSBOM)
	if !errors.Is(err, ErrProtocolRefused) || len(reqs()) != 2 {
		t.Fatalf("err %v, %d requests: want ErrProtocolRefused after 2", err, len(reqs()))
	}
}

func TestScanRunWithSBOMRetries5xxWithTheSBOM(t *testing.T) {
	fastRetries(t)
	srv, reqs := recordSBOMUploads(t, refuseWith(http.StatusBadGateway, ""), accepted)
	out, err := scanRunClient(srv).SubmitScanRunWithSBOM(context.Background(), "scan-1", testSARIF, testSBOM)
	if err != nil || !out.Accepted {
		t.Fatalf("outcome %+v, err %v", out, err)
	}
	got := reqs()
	if len(got) != 2 || got[1].protocol != "2" {
		t.Fatalf("requests = %+v, want the retry as protocol 2", got)
	}
}

// One deadline bounds both attempts: a protocol 2 attempt that used it up
// leaves no time for the protocol 1 one.
func TestScanRunBothAttemptsFitInOneDeadline(t *testing.T) {
	clock := useFakeClock(t)
	srv, reqs := recordSBOMUploads(t, func(w http.ResponseWriter) {
		clock.advance(ScanRunUploadDeadline)
		answer(w, http.StatusBadRequest, "SCAN_PROTOCOL_UNSUPPORTED")
	})
	_, err := scanRunClient(srv).SubmitScanRunWithSBOM(context.Background(), "scan-1", testSARIF, testSBOM)
	if !errors.Is(err, ErrScanRunDeadline) {
		t.Fatalf("err = %v, want ErrScanRunDeadline", err)
	}
	if n := len(reqs()); n != 1 {
		t.Fatalf("requests = %d, want 1: no protocol 1 attempt past the deadline", n)
	}
}

// The waits of both attempts share the total wait budget.
func TestScanRunBothAttemptsShareTheWaitBudget(t *testing.T) {
	clock := useFakeClock(t)
	old := ScanRunUploadDeadline
	ScanRunUploadDeadline = time.Hour
	t.Cleanup(func() { ScanRunUploadDeadline = old })
	n := 0
	srv, _ := recordSBOMUploads(t, func(w http.ResponseWriter) {
		n++
		if n == 4 {
			answer(w, http.StatusBadRequest, "SCAN_PROTOCOL_UNSUPPORTED")
			return
		}
		answerRetryAfter(w, http.StatusTooManyRequests, "", "60")
	})
	_, _ = scanRunClient(srv).SubmitScanRunWithSBOM(context.Background(), "scan-1", testSARIF, testSBOM)
	var total time.Duration
	for _, w := range clock.waits {
		total += w
	}
	if total > ScanRunMaxTotalWait {
		t.Fatalf("waited %v in all, more than %v", total, ScanRunMaxTotalWait)
	}
}
