package upload

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// refuse runs Import against a server that answers status with body and the
// given Retry-After header, and returns the *APIError Import gave.
func refuse(t *testing.T, status int, body, retryAfter string) *APIError {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if retryAfter != "" {
			w.Header().Set("Retry-After", retryAfter)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	_, err := newClient(srv.URL).Import(context.Background(), Request{ProjectID: "p1", Type: "sast", Branch: "main", SARIF: []byte("{}")})
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want *APIError", err)
	}
	if apiErr.Status != status {
		t.Fatalf("Status = %d, want %d", apiErr.Status, status)
	}
	return apiErr
}

func TestCodeRowsOfTheRefusalTable(t *testing.T) {
	cases := []struct {
		code       string
		status     int
		retryAfter string
		want       string
	}{
		{"IMPORT_INVALID_REQUEST", 400, "", "The import request is invalid: check the type and the branch."},
		{"IMPORT_UNSUPPORTED_FORMAT", 400, "", "The API accepts only the SARIF format."},
		{"IMPORT_UNSUPPORTED_FILE", 400, "", "The upload must be named .sarif, .json or .sarif.gz."},
		{"IMPORT_INVALID_SARIF", 400, "", "The file is not valid SARIF 2.1.0 JSON."},
		{"IMPORT_IMAGE_REQUIRED", 400, "", "A container import needs the image reference (--image)."},
		{"IMPORT_IMAGE_INVALID", 400, "", "The image reference is not valid: registry/name[:tag][@sha256:digest], 255 characters at most."},
		{"IMPORT_TYPE_NOT_AVAILABLE", 400, "", "Imports are available only on a Community Edition instance: CybeDefend Cloud does not take them."},
		{"IMPORT_UPLOAD_TOO_LARGE", 413, "", "The upload is larger than 50 MB even gzipped. Split the scan into smaller SARIF files."},
		{"IMPORT_BUSY", 503, "15", "The instance is busy; retry in 15 s."},
		{"IMPORT_STORAGE_UNAVAILABLE", 503, "", "The instance's file storage is unavailable. Retry later or ask the administrator."},
		{"IMPORT_UNAVAILABLE", 503, "", "The instance could not start processing the import. Retry later or ask the administrator."},
		{"WRITES_BLOCKED", 403, "", "The organisation cannot start new scans on its current plan."},
	}
	for _, c := range cases {
		t.Run(c.code, func(t *testing.T) {
			e := refuse(t, c.status, `{"code":"`+c.code+`","message":"x"}`, c.retryAfter)
			if e.Code != c.code {
				t.Fatalf("Code = %q, want %q", e.Code, c.code)
			}
			want := c.code + ": " + c.want
			if e.Error() != want {
				t.Fatalf("Error() = %q, want %q", e.Error(), want)
			}
			if !strings.HasPrefix(e.Error(), c.code) {
				t.Fatalf("message does not start with its code")
			}
		})
	}
}

func TestStatusRowsOfTheRefusalTable(t *testing.T) {
	cases := []struct {
		status     int
		retryAfter string
		want       string
	}{
		{401, "", "The token was refused: it may be expired or revoked. Create a new personal access token."},
		{403, "", "This token's user lacks the start_scan permission on the project."},
		{404, "", "Project not found, or not visible to this token's user."},
		{413, "", "The upload is larger than 50 MB even gzipped. Split the scan into smaller SARIF files."},
		{429, "30", "The API rate limit was reached; retry in 30 s."},
		{503, "", "The API is unavailable. Retry later or ask the administrator."},
		{500, "", "The API refused the import (HTTP 500)."},
	}
	for _, c := range cases {
		t.Run(http.StatusText(c.status), func(t *testing.T) {
			e := refuse(t, c.status, `{"message":"nope"}`, c.retryAfter)
			if e.Code != "" {
				t.Fatalf("Code = %q, want empty", e.Code)
			}
			if e.Error() != c.want {
				t.Fatalf("Error() = %q, want %q", e.Error(), c.want)
			}
		})
	}
}

func TestBusyIsNotAStorageOutage(t *testing.T) {
	e := refuse(t, 503, `{"code":"IMPORT_BUSY"}`, "15")
	if strings.Contains(e.Error(), "storage") {
		t.Fatalf("busy reported as a storage outage: %q", e.Error())
	}
	if !strings.HasPrefix(e.Error(), "IMPORT_BUSY: ") {
		t.Fatalf("Error() = %q", e.Error())
	}
}

func TestCodeIsNeverReadFromMessage(t *testing.T) {
	e := refuse(t, 400, `{"message":"IMPORT_TOO_LARGE"}`, "")
	if want := "The API refused the import (HTTP 400)."; e.Error() != want {
		t.Fatalf("Error() = %q, want %q", e.Error(), want)
	}
}

func TestUnknownCodeIsPrintedButNotTheServerText(t *testing.T) {
	e := refuse(t, 400, `{"code":"WHATEVER","message":"server secret text"}`, "")
	if want := "The API refused the import (HTTP 400, code WHATEVER)."; e.Error() != want {
		t.Fatalf("Error() = %q, want %q", e.Error(), want)
	}
	if strings.Contains(e.Error(), "server secret text") {
		t.Fatalf("server message printed")
	}
}

func TestUnknownCodeLetsTheStatusDecide(t *testing.T) {
	e := refuse(t, 401, `{"code":"TOKEN_EXPIRED"}`, "")
	if want := "The token was refused: it may be expired or revoked. Create a new personal access token."; e.Error() != want {
		t.Fatalf("Error() = %q, want %q", e.Error(), want)
	}
}

func TestMalformedCodeIsNotPrinted(t *testing.T) {
	e := refuse(t, 400, `{"code":"a b<c>","message":"m"}`, "")
	if e.Code != "" {
		t.Fatalf("Code = %q, want empty", e.Code)
	}
	if want := "The API refused the import (HTTP 400)."; e.Error() != want {
		t.Fatalf("Error() = %q, want %q", e.Error(), want)
	}
	if strings.Contains(e.Error(), "a b<c>") {
		t.Fatalf("malformed code printed")
	}
}

func TestNonJSONBodyFallsBackToTheStatus(t *testing.T) {
	e := refuse(t, 404, `<html>not found</html>`, "")
	if want := "Project not found, or not visible to this token's user."; e.Error() != want {
		t.Fatalf("Error() = %q, want %q", e.Error(), want)
	}
}
