package upload

import (
	"encoding/json"
	"fmt"
	"regexp"
)

// APIError is a synchronous refusal of the import route. Code is the body's
// `code` only, kept when it matches ^[A-Z][A-Z0-9_]{0,63}$; the server's
// `message` is never read nor kept.
type APIError struct {
	Status     int
	Code       string
	RetryAfter string
}

var (
	codePattern       = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	retryAfterPattern = regexp.MustCompile(`^[0-9]{1,6}$`)
)

const tooLargeSentence = "The upload is larger than 50 MB even gzipped. Split the scan into smaller SARIF files."

// codeSentences is the code part of « Messages for API refusals » (shared wording with the CLI).
var codeSentences = map[string]string{
	"IMPORT_INVALID_REQUEST":     "The import request is invalid: check the type and the branch.",
	"IMPORT_UNSUPPORTED_FORMAT":  "The API accepts only the SARIF format.",
	"IMPORT_UNSUPPORTED_FILE":    "The upload must be named .sarif, .json or .sarif.gz.",
	"IMPORT_INVALID_SARIF":       "The file is not valid SARIF 2.1.0 JSON.",
	"IMPORT_UPLOAD_TOO_LARGE":    tooLargeSentence,
	"IMPORT_STORAGE_UNAVAILABLE": "The instance's file storage is unavailable. Retry later or ask the administrator.",
	"IMPORT_UNAVAILABLE":         "The instance could not start processing the import. Retry later or ask the administrator.",
	"WRITES_BLOCKED":             "The organisation cannot start new scans on its current plan.",
	"IMPORT_IMAGE_REQUIRED":      "A container import needs the image reference (--image).",
	"IMPORT_IMAGE_INVALID":       "The image reference is not valid: registry/name[:tag][@sha256:digest], 255 characters at most.",
	"IMPORT_TYPE_NOT_AVAILABLE":  "SCA and container imports are available only on a Community Edition instance.",
}

// statusSentences is the status part of the table, used when no known code was sent.
var statusSentences = map[int]string{
	401: "The token was refused: it may be expired or revoked. Create a new personal access token.",
	403: "This token's user lacks the start_scan permission on the project.",
	404: "Project not found, or not visible to this token's user.",
	413: tooLargeSentence,
	503: "The API is unavailable. Retry later or ask the administrator.",
}

// newAPIError reads the code from a refusal body (at most what the caller read).
func newAPIError(status int, body []byte, retryAfter string) *APIError {
	e := &APIError{Status: status}
	var parsed struct {
		Code json.RawMessage `json:"code"`
	}
	if json.Unmarshal(body, &parsed) == nil && len(parsed.Code) > 0 {
		var code string
		if json.Unmarshal(parsed.Code, &code) == nil && codePattern.MatchString(code) {
			e.Code = code
		}
	}
	if retryAfterPattern.MatchString(retryAfter) {
		e.RetryAfter = retryAfter
	}
	return e
}

// retryIn renders « retry in <n> s », or « retry later » without a usable Retry-After.
func (e *APIError) retryIn() string {
	if e.RetryAfter == "" {
		return "retry later"
	}
	return "retry in " + e.RetryAfter + " s"
}

// Error returns the fixed sentence for the refusal: the code row, else the
// status row (when the code is absent or unknown), else the generic row.
func (e *APIError) Error() string {
	if e.Code == "IMPORT_BUSY" {
		return e.Code + ": The instance is busy; " + e.retryIn() + "."
	}
	if s, ok := codeSentences[e.Code]; ok {
		return e.Code + ": " + s
	}
	if e.Status == 429 {
		return "The API rate limit was reached; " + e.retryIn() + "."
	}
	if s, ok := statusSentences[e.Status]; ok {
		return s
	}
	if e.Code == "" {
		return fmt.Sprintf("The API refused the import (HTTP %d).", e.Status)
	}
	return fmt.Sprintf("The API refused the import (HTTP %d, code %s).", e.Status, e.Code)
}
