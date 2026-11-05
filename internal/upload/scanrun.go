package upload

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ScanProtocolVersion is the scan protocol of a results upload with the SARIF
// alone, sent as X-CybeDefend-Scan-Protocol.
const ScanProtocolVersion = 1

// ScanProtocolVersionSBOM is the scan protocol of a results upload that also
// carries a CycloneDX SBOM, in the part « sbom ».
const ScanProtocolVersionSBOM = 2

// The SBOM part of a protocol 2 upload.
const (
	SBOMPartName    = "results.cdx.json"
	SBOMContentType = "application/vnd.cyclonedx+json"
)

// SBOMOutcome says what became of the SBOM of a results upload.
type SBOMOutcome struct {
	// Accepted is true when the instance took the upload with its SBOM.
	Accepted bool
	// Declined is the refusal code that made the runner send the SARIF again
	// without the SBOM: SCAN_PROTOCOL_UNSUPPORTED (an instance older than
	// protocol 2) or IMPORT_INVALID_SBOM (the instance could not read it).
	Declined string
}

// ScanProtocolHeader carries ScanProtocolVersion.
const ScanProtocolHeader = "X-CybeDefend-Scan-Protocol"

// ErrProtocolRefused is returned when the instance answers 400 SCAN_PROTOCOL_UNSUPPORTED.
var ErrProtocolRefused = errors.New("the instance refused this image's scan protocol: set CYBEDEFEND_SCANNER_IMAGE_TAG to a compatible version")

// ErrScanTokenRefused is returned when the instance answers 401.
var ErrScanTokenRefused = errors.New("scan token refused")

// scanRunRetryDelays are the waits before each retry of a results upload; tests shorten them.
var scanRunRetryDelays = []time.Duration{time.Second, 5 * time.Second, 15 * time.Second}

// Bounds of the retries of a throttled answer: 429 (the route's per-IP
// throttle, RATE_LIMITED) or 503 IMPORT_UNAVAILABLE.
const (
	// ScanRunMaxThrottledRetries is how many times a throttled answer is retried.
	ScanRunMaxThrottledRetries = 6
	// ScanRunMaxRetryAfter caps the wait a Retry-After asks for.
	ScanRunMaxRetryAfter = 60 * time.Second
	// ScanRunMaxTotalWait caps the time SubmitScanRun spends waiting between attempts.
	ScanRunMaxTotalWait = 5 * time.Minute
)

// ScanRunUploadDeadline bounds the whole upload phase of a scan run: every
// attempt and every wait between them, Retry-After included. The pod's time
// budget counts on it. A variable so that a test can shorten it.
var ScanRunUploadDeadline = 6 * time.Minute

// ErrScanRunDeadline is returned when the upload phase ran into
// ScanRunUploadDeadline. It is a context.DeadlineExceeded, and never carries
// the last refusal: the runner reports the upload as interrupted.
var ErrScanRunDeadline = fmt.Errorf("the results upload ran past its deadline: %w", context.DeadlineExceeded)

// scanRunNow is the clock of the upload deadline; tests replace it.
var scanRunNow = time.Now

// scanRunWait waits d, or until ctx is done; tests replace it.
var scanRunWait = func(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// SubmitScanRun uploads the SARIF of one scanner container to
// POST <BaseURL>/scan-runs/<scanID>/results, as the multipart part « file »
// (gzipped above GzipThresholdBytes, MaxUploadBytes at most), with the scan
// token as bearer (c.Token) and the scan protocol header.
//
// Network errors and 5xx are retried 3 times (1 s, 5 s, 15 s). A throttled
// answer (429, or 503 IMPORT_UNAVAILABLE) is retried
// ScanRunMaxThrottledRetries times. Before a retry of an answer with a
// Retry-After (in seconds), the wait is that value when it is longer than the
// scheduled delay, ScanRunMaxRetryAfter at most; all waits together stay
// within ScanRunMaxTotalWait. The whole phase, attempts and waits, ends
// within ScanRunUploadDeadline: an attempt still running then is cut, and a
// wait that would reach it is not started; either way the error is
// ErrScanRunDeadline. 202 is a success, and so is 409
// SCAN_RESULTS_ALREADY_SUBMITTED: a retry of an upload whose answer was lost.
// 400 SCAN_PROTOCOL_UNSUPPORTED is ErrProtocolRefused, 401 is
// ErrScanTokenRefused, any other answer an *APIError (413 and 400 are never
// retried).
func (c *Client) SubmitScanRun(ctx context.Context, scanID string, sarif []byte) error {
	_, err := c.SubmitScanRunWithSBOM(ctx, scanID, sarif, nil)
	return err
}

// SubmitScanRunWithSBOM is SubmitScanRun with a CycloneDX SBOM: the upload is
// protocol 2, with the SBOM as the part « sbom » after the SARIF. When the
// instance refuses it with 400 SCAN_PROTOCOL_UNSUPPORTED (an instance older
// than protocol 2) or 400 IMPORT_INVALID_SBOM, the same SARIF is sent once more,
// as protocol 1 and without the SBOM, and SBOMOutcome.Declined names the
// refusal. Both attempts, their retries and their waits share one
// ScanRunUploadDeadline and one ScanRunMaxTotalWait. A nil sbom is
// SubmitScanRun.
func (c *Client) SubmitScanRunWithSBOM(ctx context.Context, scanID string, sarif, sbom []byte) (SBOMOutcome, error) {
	var outcome SBOMOutcome
	payload, name, err := encodeSARIF(sarif)
	if err != nil {
		return outcome, err
	}
	body, contentType, err := buildScanRunBody(payload, name, nil)
	if err != nil {
		return outcome, err
	}
	var bodySBOM []byte
	var contentTypeSBOM string
	if sbom != nil {
		if bodySBOM, contentTypeSBOM, err = buildScanRunBody(payload, name, sbom); err != nil {
			return outcome, err
		}
	}

	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: DefaultTimeout}
	}
	parent := ctx
	ctx, cancel := context.WithTimeout(parent, ScanRunUploadDeadline)
	defer cancel()
	a := &scanRunAttempts{
		c: c, hc: hc, parent: parent,
		endpoint: strings.TrimRight(c.BaseURL, "/") + "/scan-runs/" + url.PathEscape(scanID) + "/results",
		deadline: scanRunNow().Add(ScanRunUploadDeadline),
	}

	if sbom != nil {
		err := a.submit(ctx, bodySBOM, contentTypeSBOM, ScanProtocolVersionSBOM)
		code := sbomDeclined(err)
		if code == "" {
			outcome.Accepted = err == nil
			return outcome, err
		}
		outcome.Declined = code
	}
	return outcome, a.submit(ctx, body, contentType, ScanProtocolVersion)
}

// sbomDeclined returns the code of a refusal of a protocol 2 upload after
// which the instance stored nothing and kept the token unspent, so that the
// same SARIF may go again without the SBOM, or "". Every other refusal is
// final, as for protocol 1.
func sbomDeclined(err error) string {
	var apiErr *APIError
	switch {
	case errors.Is(err, ErrProtocolRefused):
		return "SCAN_PROTOCOL_UNSUPPORTED"
	case errors.As(err, &apiErr) && apiErr.Status == http.StatusBadRequest && apiErr.Code == "IMPORT_INVALID_SBOM":
		return apiErr.Code
	}
	return ""
}

// scanRunAttempts is the state the attempts of one upload phase share: its
// deadline and the time already waited.
type scanRunAttempts struct {
	c        *Client
	hc       *http.Client
	parent   context.Context
	endpoint string
	deadline time.Time
	waited   time.Duration
}

// pastDeadline turns an error caused by the phase's own deadline into
// ErrScanRunDeadline; a stop of the run itself keeps its own error.
func (a *scanRunAttempts) pastDeadline(err error) error {
	if a.parent.Err() == nil && errors.Is(err, context.DeadlineExceeded) {
		return ErrScanRunDeadline
	}
	return err
}

// submit sends one body, with its retries, within the phase's deadline.
func (a *scanRunAttempts) submit(ctx context.Context, body []byte, contentType string, protocol int) error {
	for attempt := 0; ; attempt++ {
		if !scanRunNow().Before(a.deadline) {
			return ErrScanRunDeadline
		}
		retry, err := a.c.submitOnce(ctx, a.hc, a.endpoint, contentType, body, protocol)
		if !retry {
			return a.pastDeadline(err)
		}
		var apiErr *APIError
		throttled := errors.As(err, &apiErr) && apiErr.throttled()
		limit := len(scanRunRetryDelays)
		if throttled {
			limit = ScanRunMaxThrottledRetries
		}
		if attempt >= limit {
			return err
		}
		wait := scanRunRetryDelays[min(attempt, len(scanRunRetryDelays)-1)]
		if apiErr != nil {
			if after, ok := apiErr.retryAfter(); ok && after > wait {
				wait = min(after, ScanRunMaxRetryAfter)
			}
		}
		if left := ScanRunMaxTotalWait - a.waited; wait > left {
			wait = left
		}
		if wait <= 0 {
			return err
		}
		// A retry that could only start at or past the deadline is not waited for.
		if wait >= a.deadline.Sub(scanRunNow()) {
			return ErrScanRunDeadline
		}
		a.waited += wait
		if werr := scanRunWait(ctx, wait); werr != nil {
			return a.pastDeadline(werr)
		}
	}
}

// throttled reports a refusal that asks the client to come back later.
func (e *APIError) throttled() bool {
	return e.Status == http.StatusTooManyRequests || (e.Status == http.StatusServiceUnavailable && e.Code == "IMPORT_UNAVAILABLE")
}

// retryAfter is the Retry-After of the refusal, when it was a number of seconds.
func (e *APIError) retryAfter() (time.Duration, bool) {
	if e.RetryAfter == "" {
		return 0, false
	}
	n, err := strconv.Atoi(e.RetryAfter)
	if err != nil {
		return 0, false
	}
	return time.Duration(n) * time.Second, true
}

// submitOnce sends one request, and says whether its outcome may be retried.
func (c *Client) submitOnce(ctx context.Context, hc *http.Client, endpoint, contentType string, body []byte, protocol int) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("build the results request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set(ScanProtocolHeader, strconv.Itoa(protocol))
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}

	resp, err := hc.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		// The *url.Error names the endpoint only: the token is a header.
		return true, fmt.Errorf("send the results request: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))

	if resp.StatusCode == http.StatusAccepted {
		return false, nil
	}
	apiErr := newAPIError(resp.StatusCode, raw, resp.Header.Get("Retry-After"))
	switch {
	case resp.StatusCode == http.StatusConflict && apiErr.Code == "SCAN_RESULTS_ALREADY_SUBMITTED":
		return false, nil
	case resp.StatusCode == http.StatusBadRequest && apiErr.Code == "SCAN_PROTOCOL_UNSUPPORTED":
		return false, ErrProtocolRefused
	case resp.StatusCode == http.StatusUnauthorized:
		return false, ErrScanTokenRefused
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return true, apiErr
	default:
		return false, apiErr
	}
}

// buildScanRunBody writes the multipart body: the file part, then the sbom
// part when sbom is not nil.
func buildScanRunBody(payload []byte, name string, sbom []byte) ([]byte, string, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", name)
	if err != nil {
		return nil, "", fmt.Errorf("write the file part: %w", err)
	}
	if _, err := fw.Write(payload); err != nil {
		return nil, "", fmt.Errorf("write the file part: %w", err)
	}
	if sbom != nil {
		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition", `form-data; name="sbom"; filename="`+SBOMPartName+`"`)
		h.Set("Content-Type", SBOMContentType)
		sw, err := mw.CreatePart(h)
		if err != nil {
			return nil, "", fmt.Errorf("write the sbom part: %w", err)
		}
		if _, err := sw.Write(sbom); err != nil {
			return nil, "", fmt.Errorf("write the sbom part: %w", err)
		}
	}
	if err := mw.Close(); err != nil {
		return nil, "", fmt.Errorf("close the multipart body: %w", err)
	}
	return buf.Bytes(), mw.FormDataContentType(), nil
}
