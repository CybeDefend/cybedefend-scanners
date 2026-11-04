package upload

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ScanProtocolVersion is the scan protocol this runner speaks, sent as
// X-CybeDefend-Scan-Protocol on every results upload of a scan run.
const ScanProtocolVersion = 1

// ScanProtocolHeader carries ScanProtocolVersion.
const ScanProtocolHeader = "X-CybeDefend-Scan-Protocol"

// ErrProtocolRefused is returned when the instance answers 400 SCAN_PROTOCOL_UNSUPPORTED.
var ErrProtocolRefused = errors.New("the instance refused this image's scan protocol: set CYBEDEFEND_SCANNER_IMAGE_TAG to a compatible version")

// ErrScanTokenRefused is returned when the instance answers 401.
var ErrScanTokenRefused = errors.New("scan token refused")

// scanRunRetryDelays are the waits before each retry of a results upload; tests shorten them.
var scanRunRetryDelays = []time.Duration{time.Second, 5 * time.Second, 15 * time.Second}

// SubmitScanRun uploads the SARIF of one scanner container to
// POST <BaseURL>/scan-runs/<scanID>/results, as the multipart part « file »
// (gzipped above GzipThresholdBytes, MaxUploadBytes at most), with the scan
// token as bearer (c.Token) and the scan protocol header.
//
// Network errors, 5xx and 429 are retried 3 times (1 s, 5 s, 15 s). 202 is a
// success, and so is 409 SCAN_RESULTS_ALREADY_SUBMITTED: a retry of an upload
// whose answer was lost. 400 SCAN_PROTOCOL_UNSUPPORTED is ErrProtocolRefused,
// 401 is ErrScanTokenRefused, any other answer an *APIError.
func (c *Client) SubmitScanRun(ctx context.Context, scanID string, sarif []byte) error {
	payload, name, err := encodeSARIF(sarif)
	if err != nil {
		return err
	}
	body, contentType, err := buildScanRunBody(payload, name)
	if err != nil {
		return err
	}
	endpoint := strings.TrimRight(c.BaseURL, "/") + "/scan-runs/" + url.PathEscape(scanID) + "/results"

	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: DefaultTimeout}
	}

	for attempt := 0; ; attempt++ {
		retry, err := c.submitOnce(ctx, hc, endpoint, contentType, body)
		if !retry || attempt >= len(scanRunRetryDelays) {
			return err
		}
		timer := time.NewTimer(scanRunRetryDelays[attempt])
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// submitOnce sends one request, and says whether its outcome may be retried.
func (c *Client) submitOnce(ctx context.Context, hc *http.Client, endpoint, contentType string, body []byte) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("build the results request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set(ScanProtocolHeader, strconv.Itoa(ScanProtocolVersion))
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

// buildScanRunBody writes the multipart body: the file part only.
func buildScanRunBody(payload []byte, name string) ([]byte, string, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", name)
	if err != nil {
		return nil, "", fmt.Errorf("write the file part: %w", err)
	}
	if _, err := fw.Write(payload); err != nil {
		return nil, "", fmt.Errorf("write the file part: %w", err)
	}
	if err := mw.Close(); err != nil {
		return nil, "", fmt.Errorf("close the multipart body: %w", err)
	}
	return buf.Bytes(), mw.FormDataContentType(), nil
}
