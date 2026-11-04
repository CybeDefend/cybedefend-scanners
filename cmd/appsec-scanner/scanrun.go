package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/cybedefend/cybedefend-scanners/internal/archive"
	"github.com/cybedefend/cybedefend-scanners/internal/config"
	"github.com/cybedefend/cybedefend-scanners/internal/upload"
)

// Bounds of the archive download of a scan run: a connection (and a TLS
// handshake) within fetchConnectTimeout, response headers within twice that,
// and the whole download and unpack within fetchDeadline. Tests shorten them.
var (
	fetchConnectTimeout = 30 * time.Second
	fetchDeadline       = 15 * time.Minute
)

// fetchClient is the HTTP client of the archive download: bounded at every
// step, so that a hung URL ends with exit 6 instead of holding the pod.
func fetchClient() *http.Client {
	dialer := &net.Dialer{Timeout: fetchConnectTimeout, KeepAlive: 30 * time.Second}
	return &http.Client{Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   fetchConnectTimeout,
		ResponseHeaderTimeout: 2 * fetchConnectTimeout,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          1,
		IdleConnTimeout:       90 * time.Second,
	}}
}

// fetchSource downloads and unpacks the archive of the scan run into
// cfg.Source, and returns the directory to scan: the archive's only entry
// when that is a directory (GitHub and GitLab archives unpack under one
// <repo>-<sha>/ folder), else cfg.Source. The zip goes under the directory of
// cfg.Out and is deleted once unpacked. Errors never quote the URL.
func fetchSource(ctx context.Context, cfg config.Config) (string, error) {
	tmpDir := filepath.Dir(cfg.Out)
	if err := os.MkdirAll(tmpDir, 0o700); err != nil {
		return "", fmt.Errorf("create the directory of --out: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, fetchDeadline)
	defer cancel()
	if err := archive.Fetch(ctx, fetchClient(), cfg.ArchiveURL, tmpDir, cfg.Source); err != nil {
		return "", err
	}
	entries, err := os.ReadDir(cfg.Source)
	if err != nil {
		return "", fmt.Errorf("read the source directory: %w", err)
	}
	if len(entries) == 1 && entries[0].IsDir() {
		return filepath.Join(cfg.Source, entries[0].Name()), nil
	}
	return cfg.Source, nil
}

// exitProtocol and exitFetch are the scan run's own exit codes.
const (
	exitProtocol = 5
	exitFetch    = 6
)

// scanRunSentences are the fixed sentences of the results route's refusals,
// by code. They speak of a scan run, never of the import or its tokens.
var scanRunSentences = map[string]string{
	"SCAN_TOKEN_INVALID":             "the instance refused the scan token: it was already used, it expired, or its scan is no longer running.",
	"IMPORT_UPLOAD_TOO_LARGE":        "the results are larger than the instance accepts (50 MB, gzipped).",
	"IMPORT_INVALID_SARIF":           "the instance found the SARIF invalid.",
	"IMPORT_UNSUPPORTED_FILE":        "the instance refused the results file (.sarif, .json or .sarif.gz).",
	"IMPORT_BUSY":                    "the instance is busy importing other results; still busy after the retries.",
	"IMPORT_STORAGE_UNAVAILABLE":     "the instance's file storage is unavailable; still unavailable after the retries.",
	"IMPORT_UNAVAILABLE":             "the instance could not start the import; still unavailable after the retries.",
	"RATE_LIMITED":                   "the instance's rate limit was reached; still limited after the retries.",
	"SCAN_PROTOCOL_UNSUPPORTED":      "the instance does not speak this image's scan protocol (version 1).",
	"SCAN_RESULTS_ALREADY_SUBMITTED": "the results of this scanner were already submitted.",
}

// scanRunOutcome maps an error of SubmitScanRun to an exit code and a fixed
// sentence. Nothing of the request (token, URL) nor of the server's message
// is printed.
func scanRunOutcome(err error) (int, string) {
	var apiErr *upload.APIError
	switch {
	case errors.Is(err, upload.ErrProtocolRefused):
		return exitProtocol, "SCAN_PROTOCOL_UNSUPPORTED: " + scanRunSentences["SCAN_PROTOCOL_UNSUPPORTED"] +
			" Set CYBEDEFEND_SCANNER_IMAGE_TAG to a version the instance supports."
	case errors.Is(err, upload.ErrScanTokenRefused):
		return exitRefused, "SCAN_TOKEN_INVALID: " + scanRunSentences["SCAN_TOKEN_INVALID"]
	case errors.Is(err, upload.ErrTooLargeToUpload):
		return exitRefused, "IMPORT_UPLOAD_TOO_LARGE: " + scanRunSentences["IMPORT_UPLOAD_TOO_LARGE"]
	case errors.As(err, &apiErr):
		if s, ok := scanRunSentences[apiErr.Code]; ok {
			return exitRefused, apiErr.Code + ": " + s
		}
		if apiErr.Status == http.StatusTooManyRequests {
			return exitRefused, "RATE_LIMITED: " + scanRunSentences["RATE_LIMITED"]
		}
		if apiErr.Code != "" {
			return exitRefused, fmt.Sprintf("the instance refused the results (HTTP %d, code %s).", apiErr.Status, apiErr.Code)
		}
		return exitRefused, fmt.Sprintf("the instance refused the results (HTTP %d).", apiErr.Status)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return exitRefused, "the results upload was interrupted."
	default:
		// A transport error: its text names the endpoint, so it is not printed.
		return exitRefused, "the results upload could not reach the instance, even after the retries."
	}
}

// submitScanRun sends the SARIF to the results route of the scan run.
func submitScanRun(ctx context.Context, cfg config.Config, sarif []byte, logf func(string, ...any)) int {
	client := &upload.Client{BaseURL: cfg.APIURL, Token: cfg.ScanToken, UserAgent: "appsec-scanner/" + version}
	logf("submitting %d bytes of results to scan %s", len(sarif), cfg.ScanID)
	if err := client.SubmitScanRun(ctx, cfg.ScanID, sarif); err != nil {
		code, sentence := scanRunOutcome(err)
		logf("the results were not submitted: %s", sentence)
		return code
	}
	return exitOK
}
