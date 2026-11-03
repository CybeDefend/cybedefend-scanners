// Package upload sends a SARIF file to the import route of a CybeDefend instance.
package upload

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// GzipThresholdBytes is the size above which the SARIF is gzipped before upload.
	GzipThresholdBytes = 1 << 20
	// MaxUploadBytes is the largest body sent, after gzip. It is stricter than
	// the server's 50 MiB, in decimal units, so that « 50 MB » stays true.
	MaxUploadBytes = 50 * 1000 * 1000
)

const (
	// PartName is the file name of a plain SARIF part.
	PartName = "results.sarif"
	// PartNameGzip is the file name of a gzipped SARIF part.
	PartNameGzip = "results.sarif.gz"
)

// DefaultTimeout bounds a request when the caller gives no HTTP client.
const DefaultTimeout = 5 * time.Minute

// maxErrorBody is how much of a refusal's body is read.
const maxErrorBody = 64 << 10

// ErrTooLargeToUpload is returned, before any request, when the body would exceed MaxUploadBytes.
var ErrTooLargeToUpload = errors.New("upload larger than 50 MB after gzip")

// ErrImageMisplaced is returned, before any request, when an image is given
// with a type other than container, or no image with type container.
var ErrImageMisplaced = errors.New("image is sent only with type container, and type container needs one")

// Request is one import. Type is one of sast, iac, secret, cicd, sca and
// container; Image is sent as the image part, with type container only. No
// commit is sent in phase 1.
type Request struct {
	ProjectID, Type, Branch, Image string
	SARIF                          []byte
}

// Response is the 202 answer of the import route.
type Response struct {
	ScanID string `json:"scanId"`
}

// Client uploads imports. UserAgent is « appsec-scanner/<version> », set by the command.
type Client struct {
	BaseURL, Token string
	HTTP           *http.Client
	UserAgent      string
}

// Import uploads r and returns the scan id the API answered with. A refusal
// of the API is an *APIError.
func (c *Client) Import(ctx context.Context, r Request) (*Response, error) {
	if (r.Type == "container") != (r.Image != "") {
		return nil, ErrImageMisplaced
	}

	payload, name, err := encodeSARIF(r.SARIF)
	if err != nil {
		return nil, err
	}

	body, contentType, err := buildBody(r, payload, name)
	if err != nil {
		return nil, err
	}

	endpoint := strings.TrimRight(c.BaseURL, "/") + "/project/" + url.PathEscape(r.ProjectID) + "/scan/import/start"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build the import request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}

	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: DefaultTimeout}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send the import request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		return nil, newAPIError(resp.StatusCode, raw, resp.Header.Get("Retry-After"))
	}

	var out Response
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxErrorBody)).Decode(&out); err != nil {
		return nil, fmt.Errorf("read the import answer (HTTP %d): %w", resp.StatusCode, err)
	}
	return &out, nil
}

// encodeSARIF gzips the SARIF above GzipThresholdBytes and checks the result
// against MaxUploadBytes. It returns the bytes to send and the part's file name.
func encodeSARIF(sarif []byte) ([]byte, string, error) {
	payload, name := sarif, PartName
	if len(sarif) > GzipThresholdBytes {
		var buf bytes.Buffer
		zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
		if err != nil {
			return nil, "", fmt.Errorf("gzip the SARIF: %w", err)
		}
		if _, err := zw.Write(sarif); err != nil {
			return nil, "", fmt.Errorf("gzip the SARIF: %w", err)
		}
		if err := zw.Close(); err != nil {
			return nil, "", fmt.Errorf("gzip the SARIF: %w", err)
		}
		payload, name = buf.Bytes(), PartNameGzip
	}
	if len(payload) > MaxUploadBytes {
		return nil, "", ErrTooLargeToUpload
	}
	return payload, name, nil
}

// buildBody writes the multipart body: type, branch, format, image (container
// only), then the file part.
func buildBody(r Request, payload []byte, name string) ([]byte, string, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fields := [][2]string{{"type", r.Type}, {"branch", r.Branch}, {"format", "sarif"}}
	if r.Type == "container" {
		fields = append(fields, [2]string{"image", r.Image})
	}
	for _, f := range fields {
		if err := mw.WriteField(f[0], f[1]); err != nil {
			return nil, "", fmt.Errorf("write the %s part: %w", f[0], err)
		}
	}
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
