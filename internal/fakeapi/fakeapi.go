// Package fakeapi is an in-memory stand-in for the import route of a
// CybeDefend instance, POST <api>/project/<projectId>/scan/import/start. The
// integration tests and the action's self-test (through cmd/fake-api) upload
// to it and read back what it received.
//
// It answers 401 with the gateway's body when the bearer is not the token it
// was given, 400 IMPORT_INVALID_REQUEST when the multipart body holds no file
// part, and 202 {"scanId":"fake-<n>"} otherwise. Any path that ends with the
// import route is accepted, so an API URL with a prefix (« /api ») works.
//
// It also serves the route a scanner pod of a Community cluster submits to,
// POST <api>/scan-runs/<scanId>/results (bearer: the same token, header
// X-CybeDefend-Scan-Protocol: 1 with one part « file », or 2 with the part
// « sbom » after it): 202 {"accepted":true}, then 409
// SCAN_RESULTS_ALREADY_SUBMITTED for that scan, 401 SCAN_TOKEN_INVALID, 400
// SCAN_PROTOCOL_UNSUPPORTED (a version SetScanProtocols did not name),
// IMPORT_INVALID_REQUEST (an SBOM with protocol 1, none with 2),
// IMPORT_INVALID_SBOM (after RefuseSBOM) or IMPORT_UNSUPPORTED_FILE;
// and, once SetArchive was called, the archive of the scan at GET
// <any prefix>/archive.zip, whatever its query.
package fakeapi

import (
	"bytes"
	"compress/gzip"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Upload is one accepted import. Body is the file part, gunzipped when it was
// sent gzipped. Fields lists the name of every non-file part, in the order
// received; Type, Branch, Format and Image hold the first value of their part,
// empty when it was absent.
type Upload struct {
	ProjectID, Type, Branch, Format, Image, Filename, Authorization, UserAgent string
	Fields                                                                     []string
	Body                                                                       []byte
	// ScanID and Protocol are set for a scan-run upload only.
	ScanID   string `json:",omitempty"`
	Protocol string `json:",omitempty"`
	// SBOM is the part « sbom » of a protocol 2 scan-run upload, as sent.
	SBOM                          []byte `json:",omitempty"`
	SBOMFilename, SBOMContentType string `json:",omitempty"`
}

// Server records the uploads it accepts.
type Server struct {
	token string
	srv   *httptest.Server

	mu        sync.Mutex
	uploads   []Upload
	archive   []byte
	submitted map[string]bool
	// protocols are the scan protocols accepted, nil for 1 and 2; refused
	// records each version refused.
	protocols map[string]bool
	refused   []string
	// refuseSBOM answers every SBOM 400 IMPORT_INVALID_SBOM.
	refuseSBOM bool
}

// RefuseSBOM makes the results route answer a protocol 2 upload 400
// IMPORT_INVALID_SBOM, as the instance does for an SBOM it cannot read: it
// stores nothing, and the scan stays open for a protocol 1 upload.
func (s *Server) RefuseSBOM() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refuseSBOM = true
}

// SetScanProtocols sets the scan protocols the results route accepts (by
// default 1 and 2): SetScanProtocols("1") plays an instance older than the SBOM.
func (s *Server) SetScanProtocols(versions ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.protocols = map[string]bool{}
	for _, v := range versions {
		s.protocols[v] = true
	}
}

// RefusedProtocols returns the scan protocol of each upload refused with
// SCAN_PROTOCOL_UNSUPPORTED, oldest first.
func (s *Server) RefusedProtocols() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.refused...)
}

func (s *Server) speaks(protocol string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	ok := protocol == "1" || protocol == "2"
	if s.protocols != nil {
		ok = s.protocols[protocol]
	}
	if !ok {
		s.refused = append(s.refused, protocol)
	}
	return ok
}

const (
	// maxUploadBytes bounds what is read of a request: above the scanner's 50 MB.
	maxUploadBytes = 60 << 20
	// maxSARIFBytes bounds a gunzipped file part: above the server's 200 MiB.
	maxSARIFBytes = 210 << 20
	maxFieldBytes = 4 << 10
)

// importRoute matches the import route, behind any prefix.
var importRoute = regexp.MustCompile(`^(?:/.*)?/project/([^/]+)/scan/import/start$`)

// scanRunRoute matches the results route of a scan run, behind any prefix.
var scanRunRoute = regexp.MustCompile(`^(?:/.*)?/scan-runs/([^/]+)/results$`)

// archiveRoute matches the archive download, behind any prefix.
var archiveRoute = regexp.MustCompile(`^(?:/.*)?/archive\.zip$`)

// New starts a server on a random loopback port.
func New(token string) *Server {
	s := &Server{token: token}
	s.srv = httptest.NewUnstartedServer(http.HandlerFunc(s.serve))
	s.start()
	return s
}

// NewOn starts a server on ln, which it then owns. cmd/fake-api uses it to
// listen on a fixed address; the integration tests on every interface.
func NewOn(token string, ln net.Listener) *Server {
	s := &Server{token: token}
	s.srv = httptest.NewUnstartedServer(http.HandlerFunc(s.serve))
	_ = s.srv.Listener.Close()
	s.srv.Listener = ln
	s.start()
	return s
}

// start bounds how long a client may take to send its request, then serves.
func (s *Server) start() {
	s.srv.Config.ReadHeaderTimeout = 10 * time.Second
	s.srv.Config.ReadTimeout = 5 * time.Minute
	s.srv.Start()
}

// URL is the server's base URL, http://<host>:<port>, without a trailing slash.
func (s *Server) URL() string { return s.srv.URL }

// Uploads returns a copy of the uploads accepted so far, oldest first.
func (s *Server) Uploads() []Upload {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Upload(nil), s.uploads...)
}

// SetArchive sets the zip served at /archive.zip.
func (s *Server) SetArchive(data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.archive = append([]byte(nil), data...)
}

// ArchiveURL is the URL of the archive, with a query standing in for a signature.
func (s *Server) ArchiveURL() string { return s.srv.URL + "/archive.zip?X-Amz-Signature=fake" }

// Close stops the server.
func (s *Server) Close() { s.srv.Close() }

// Dump writes the uploads as a JSON array. An Authorization header that held
// the expected token is written as « Bearer [redacted] »: the dump never holds
// the token.
func (s *Server) Dump(w io.Writer) error {
	ups := s.Uploads()
	for i := range ups {
		if ups[i].Authorization != "" {
			ups[i].Authorization = "Bearer [redacted]"
		}
	}
	if ups == nil {
		ups = []Upload{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(ups)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && archiveRoute.MatchString(r.URL.Path) {
		s.serveArchive(w)
		return
	}
	if m := scanRunRoute.FindStringSubmatch(r.URL.Path); r.Method == http.MethodPost && m != nil {
		s.serveScanRun(w, r, m[1])
		return
	}
	m := importRoute.FindStringSubmatch(r.URL.Path)
	if r.Method != http.MethodPost || m == nil {
		answer(w, http.StatusNotFound, `{"statusCode":404,"error":"Not Found","message":"Cannot `+jsonSafe(r.Method)+` this route"}`)
		return
	}
	want := "Bearer " + s.token
	got := r.Header.Get("Authorization")
	if s.token == "" || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		answer(w, http.StatusUnauthorized, `{"statusCode":401,"error":"Unauthorized","message":"Invalid token"}`)
		return
	}
	u, err := readUpload(w, r)
	if err != nil {
		answer(w, http.StatusBadRequest, `{"statusCode":400,"error":"Bad Request","message":"The import request is invalid","code":"IMPORT_INVALID_REQUEST"}`)
		return
	}
	u.ProjectID = m[1]

	s.mu.Lock()
	s.uploads = append(s.uploads, u)
	n := len(s.uploads)
	s.mu.Unlock()
	answer(w, http.StatusAccepted, fmt.Sprintf(`{"scanId":"fake-%d"}`, n))
}

func (s *Server) serveArchive(w http.ResponseWriter) {
	s.mu.Lock()
	data := s.archive
	s.mu.Unlock()
	if data == nil {
		answer(w, http.StatusNotFound, `{"statusCode":404,"error":"Not Found"}`)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Length", fmt.Sprint(len(data)))
	_, _ = w.Write(data)
}

// serveScanRun answers a results upload as the route does, in its order:
// token, protocol, already submitted, file.
func (s *Server) serveScanRun(w http.ResponseWriter, r *http.Request, scanID string) {
	got := r.Header.Get("Authorization")
	if s.token == "" || subtle.ConstantTimeCompare([]byte(got), []byte("Bearer "+s.token)) != 1 {
		answer(w, http.StatusUnauthorized, `{"statusCode":401,"error":"Unauthorized","code":"SCAN_TOKEN_INVALID"}`)
		return
	}
	protocol := r.Header.Get("X-CybeDefend-Scan-Protocol")
	if !s.speaks(protocol) {
		answer(w, http.StatusBadRequest, `{"statusCode":400,"error":"Bad Request","code":"SCAN_PROTOCOL_UNSUPPORTED"}`)
		return
	}
	s.mu.Lock()
	done := s.submitted[scanID]
	s.mu.Unlock()
	if done {
		answer(w, http.StatusConflict, `{"statusCode":409,"error":"Conflict","code":"SCAN_RESULTS_ALREADY_SUBMITTED"}`)
		return
	}
	u, err := readUpload(w, r)
	if err != nil {
		answer(w, http.StatusBadRequest, `{"statusCode":400,"error":"Bad Request","code":"IMPORT_UNSUPPORTED_FILE"}`)
		return
	}
	if (u.SBOM != nil) != (protocol == "2") {
		answer(w, http.StatusBadRequest, `{"statusCode":400,"error":"Bad Request","code":"IMPORT_INVALID_REQUEST"}`)
		return
	}
	s.mu.Lock()
	refuseSBOM := s.refuseSBOM
	s.mu.Unlock()
	if u.SBOM != nil && refuseSBOM {
		answer(w, http.StatusBadRequest, `{"statusCode":400,"error":"Bad Request","code":"IMPORT_INVALID_SBOM"}`)
		return
	}
	u.ScanID, u.Protocol = scanID, protocol

	s.mu.Lock()
	if s.submitted[scanID] {
		s.mu.Unlock()
		answer(w, http.StatusConflict, `{"statusCode":409,"error":"Conflict","code":"SCAN_RESULTS_ALREADY_SUBMITTED"}`)
		return
	}
	if s.submitted == nil {
		s.submitted = map[string]bool{}
	}
	s.submitted[scanID] = true
	s.uploads = append(s.uploads, u)
	s.mu.Unlock()
	answer(w, http.StatusAccepted, `{"accepted":true}`)
}

func answer(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

// jsonSafe keeps the letters of an HTTP method, so the 404 body stays JSON.
func jsonSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r
		}
		return -1
	}, s)
}

var errNoFile = errors.New("no file part")

func readUpload(w http.ResponseWriter, r *http.Request) (Upload, error) {
	u := Upload{Authorization: r.Header.Get("Authorization"), UserAgent: r.Header.Get("User-Agent")}
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	mr, err := r.MultipartReader()
	if err != nil {
		return u, err
	}
	var raw []byte
	seenFile := false
	for {
		p, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return u, err
		}
		name := p.FormName()
		if name == "file" {
			if seenFile {
				return u, errors.New("two file parts")
			}
			seenFile = true
			u.Filename = p.FileName()
			if raw, err = io.ReadAll(p); err != nil {
				return u, err
			}
			continue
		}
		if name == "sbom" {
			if u.SBOM != nil {
				return u, errors.New("two sbom parts")
			}
			u.SBOMFilename, u.SBOMContentType = p.FileName(), p.Header.Get("Content-Type")
			if u.SBOM, err = io.ReadAll(p); err != nil {
				return u, err
			}
			if u.SBOM == nil {
				u.SBOM = []byte{}
			}
			continue
		}
		data, err := io.ReadAll(io.LimitReader(p, maxFieldBytes))
		if err != nil {
			return u, err
		}
		u.Fields = append(u.Fields, name)
		value := string(data)
		set := func(dst *string) {
			if *dst == "" {
				*dst = value
			}
		}
		switch name {
		case "type":
			set(&u.Type)
		case "branch":
			set(&u.Branch)
		case "format":
			set(&u.Format)
		case "image":
			set(&u.Image)
		}
	}
	if !seenFile {
		return u, errNoFile
	}
	u.Body = raw
	if strings.HasSuffix(u.Filename, ".gz") || bytes.HasPrefix(raw, []byte{0x1f, 0x8b}) {
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return u, err
		}
		if u.Body, err = io.ReadAll(io.LimitReader(zr, maxSARIFBytes)); err != nil {
			return u, err
		}
	}
	return u, nil
}
