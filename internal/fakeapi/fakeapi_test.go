package fakeapi

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

const (
	testToken   = "cdp_fake-api-test-token"
	testProject = "00000000-0000-4000-8000-000000000001"
)

// part is one multipart part: a field, or the file when fileName is set.
type part struct {
	name, fileName string
	data           []byte
}

func post(t *testing.T, url, auth string, parts []part) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, p := range parts {
		var w io.Writer
		var err error
		if p.fileName != "" {
			w, err = mw.CreateFormFile(p.name, p.fileName)
		} else {
			w, err = mw.CreateFormField(p.name)
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(p.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, url, &buf)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("User-Agent", "appsec-scanner/test")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func gzipped(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func importURL(s *Server) string {
	return s.URL() + "/project/" + testProject + "/scan/import/start"
}

func TestFakeAPIRecordsAnUpload(t *testing.T) {
	s := New(testToken)
	defer s.Close()
	sarif := []byte(`{"version":"2.1.0","runs":[]}`)

	// The file first, the fields after: the order of the parts is free.
	resp := post(t, importURL(s), "Bearer "+testToken, []part{
		{name: "file", fileName: "results.sarif.gz", data: gzipped(t, sarif)},
		{name: "format", data: []byte("sarif")},
		{name: "branch", data: []byte("main")},
		{name: "type", data: []byte("sast")},
	})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status %d, want 202: %s", resp.StatusCode, body)
	}
	var answer struct {
		ScanID string `json:"scanId"`
	}
	if err := json.Unmarshal(body, &answer); err != nil || answer.ScanID != "fake-1" {
		t.Fatalf("answer %s, want {\"scanId\":\"fake-1\"}", body)
	}

	// A container upload, its file plain and its fields first.
	resp = post(t, s.URL()+"/api/project/"+testProject+"/scan/import/start", "Bearer "+testToken, []part{
		{name: "type", data: []byte("container")},
		{name: "image", data: []byte("registry.example.com/app:1.0")},
		{name: "branch", data: []byte("release")},
		{name: "format", data: []byte("sarif")},
		{name: "file", fileName: "results.sarif", data: sarif},
	})
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted || !strings.Contains(string(body), `"fake-2"`) {
		t.Fatalf("second upload: status %d, body %s", resp.StatusCode, body)
	}

	ups := s.Uploads()
	if len(ups) != 2 {
		t.Fatalf("%d uploads, want 2", len(ups))
	}
	sast := ups[0]
	if sast.ProjectID != testProject || sast.Type != "sast" || sast.Branch != "main" || sast.Format != "sarif" || sast.Image != "" {
		t.Errorf("first upload = %+v", sast)
	}
	if sast.Filename != "results.sarif.gz" || !bytes.Equal(sast.Body, sarif) {
		t.Errorf("first upload: filename %q, body %q (want the gunzipped SARIF)", sast.Filename, sast.Body)
	}
	if !reflect.DeepEqual(sast.Fields, []string{"format", "branch", "type"}) {
		t.Errorf("first upload: Fields = %v, want [format branch type]", sast.Fields)
	}
	if sast.Authorization != "Bearer "+testToken || sast.UserAgent != "appsec-scanner/test" {
		t.Errorf("first upload: Authorization %q, User-Agent %q", sast.Authorization, sast.UserAgent)
	}

	container := ups[1]
	if container.Type != "container" || container.Image != "registry.example.com/app:1.0" || container.Branch != "release" {
		t.Errorf("container upload = %+v", container)
	}
	if !reflect.DeepEqual(container.Fields, []string{"type", "image", "branch", "format"}) {
		t.Errorf("container upload: Fields = %v, want [type image branch format]", container.Fields)
	}
	if !bytes.Equal(container.Body, sarif) {
		t.Errorf("container upload: body %q", container.Body)
	}
}

func TestFakeAPIRefusesAWrongToken(t *testing.T) {
	s := New(testToken)
	defer s.Close()
	for _, auth := range []string{"", "Bearer wrong", testToken, "Bearer " + testToken + "x"} {
		resp := post(t, importURL(s), auth, []part{
			{name: "type", data: []byte("sast")},
			{name: "branch", data: []byte("main")},
			{name: "format", data: []byte("sarif")},
			{name: "file", fileName: "results.sarif", data: []byte(`{}`)},
		})
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Authorization %q: status %d, want 401", auth, resp.StatusCode)
		}
		// The gateway's answer to a refused cdp_ token: no code.
		if got, want := string(body), `{"statusCode":401,"error":"Unauthorized","message":"Invalid token"}`; got != want {
			t.Errorf("Authorization %q: body %s, want %s", auth, got, want)
		}
	}
	if n := len(s.Uploads()); n != 0 {
		t.Errorf("%d uploads recorded, want 0", n)
	}
}

func TestFakeAPIAnswers404OutsideTheImportRoute(t *testing.T) {
	s := New(testToken)
	defer s.Close()
	resp, err := http.Get(importURL(s))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET on the import route: status %d, want 404", resp.StatusCode)
	}
	resp = post(t, s.URL()+"/project/"+testProject+"/scan/start", "Bearer "+testToken, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("POST elsewhere: status %d, want 404", resp.StatusCode)
	}
}

func TestFakeAPIRefusesAnUploadWithoutFile(t *testing.T) {
	s := New(testToken)
	defer s.Close()
	resp := post(t, importURL(s), "Bearer "+testToken, []part{{name: "type", data: []byte("sast")}})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), `"code":"IMPORT_INVALID_REQUEST"`) {
		t.Errorf("status %d, body %s, want 400 IMPORT_INVALID_REQUEST", resp.StatusCode, body)
	}
	if n := len(s.Uploads()); n != 0 {
		t.Errorf("%d uploads recorded, want 0", n)
	}
}

func TestDumpWritesTheUploadsAsJSON(t *testing.T) {
	s := New(testToken)
	defer s.Close()
	resp := post(t, importURL(s), "Bearer "+testToken, []part{
		{name: "type", data: []byte("secret")},
		{name: "branch", data: []byte("main")},
		{name: "format", data: []byte("sarif")},
		{name: "file", fileName: "results.sarif", data: []byte(`{"runs":[]}`)},
	})
	resp.Body.Close()

	var buf bytes.Buffer
	if err := s.Dump(&buf); err != nil {
		t.Fatal(err)
	}
	var got []Upload
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("the dump is not JSON: %v\n%s", err, buf.Bytes())
	}
	if len(got) != 1 || got[0].Type != "secret" || string(got[0].Body) != `{"runs":[]}` {
		t.Errorf("dump = %+v", got)
	}
	// The token the uploads carried is never written to the dump.
	if strings.Contains(buf.String(), testToken) {
		t.Error("the dump holds the token")
	}
}
