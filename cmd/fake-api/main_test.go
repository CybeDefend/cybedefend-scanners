package main

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cybedefend/cybedefend-scanners/internal/fakeapi"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestRunNeedsAToken(t *testing.T) {
	var stderr bytes.Buffer
	if code := run(context.Background(), env(nil), nil, &stderr); code != 2 {
		t.Errorf("exit %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "FAKE_API_TOKEN") {
		t.Errorf("stderr does not name FAKE_API_TOKEN: %s", stderr.String())
	}
}

func TestRunDumpsTheUploadsWhenStopped(t *testing.T) {
	dump := filepath.Join(t.TempDir(), "dump.json")
	ctx, stop := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	done := make(chan int, 1)
	var stderr bytes.Buffer
	go func() {
		done <- run(ctx, env(map[string]string{
			"FAKE_API_TOKEN": "test-token",
			"FAKE_API_ADDR":  "127.0.0.1:0",
			"FAKE_API_DUMP":  dump,
		}), ready, &stderr)
	}()
	var url string
	select {
	case url = <-ready:
	case <-time.After(10 * time.Second):
		t.Fatal("the fake API did not start")
	}

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for _, f := range [][2]string{{"type", "iac"}, {"branch", "main"}, {"format", "sarif"}} {
		_ = mw.WriteField(f[0], f[1])
	}
	fw, _ := mw.CreateFormFile("file", "results.sarif")
	_, _ = fw.Write([]byte(`{"runs":[]}`))
	_ = mw.Close()
	req, _ := http.NewRequest(http.MethodPost, url+"/api/project/p1/scan/import/start", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer test-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status %d, want 202", resp.StatusCode)
	}

	stop()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit %d, want 0: %s", code, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the fake API did not stop")
	}
	data, err := os.ReadFile(dump)
	if err != nil {
		t.Fatal(err)
	}
	var ups []fakeapi.Upload
	if err := json.Unmarshal(data, &ups); err != nil {
		t.Fatalf("dump is not JSON: %v", err)
	}
	if len(ups) != 1 || ups[0].Type != "iac" || ups[0].ProjectID != "p1" {
		t.Errorf("dump = %+v", ups)
	}
	if strings.Contains(string(data), "test-token") || strings.Contains(stderr.String(), "test-token") {
		t.Error("the token was written to the dump or the log")
	}
}

func TestRunServesTheArchiveOfFAKE_API_ARCHIVE(t *testing.T) {
	zipPath := filepath.Join(t.TempDir(), "source.zip")
	if err := os.WriteFile(zipPath, []byte("PK-zip-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	ready := make(chan string, 1)
	done := make(chan int, 1)
	var stderr bytes.Buffer
	go func() {
		done <- run(ctx, env(map[string]string{
			"FAKE_API_TOKEN":   "test-token",
			"FAKE_API_ADDR":    "127.0.0.1:0",
			"FAKE_API_ARCHIVE": zipPath,
		}), ready, &stderr)
	}()
	var url string
	select {
	case url = <-ready:
	case <-time.After(10 * time.Second):
		t.Fatal("the fake API did not start")
	}
	resp, err := http.Get(url + "/archive.zip")
	if err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	_, _ = body.ReadFrom(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || body.String() != "PK-zip-bytes" {
		t.Errorf("archive: %d %q", resp.StatusCode, body.String())
	}
	stop()
	<-done
}

func TestRunRefusesAnUnreadableArchive(t *testing.T) {
	var stderr bytes.Buffer
	code := run(context.Background(), env(map[string]string{
		"FAKE_API_TOKEN":   "test-token",
		"FAKE_API_ADDR":    "127.0.0.1:0",
		"FAKE_API_ARCHIVE": filepath.Join(t.TempDir(), "missing.zip"),
	}), nil, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "FAKE_API_ARCHIVE") {
		t.Errorf("exit %d, stderr %s", code, stderr.String())
	}
}
