package archive

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// secretQuery is the signature part of a signed URL: no error may quote it.
const secretQuery = "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=deadbeefcafe0123456789"

// zipEntry is one entry of a test archive. A link entry carries its target as body.
type zipEntry struct {
	name string
	body string
	mode os.FileMode
}

// buildZip writes the entries into an in-memory zip.
func buildZip(t *testing.T, entries ...zipEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		mode := e.mode
		if mode == 0 {
			mode = 0o644
		}
		h.SetMode(mode)
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatalf("create %s: %v", e.name, err)
		}
		if _, err := io.WriteString(w, e.body); err != nil {
			t.Fatalf("write %s: %v", e.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

// serveBytes answers every request with body and counts nothing else.
func serveBytes(t *testing.T, body []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// dirs returns a fresh tmp dir and a fresh destination dir.
func dirs(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	tmp := filepath.Join(root, "tmp")
	dest := filepath.Join(root, "src")
	if err := os.Mkdir(tmp, 0o755); err != nil {
		t.Fatal(err)
	}
	return tmp, dest
}

// signed appends the secret query to a server URL.
func signed(base string) string { return base + "/archive.zip?" + secretQuery }

// listTree returns every path under dir, relative and slash-separated.
func listTree(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	_ = filepath.WalkDir(dir, func(p string, _ os.DirEntry, err error) error {
		if err != nil || p == dir {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	return out
}

// setLimit replaces a package limit for the duration of the test.
func setLimit(t *testing.T, v *int64, n int64) {
	t.Helper()
	old := *v
	*v = n
	t.Cleanup(func() { *v = old })
}

func TestLimits(t *testing.T) {
	if MaxDownloadBytes != 2<<30 {
		t.Errorf("MaxDownloadBytes = %d, want 2 GiB", MaxDownloadBytes)
	}
	if MaxUnpackedBytes != 3<<30 {
		t.Errorf("MaxUnpackedBytes = %d, want 3 GiB", MaxUnpackedBytes)
	}
	if MaxEntries != 200_000 {
		t.Errorf("MaxEntries = %d, want 200000", MaxEntries)
	}
}

func TestFetchUnpacksZip(t *testing.T) {
	data := buildZip(t,
		zipEntry{name: "app/", mode: os.ModeDir | 0o755},
		zipEntry{name: "app/main.go", body: "package main\n"},
		zipEntry{name: "run.sh", body: "#!/bin/sh\n", mode: 0o755},
		zipEntry{name: "deep/a/b/c.txt", body: "c"},
	)
	srv := serveBytes(t, data)
	tmp, dest := dirs(t)

	if err := Fetch(context.Background(), srv.Client(), signed(srv.URL), tmp, dest); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	for name, want := range map[string]string{"app/main.go": "package main\n", "run.sh": "#!/bin/sh\n", "deep/a/b/c.txt": "c"} {
		got, err := os.ReadFile(filepath.Join(dest, name))
		if err != nil {
			t.Errorf("read %s: %v", name, err)
			continue
		}
		if string(got) != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	info, err := os.Stat(filepath.Join(dest, "run.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o100 == 0 {
		t.Errorf("run.sh lost its executable bit: %v", info.Mode())
	}
}

func TestFetchRemovesArchiveAfterUnpack(t *testing.T) {
	srv := serveBytes(t, buildZip(t, zipEntry{name: "a.txt", body: "a"}))
	tmp, dest := dirs(t)

	if err := Fetch(context.Background(), srv.Client(), signed(srv.URL), tmp, dest); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if left := listTree(t, tmp); len(left) != 0 {
		t.Errorf("tmp dir still holds %v after the unpack", left)
	}
	if _, err := os.Stat(filepath.Join(dest, "a.txt")); err != nil {
		t.Errorf("a.txt not unpacked: %v", err)
	}
}

func TestFetchRemovesArchiveAfterRefusal(t *testing.T) {
	srv := serveBytes(t, buildZip(t, zipEntry{name: "../x", body: "x"}))
	tmp, dest := dirs(t)

	if err := Fetch(context.Background(), srv.Client(), signed(srv.URL), tmp, dest); err == nil {
		t.Fatal("Fetch accepted a zip-slip entry")
	}
	if left := listTree(t, tmp); len(left) != 0 {
		t.Errorf("tmp dir still holds %v after a refusal", left)
	}
}

func TestFetchRefusesZipSlip(t *testing.T) {
	for _, name := range []string{"../x", "a/../../x", "/etc/x", "..\\x", "a\\..\\..\\x"} {
		t.Run(name, func(t *testing.T) {
			srv := serveBytes(t, buildZip(t, zipEntry{name: "ok.txt", body: "ok"}, zipEntry{name: name, body: "evil"}))
			tmp, dest := dirs(t)
			parent := filepath.Dir(dest)

			err := Fetch(context.Background(), srv.Client(), signed(srv.URL), tmp, dest)
			if !errors.Is(err, ErrArchiveRefused) {
				t.Fatalf("Fetch error = %v, want ErrArchiveRefused", err)
			}
			if _, statErr := os.Stat(filepath.Join(parent, "x")); statErr == nil {
				t.Errorf("an entry escaped the destination")
			}
			if _, statErr := os.Stat(filepath.Join(dest, "ok.txt")); statErr == nil {
				t.Errorf("the archive was partly unpacked before the refusal")
			}
		})
	}
}

func TestFetchSkipsLinks(t *testing.T) {
	data := buildZip(t,
		zipEntry{name: "link", body: "/etc/passwd", mode: os.ModeSymlink | 0o777},
		zipEntry{name: "kept.txt", body: "kept"},
	)
	srv := serveBytes(t, data)
	tmp, dest := dirs(t)

	if err := Fetch(context.Background(), srv.Client(), signed(srv.URL), tmp, dest); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dest, "link")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the link entry was created (Lstat err = %v)", err)
	}
	if got, err := os.ReadFile(filepath.Join(dest, "kept.txt")); err != nil || string(got) != "kept" {
		t.Errorf("kept.txt = %q, %v", got, err)
	}
}

func TestFetchStopsAtDownloadLimit(t *testing.T) {
	setLimit(t, &maxDownloadBytes, 1024)
	big := bytes.Repeat([]byte("z"), 4096)

	t.Run("with Content-Length", func(t *testing.T) {
		srv := serveBytes(t, big)
		tmp, dest := dirs(t)
		err := Fetch(context.Background(), srv.Client(), signed(srv.URL), tmp, dest)
		if !errors.Is(err, ErrArchiveRefused) || !strings.Contains(err.Error(), "download limit") {
			t.Fatalf("Fetch error = %v, want the download limit refusal", err)
		}
		if left := listTree(t, tmp); len(left) != 0 {
			t.Errorf("tmp dir still holds %v", left)
		}
	})

	t.Run("streamed", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			for i := 0; i < 8; i++ {
				_, _ = w.Write(big[:512])
				w.(http.Flusher).Flush()
			}
		}))
		t.Cleanup(srv.Close)
		tmp, dest := dirs(t)
		err := Fetch(context.Background(), srv.Client(), signed(srv.URL), tmp, dest)
		if !errors.Is(err, ErrArchiveRefused) || !strings.Contains(err.Error(), "download limit") {
			t.Fatalf("Fetch error = %v, want the download limit refusal", err)
		}
		if left := listTree(t, tmp); len(left) != 0 {
			t.Errorf("tmp dir still holds %v", left)
		}
	})
}

func TestFetchStopsAtEntryLimit(t *testing.T) {
	setLimit(t, &maxEntries, 3)
	srv := serveBytes(t, buildZip(t,
		zipEntry{name: "1", body: "1"}, zipEntry{name: "2", body: "2"},
		zipEntry{name: "3", body: "3"}, zipEntry{name: "4", body: "4"},
	))
	tmp, dest := dirs(t)

	err := Fetch(context.Background(), srv.Client(), signed(srv.URL), tmp, dest)
	if !errors.Is(err, ErrArchiveRefused) || !strings.Contains(err.Error(), "entries") {
		t.Fatalf("Fetch error = %v, want the entry limit refusal", err)
	}
	if got := listTree(t, dest); len(got) != 0 {
		t.Errorf("entries were unpacked before the refusal: %v", got)
	}
}

func TestFetchStopsAtUnpackedLimit(t *testing.T) {
	setLimit(t, &maxUnpackedBytes, 100)
	srv := serveBytes(t, buildZip(t,
		zipEntry{name: "a", body: strings.Repeat("a", 60)},
		zipEntry{name: "b", body: strings.Repeat("b", 60)},
	))
	tmp, dest := dirs(t)

	err := Fetch(context.Background(), srv.Client(), signed(srv.URL), tmp, dest)
	if !errors.Is(err, ErrArchiveRefused) || !strings.Contains(err.Error(), "unpacked limit") {
		t.Fatalf("Fetch error = %v, want the unpacked limit refusal", err)
	}
}

func TestFetchRefusesHTTPStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "AccessDenied: Request has expired", http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	tmp, dest := dirs(t)

	err := Fetch(context.Background(), srv.Client(), signed(srv.URL), tmp, dest)
	if !errors.Is(err, ErrArchiveRefused) || !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("Fetch error = %v, want ErrArchiveRefused naming HTTP 403", err)
	}
	if strings.Contains(err.Error(), "AccessDenied") {
		t.Errorf("the error quotes the server's body: %v", err)
	}
}

func TestFetchRefusesSchemes(t *testing.T) {
	tmp, dest := dirs(t)
	for _, raw := range []string{"file:///etc/passwd?" + secretQuery, "ftp://example.org/a.zip?" + secretQuery, "", "://bad?" + secretQuery} {
		err := Fetch(context.Background(), http.DefaultClient, raw, tmp, dest)
		if !errors.Is(err, ErrArchiveRefused) {
			t.Errorf("Fetch(%q) error = %v, want ErrArchiveRefused", raw, err)
		}
	}
}

func TestFetchRefusesRedirectToAnotherScheme(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "ftp://example.org/a.zip?"+secretQuery, http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	tmp, dest := dirs(t)

	err := Fetch(context.Background(), srv.Client(), signed(srv.URL), tmp, dest)
	if !errors.Is(err, ErrArchiveRefused) || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("Fetch error = %v, want a redirect refusal", err)
	}
	if strings.Contains(err.Error(), "X-Amz-Signature=") {
		t.Errorf("the error quotes the signed URL: %v", err)
	}
}

func TestFetchFollowsSameSchemeRedirect(t *testing.T) {
	data := buildZip(t, zipEntry{name: "a.txt", body: "a"})
	mux := http.NewServeMux()
	mux.HandleFunc("/archive.zip", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/real.zip?"+secretQuery, http.StatusFound)
	})
	mux.HandleFunc("/real.zip", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(data) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	tmp, dest := dirs(t)

	if err := Fetch(context.Background(), srv.Client(), signed(srv.URL), tmp, dest); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(dest, "a.txt")); err != nil || string(got) != "a" {
		t.Errorf("a.txt = %q, %v", got, err)
	}
}

func TestFetchErrorNeverQuotesURL(t *testing.T) {
	forbidden := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "denied "+r.URL.RawQuery, http.StatusForbidden)
	}))
	t.Cleanup(forbidden.Close)
	notZip := serveBytes(t, []byte("not a zip "+secretQuery))
	closed := httptest.NewServer(http.NotFoundHandler())
	closedURL := closed.URL
	closed.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "gopher://example.org/?"+secretQuery, http.StatusFound)
	}))
	t.Cleanup(redirect.Close)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	cases := map[string]struct {
		ctx context.Context
		url string
	}{
		"403":             {context.Background(), signed(forbidden.URL)},
		"not a zip":       {context.Background(), signed(notZip.URL)},
		"connection":      {context.Background(), signed(closedURL)},
		"redirect":        {context.Background(), signed(redirect.URL)},
		"cancelled":       {cancelled, signed(forbidden.URL)},
		"bad scheme":      {context.Background(), "file:///x?" + secretQuery},
		"unparsable":      {context.Background(), "http://[::1?" + secretQuery},
		"control char":    {context.Background(), "http://example.org/\x7f?" + secretQuery},
		"missing tmp dir": {context.Background(), signed(notZip.URL)},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			tmp, dest := dirs(t)
			if name == "missing tmp dir" {
				tmp = filepath.Join(tmp, "missing")
			}
			err := Fetch(c.ctx, http.DefaultClient, c.url, tmp, dest)
			if err == nil {
				t.Fatal("Fetch succeeded")
			}
			if !errors.Is(err, ErrArchiveRefused) {
				t.Errorf("error = %v, want ErrArchiveRefused", err)
			}
			for _, leak := range []string{"X-Amz-Signature=", "deadbeefcafe", "archive.zip?"} {
				if strings.Contains(err.Error(), leak) {
					t.Errorf("error %q quotes %q", err.Error(), leak)
				}
			}
		})
	}
	if t.Failed() {
		return
	}
	if err := Fetch(cancelled, http.DefaultClient, signed(forbidden.URL), t.TempDir(), t.TempDir()); !errors.Is(err, context.Canceled) {
		t.Errorf("a cancelled fetch should still unwrap to context.Canceled, got %v", err)
	}
}

func TestFetchStopsAnEntryThatUnderstatesItsSize(t *testing.T) {
	setLimit(t, &maxUnpackedBytes, 100)
	content := []byte(strings.Repeat("x", 500))
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.CreateRaw(&zip.FileHeader{
		Name:               "liar.txt",
		Method:             zip.Store,
		CRC32:              crc32.ChecksumIEEE(content),
		CompressedSize64:   uint64(len(content)),
		UncompressedSize64: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	srv := serveBytes(t, buf.Bytes())
	tmp, dest := dirs(t)

	// archive/zip refuses to read past the declared size, before the budget
	// does: either way the entry is refused and nothing past it is written.
	err = Fetch(context.Background(), srv.Client(), signed(srv.URL), tmp, dest)
	if !errors.Is(err, ErrArchiveRefused) {
		t.Fatalf("Fetch error = %v, want ErrArchiveRefused", err)
	}
	if info, statErr := os.Stat(filepath.Join(dest, "liar.txt")); statErr == nil && info.Size() > 101 {
		t.Errorf("wrote %d bytes past the budget", info.Size())
	}
}
