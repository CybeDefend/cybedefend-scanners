// Package archive fetches the code archive of a scan from a signed URL and
// unpacks it into the source directory.
//
// The signed URL is a credential: it never appears in an error, a log line or
// a panic. A refusal names its reason (HTTP status, limit, entry) only.
package archive

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const (
	// MaxDownloadBytes bounds the archive as downloaded.
	MaxDownloadBytes = 2 << 30
	// MaxUnpackedBytes bounds the sum of the unpacked file sizes. The zip is
	// deleted once unpacked, so the pod's disk holds at most this plus the
	// tool's cache.
	MaxUnpackedBytes = 3 << 30
	// MaxEntries bounds the number of entries of the archive.
	MaxEntries = 200_000
)

// The limits as enforced; tests lower them.
var (
	maxDownloadBytes int64 = MaxDownloadBytes
	maxUnpackedBytes int64 = MaxUnpackedBytes
	maxEntries       int64 = MaxEntries
)

// ErrArchiveRefused is wrapped by every error of Fetch, with the reason. The
// reason never quotes the URL.
var ErrArchiveRefused = errors.New("archive refused")

// refusal is an error of Fetch: a fixed reason, plus a cause kept for
// errors.Is (a context error) but never printed.
type refusal struct {
	reason string
	cause  error
}

func (r *refusal) Error() string { return ErrArchiveRefused.Error() + ": " + r.reason }

func (r *refusal) Unwrap() []error {
	if r.cause == nil {
		return []error{ErrArchiveRefused}
	}
	return []error{ErrArchiveRefused, r.cause}
}

func refuse(format string, args ...any) error {
	return &refusal{reason: fmt.Sprintf(format, args...)}
}

// errRedirectScheme is returned by CheckRedirect, so that Fetch can tell it apart.
var errRedirectScheme = errors.New("redirect to another scheme")

// Fetch downloads rawURL (http or https only, no redirect to another scheme)
// into a temporary file under tmpDir, unzips it into dest, then deletes the
// temporary file, whatever the outcome. Absolute paths and « .. » refuse the
// whole archive before anything is written; links and other non-regular
// entries are skipped.
func Fetch(ctx context.Context, hc *http.Client, rawURL, tmpDir, dest string) error {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return refuse("the archive URL is not an http or https URL")
	}

	tmp, err := os.CreateTemp(tmpDir, "archive-*.zip")
	if err != nil {
		return refuse("create the temporary file: %v", err)
	}
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
	}()

	if err := download(ctx, hc, u, tmp); err != nil {
		return err
	}
	return unpack(tmp, dest)
}

// download writes the body of u into f, within maxDownloadBytes.
func download(ctx context.Context, hc *http.Client, u *url.URL, f *os.File) error {
	if hc == nil {
		hc = http.DefaultClient
	}
	client := *hc
	scheme := u.Scheme
	next := hc.CheckRedirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != scheme {
			return errRedirectScheme
		}
		if next != nil {
			return next(req, via)
		}
		if len(via) >= 10 {
			return errors.New("too many redirects")
		}
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return refuse("build the archive request")
	}
	resp, err := client.Do(req)
	if err != nil {
		return transportRefusal(ctx, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return refuse("the archive download answered HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > maxDownloadBytes {
		return refuse("the archive is over the download limit (%d bytes)", maxDownloadBytes)
	}
	n, err := io.Copy(f, io.LimitReader(resp.Body, maxDownloadBytes+1))
	if err != nil {
		return transportRefusal(ctx, err)
	}
	if n > maxDownloadBytes {
		return refuse("the archive is over the download limit (%d bytes)", maxDownloadBytes)
	}
	return nil
}

// transportRefusal turns a transport error into a refusal. The *url.Error
// that wraps it quotes the URL, so only fixed sentences are printed.
func transportRefusal(ctx context.Context, err error) error {
	switch {
	case ctx.Err() != nil:
		return &refusal{reason: "the archive download was interrupted", cause: ctx.Err()}
	case errors.Is(err, errRedirectScheme):
		return refuse("the archive URL redirects to another scheme")
	case errors.Is(err, context.DeadlineExceeded):
		return &refusal{reason: "the archive download timed out", cause: context.DeadlineExceeded}
	default:
		return refuse("the archive download failed")
	}
}

// unpack checks every entry of the zip in f, then writes the regular files
// and directories into dest.
func unpack(f *os.File, dest string) error {
	info, err := f.Stat()
	if err != nil {
		return refuse("read the archive: %v", err)
	}
	zr, err := zip.NewReader(f, info.Size())
	if err != nil {
		return refuse("the archive is not a readable zip")
	}
	if int64(len(zr.File)) > maxEntries {
		return refuse("the archive has more than %d entries", maxEntries)
	}

	var declared uint64
	for _, zf := range zr.File {
		if !localName(zf.Name) {
			return refuse("the archive holds an entry outside its root")
		}
		if zf.Mode().IsRegular() {
			declared += zf.UncompressedSize64
		}
	}
	if declared > uint64(maxUnpackedBytes) {
		return refuse("the archive is over the unpacked limit (%d bytes)", maxUnpackedBytes)
	}

	if err := os.MkdirAll(dest, 0o755); err != nil {
		return refuse("create the source directory: %v", err)
	}
	root, err := os.OpenRoot(dest)
	if err != nil {
		return refuse("open the source directory: %v", err)
	}
	defer root.Close()

	budget := maxUnpackedBytes
	for _, zf := range zr.File {
		name := strings.TrimSuffix(zf.Name, "/")
		mode := zf.Mode()
		switch {
		case mode.IsDir():
			if err := root.MkdirAll(name, 0o755); err != nil {
				return refuse("create a directory of the archive: %v", err)
			}
		case mode.IsRegular():
			written, err := writeEntry(root, name, zf, budget)
			if err != nil {
				return err
			}
			budget -= written
		default:
			// Links, devices, pipes: never created.
		}
	}
	return nil
}

// writeEntry writes one regular file within budget bytes, and returns how many it wrote.
func writeEntry(root *os.Root, name string, zf *zip.File, budget int64) (int64, error) {
	if dir := filepath.Dir(name); dir != "." {
		if err := root.MkdirAll(dir, 0o755); err != nil {
			return 0, refuse("create a directory of the archive: %v", err)
		}
	}
	perm := fs.FileMode(0o644)
	if zf.Mode().Perm()&0o111 != 0 {
		perm = 0o755
	}
	rc, err := zf.Open()
	if err != nil {
		return 0, refuse("read an entry of the archive")
	}
	defer rc.Close()
	out, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return 0, refuse("write an entry of the archive: %v", err)
	}
	n, err := io.Copy(out, io.LimitReader(rc, budget+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return n, refuse("unpack an entry of the archive")
	}
	if n > budget {
		return n, refuse("the archive is over the unpacked limit (%d bytes)", maxUnpackedBytes)
	}
	return n, nil
}

// localName reports whether a zip entry name stays under the root: not
// empty, not absolute, no « .. » element, with either separator.
func localName(name string) bool {
	if name == "" || strings.ContainsRune(name, 0) {
		return false
	}
	slashed := strings.ReplaceAll(name, `\`, "/")
	if strings.HasPrefix(slashed, "/") || (len(slashed) > 1 && slashed[1] == ':') {
		return false
	}
	for _, part := range strings.Split(slashed, "/") {
		if part == ".." {
			return false
		}
	}
	return filepath.IsLocal(strings.TrimSuffix(slashed, "/")) && !strings.Contains(name, `\`)
}
