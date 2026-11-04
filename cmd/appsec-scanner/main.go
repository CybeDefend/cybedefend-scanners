// Command appsec-scanner runs one open-source tool, normalises the SARIF it
// produced and, with --upload, sends it to the import route of a CybeDefend
// instance.
//
//	appsec-scanner run <adapter> [--source DIR] [--out FILE] [--upload] [--timeout D]
//	                   [--image REF] [--image-archive FILE]   (trivy-image only)
//	appsec-scanner run <adapter> --scan-run [--source DIR] [--out FILE] [--timeout D]
//	appsec-scanner version
//
// --scan-run is the mode of a scanner pod of a CybeDefend Community cluster:
// it fetches the archive of CYBEDEFEND_ARCHIVE_URL into --source, runs the
// tool, and submits the SARIF to CYBEDEFEND_API_URL with CYBEDEFEND_SCAN_TOKEN
// (scan CYBEDEFEND_SCAN_ID, scan protocol 1).
//
// Exit codes: 0 done; 2 the tool failed; 3 the SARIF was refused locally or by
// the API; 4 configuration error; 5 the instance refused the scan protocol;
// 6 the archive could not be fetched.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/cybedefend/cybedefend-scanners/internal/adapter"
	"github.com/cybedefend/cybedefend-scanners/internal/config"
	"github.com/cybedefend/cybedefend-scanners/internal/runner"
	"github.com/cybedefend/cybedefend-scanners/internal/sarif"
	"github.com/cybedefend/cybedefend-scanners/internal/upload"
)

// version is set at build time: -ldflags "-X main.version=<version>".
var version = "dev"

// Exit codes of `appsec-scanner run`.
const (
	exitOK       = 0
	exitTool     = 2
	exitRefused  = 3
	exitConfig   = 4
	usageMessage = "usage: appsec-scanner run <adapter> [--source DIR] [--out FILE] [--upload] [--timeout DURATION] [--image REF] [--image-archive FILE]\n       appsec-scanner run <adapter> --scan-run [--source DIR] [--out FILE] [--timeout DURATION]\n       appsec-scanner version\n"
)

// scanIDPattern is what a scan id printed to the terminal may look like.
var scanIDPattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

func run(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usageMessage)
		return exitConfig
	}
	switch args[0] {
	case "version", "--version":
		fmt.Fprintf(stdout, "appsec-scanner %s\n", version)
		return exitOK
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usageMessage)
		return exitOK
	case "run":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return runAdapter(ctx, args[1:], getenv, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "appsec-scanner: unknown command %q\n%s", args[0], usageMessage)
		return exitConfig
	}
}

func runAdapter(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	logf := func(format string, a ...any) { fmt.Fprintf(stderr, "appsec-scanner: "+format+"\n", a...) }

	cfg, err := config.Load(args, getenv)
	if err != nil {
		logf("%v", err)
		return exitConfig
	}
	a, ok := adapter.Get(cfg.Adapter)
	if !ok {
		logf("unknown adapter %q; known adapters: %s", cfg.Adapter, strings.Join(adapter.Names(), ", "))
		return exitConfig
	}
	sourceRoot := cfg.Source
	if _, isImage := a.(adapter.ImageAdapter); isImage && cfg.ScanRun {
		logf("%s does not support --scan-run: a scan run scans a source archive, not an image", a.Name())
		return exitConfig
	}
	if ia, isImage := a.(adapter.ImageAdapter); isImage {
		// The reference is never printed: it is checked, then sent as typed.
		if cfg.Image == "" {
			logf("%s needs the image reference: set CYBEDEFEND_IMAGE or --image", a.Name())
			return exitConfig
		}
		if !adapter.ValidImage(cfg.Image) {
			logf("CYBEDEFEND_IMAGE is not a valid image reference: registry/name[:tag][@sha256:digest], 255 characters at most")
			return exitConfig
		}
		a = ia.WithImage(cfg.Image, cfg.ImageArchive)
		sourceRoot = ia.SourceRoot()
	} else if cfg.Image != "" {
		logf("CYBEDEFEND_IMAGE is only used by trivy-image")
		return exitConfig
	}

	if cfg.ScanRun {
		logf("fetching the archive of scan %s", cfg.ScanID)
		root, err := fetchSource(ctx, cfg)
		if err != nil {
			logf("the archive could not be fetched: %v", err)
			return exitFetch
		}
		if root != cfg.Source {
			logf("scanning the archive's top folder")
		}
		cfg.Source, sourceRoot = root, root
	}

	env := toolEnv(a, getenv)
	res, err := runner.Run(ctx, a, cfg.Source, cfg.Out, cfg.Timeout, env)
	if err != nil {
		logf("%v", err)
		if res != nil && len(res.Output) > 0 {
			logf("last output of %s:", a.Name())
			_, _ = stderr.Write(res.Output)
			if !bytes.HasSuffix(res.Output, []byte("\n")) {
				fmt.Fprintln(stderr)
			}
		}
		return exitTool
	}
	logf("%s (%s) exited %d in %s, %d bytes of SARIF", a.Name(), a.Type(), res.ExitCode, res.Duration.Round(time.Millisecond), len(res.SARIF))

	log, err := sarif.Parse(bytes.NewReader(res.SARIF))
	if err != nil {
		logf("the SARIF of %s was refused: %s", a.Name(), sarifReason(err))
		return exitRefused
	}
	if err := sarif.Check(log); err != nil {
		logf("the SARIF of %s was refused: %s", a.Name(), sarifReason(err))
		return exitRefused
	}
	if rw, ok := a.(adapter.SARIFRewriter); ok {
		logf("rewrote %d rule ids", rw.RewriteSARIF(log, cfg.Source, env))
	}
	rep := sarif.Normalize(log, sarif.NormalizeOptions{SourceRoot: sourceRoot, DropSnippets: a.Type() == adapter.TypeSecret})
	logf("normalised: %d results, %d rewritten, %d dropped", countResults(log), rep.Rewritten, rep.Dropped)

	var buf bytes.Buffer
	if err := sarif.Write(&buf, log); err != nil {
		logf("write the SARIF: %v", err)
		return exitRefused
	}
	if err := writeFile(cfg.Out, buf.Bytes()); err != nil {
		logf("write the SARIF: %v", err)
		return exitRefused
	}
	logf("wrote %d bytes to %s", buf.Len(), cfg.Out)

	if cfg.ScanRun {
		code := submitScanRun(ctx, cfg, buf.Bytes(), logf)
		if code == exitOK {
			fmt.Fprintln(stdout, "results submitted")
		}
		return code
	}
	if !cfg.Upload {
		return exitOK
	}
	client := &upload.Client{BaseURL: cfg.APIURL, Token: cfg.Token, UserAgent: "appsec-scanner/" + version}
	logf("uploading %d bytes", buf.Len())
	resp, err := client.Import(ctx, upload.Request{
		ProjectID: cfg.ProjectID, Type: string(a.Type()), Branch: cfg.Branch, Image: cfg.Image, SARIF: buf.Bytes(),
	})
	if err != nil {
		var apiErr *upload.APIError
		switch {
		case errors.As(err, &apiErr):
			logf("%s", apiErr.Error())
			return exitRefused
		case errors.Is(err, upload.ErrImageMisplaced):
			logf("%v", err)
			return exitConfig
		case errors.Is(err, upload.ErrTooLargeToUpload):
			logf("The upload is larger than 50 MB even gzipped. Split the scan into smaller SARIF files.")
			return exitRefused
		default:
			// A transport error: its text names the URL, never the token.
			logf("the upload failed: %v", err)
			return exitRefused
		}
	}
	if scanIDPattern.MatchString(resp.ScanID) {
		fmt.Fprintf(stdout, "scan %s queued\n", resp.ScanID)
	} else {
		fmt.Fprintln(stdout, "scan queued")
	}
	return exitOK
}

// toolEnv reads the keys a tool may receive; runner.Run filters them again.
func toolEnv(a adapter.Adapter, getenv func(string) string) map[string]string {
	keys := append(append([]string{}, runner.BaseEnvKeys...), adapter.ToolEnvKeys(a)...)
	env := make(map[string]string, len(keys))
	for _, k := range keys {
		if v := getenv(k); v != "" {
			env[k] = v
		}
	}
	return env
}

// sarifSentences explains each local refusal; the file's content is never printed.
var sarifSentences = []struct {
	err      error
	sentence string
}{
	{sarif.ErrTooLarge, "the SARIF file is larger than 200 MB."},
	{sarif.ErrTooManyResults, "the SARIF file holds more than 100,000 results."},
	{sarif.ErrTooManyRuns, "the SARIF file holds more than 20 runs."},
	{sarif.ErrInvalid, "the file is not valid SARIF 2.1.0 JSON."},
}

// sarifReason prints the import code of a refusal and a fixed sentence.
func sarifReason(err error) string {
	for _, s := range sarifSentences {
		if errors.Is(err, s.err) {
			return s.err.Error() + ": " + s.sentence
		}
	}
	return err.Error()
}

func countResults(l *sarif.Log) int {
	n := 0
	for i := range l.Runs {
		n += len(l.Runs[i].Results)
	}
	return n
}

// writeFile writes through a temporary file in the same directory, so that a
// failed write leaves no half-written SARIF behind.
func writeFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".results-*.sarif")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op once renamed
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
