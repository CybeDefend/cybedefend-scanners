// Package config reads the command line and the environment of
// `appsec-scanner run`. The environment names are the CLI's.
package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Defaults of the flags.
const (
	DefaultSource  = "/src"
	DefaultOut     = "/tmp/appsec-scanner/results.sarif"
	DefaultTimeout = 30 * time.Minute
)

// Config is one run. There is no commit in phase 1 (R15): no variable or
// flag of a commit is read.
type Config struct {
	Adapter, Source, Out, APIURL, Token, ProjectID, Branch string
	Upload                                                 bool
	Timeout                                                time.Duration
	// Image is the image reference trivy-image scans and uploads as the
	// image part (--image, else CYBEDEFEND_IMAGE). ImageArchive is a
	// `docker save` tar Trivy reads instead of pulling it (--image-archive,
	// else IMAGE_ARCHIVE).
	Image, ImageArchive string
	// ScanRun is the mode of a scanner pod of a CybeDefend Community
	// cluster (--scan-run): the source is fetched from ArchiveURL into
	// Source, and the SARIF goes to POST <APIURL>/scan-runs/<ScanID>/results
	// with ScanToken. ScanToken and ArchiveURL are credentials: no error
	// quotes them.
	ScanRun                       bool
	ScanID, ScanToken, ArchiveURL string
}

// Environment of a scan run.
const (
	EnvAPIURL     = "CYBEDEFEND_API_URL"
	EnvScanID     = "CYBEDEFEND_SCAN_ID"
	EnvScanToken  = "CYBEDEFEND_SCAN_TOKEN"
	EnvArchiveURL = "CYBEDEFEND_ARCHIVE_URL"
)

// uuidPattern is the shape of a scan id.
var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// branchVariables are read in order; the first non-empty one wins.
var branchVariables = []string{"CYBEDEFEND_BRANCH", "GITHUB_HEAD_REF", "GITHUB_REF_NAME", "CI_COMMIT_REF_NAME"}

// Load parses `<adapter> [flags]` (flags may come before or after the
// adapter) and reads the environment through getenv. Errors never quote the
// token or the API URL.
func Load(args []string, getenv func(string) string) (Config, error) {
	c := Config{}
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&c.Source, "source", DefaultSource, "directory the tool scans")
	fs.StringVar(&c.Out, "out", DefaultOut, "where the normalised SARIF is written")
	fs.BoolVar(&c.Upload, "upload", false, "upload the SARIF to the import API")
	fs.BoolVar(&c.ScanRun, "scan-run", false, "fetch the archive of a scan run, scan it and submit the SARIF with the scan token")
	fs.DurationVar(&c.Timeout, "timeout", DefaultTimeout, "how long the tool may run")
	fs.StringVar(&c.Image, "image", "", "image reference (trivy-image only)")
	fs.StringVar(&c.ImageArchive, "image-archive", "", "docker save archive of the image (trivy-image only)")

	var positional []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return Config{}, fmt.Errorf("invalid arguments: %w", err)
		}
		if fs.NArg() == 0 {
			break
		}
		positional = append(positional, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	switch len(positional) {
	case 0:
		return Config{}, errors.New("name the adapter: appsec-scanner run <adapter> [flags]")
	case 1:
		c.Adapter = positional[0]
	default:
		return Config{}, fmt.Errorf("expected one adapter, got %d arguments", len(positional))
	}
	if c.Timeout <= 0 {
		return Config{}, errors.New("--timeout must be positive")
	}
	if c.Source == "" || c.Out == "" {
		return Config{}, errors.New("--source and --out must not be empty")
	}
	src, err := filepath.Abs(c.Source)
	if err != nil {
		return Config{}, fmt.Errorf("--source: %w", err)
	}
	c.Source = src

	if c.Image == "" {
		c.Image = strings.TrimSpace(getenv("CYBEDEFEND_IMAGE"))
	}
	if c.ImageArchive == "" {
		c.ImageArchive = strings.TrimSpace(getenv("IMAGE_ARCHIVE"))
	}

	c.APIURL = strings.TrimSpace(getenv("CYBEDEFEND_API_URL"))
	c.ProjectID = strings.TrimSpace(getenv("CYBEDEFEND_PROJECT_ID"))
	c.Token = getenv("CYBEDEFEND_TOKEN")
	if c.Token == "" {
		c.Token = getenv("CYBEDEFEND_PAT")
	}
	for _, k := range branchVariables {
		if v := strings.TrimSpace(getenv(k)); v != "" {
			c.Branch = v
			break
		}
	}

	if c.ScanRun {
		return loadScanRun(c, getenv)
	}

	if c.Upload {
		var missing []string
		if c.APIURL == "" {
			missing = append(missing, "CYBEDEFEND_API_URL")
		}
		if c.ProjectID == "" {
			missing = append(missing, "CYBEDEFEND_PROJECT_ID")
		}
		if c.Token == "" {
			missing = append(missing, "CYBEDEFEND_TOKEN (or CYBEDEFEND_PAT)")
		}
		if c.Branch == "" {
			missing = append(missing, "CYBEDEFEND_BRANCH")
		}
		if len(missing) > 0 {
			return Config{}, fmt.Errorf("--upload needs %s", strings.Join(missing, ", "))
		}
		if err := checkAPIURL(c.APIURL); err != nil {
			return Config{}, err
		}
	}
	return c, nil
}

// checkAPIURL accepts an http(s) URL with a host and no credentials. The
// message never quotes the URL, which could carry a password.
func checkAPIURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("CYBEDEFEND_API_URL must be an http:// or https:// URL, such as https://appsec.example.com/api")
	}
	if u.User != nil {
		return errors.New("CYBEDEFEND_API_URL must not carry credentials: set the token in CYBEDEFEND_TOKEN")
	}
	return nil
}

// loadScanRun reads and checks the four variables of a scan run. Errors name
// a variable, never its value.
func loadScanRun(c Config, getenv func(string) string) (Config, error) {
	if c.Upload {
		return Config{}, errors.New("--scan-run and --upload cannot be used together")
	}
	if c.Adapter == "trivy-image" {
		return Config{}, errors.New("trivy-image does not support --scan-run: a scan run scans a source archive, not an image")
	}
	c.APIURL = strings.TrimSpace(getenv(EnvAPIURL))
	c.ScanID = strings.TrimSpace(getenv(EnvScanID))
	c.ScanToken = strings.TrimSpace(getenv(EnvScanToken))
	c.ArchiveURL = strings.TrimSpace(getenv(EnvArchiveURL))
	// The upload's variables are not the scan run's.
	c.ProjectID, c.Token, c.Branch = "", "", ""

	var missing []string
	for _, kv := range []struct{ key, value string }{
		{EnvAPIURL, c.APIURL}, {EnvScanID, c.ScanID}, {EnvScanToken, c.ScanToken}, {EnvArchiveURL, c.ArchiveURL},
	} {
		if kv.value == "" {
			missing = append(missing, kv.key)
		}
	}
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("--scan-run needs %s", strings.Join(missing, ", "))
	}
	if !uuidPattern.MatchString(c.ScanID) {
		return Config{}, errors.New(EnvScanID + " must be a UUID")
	}
	if err := checkAPIURL(c.APIURL); err != nil {
		if u, perr := url.Parse(c.APIURL); perr == nil && u.User != nil {
			// The upload mode's sentence names the personal token: not this mode's.
			return Config{}, errors.New(EnvAPIURL + " must not carry credentials: the instance URL is https://<host>/api, and the scan token comes in " + EnvScanToken)
		}
		return Config{}, err
	}
	u, err := url.Parse(c.ArchiveURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return Config{}, errors.New(EnvArchiveURL + " must be an http:// or https:// URL")
	}
	return c, nil
}
