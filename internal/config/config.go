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
}

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
	fs.DurationVar(&c.Timeout, "timeout", DefaultTimeout, "how long the tool may run")

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
