package adapter

import (
	"bytes"
	"net/url"
	"path"
	"path/filepath"

	"github.com/cybedefend/cybedefend-scanners/internal/sarif"
)

// TrivyCacheDir is where Trivy keeps the vulnerability database it downloads
// at run time. The image creates it for uid 65532; it is never under /src.
const TrivyCacheDir = "/tmp/cybedefend-scanner/trivy-cache"

// TrivyFs runs `trivy fs` for vulnerabilities in dependency manifests and
// lockfiles (import type sca).
//
// An sca import is the branch's whole dependency picture: the server resolves
// every package it does not report. So the source root is the only target,
// nothing under it is skipped, and no other scanner is mixed in.
//
// offline runs it with --offline-scan: no call to a Maven repository. That is
// the fallback when Maven Central refuses with 429 (see Fallback).
//
// sbom, when set, is where a CycloneDX SBOM of the same scan goes (WithSBOM):
// the scan then writes Trivy's JSON report with every package, which `trivy
// convert` turns into the SARIF and into the SBOM. One scan for both, so a
// Maven repository is asked once.
type TrivyFs struct {
	offline bool
	sbom    string
}

func init() { Register(TrivyFs{}) }

// Name implements Adapter.
func (TrivyFs) Name() string { return "trivy-fs" }

// Type implements Adapter.
func (TrivyFs) Type() ImportType { return TypeSCA }

// Command implements Adapter.
func (t TrivyFs) Command(src, out string, _ map[string]string) ([]string, bool) {
	argv := []string{"trivy", "fs", "--scanners", "vuln"}
	if t.sbom == "" {
		argv = append(argv, "--format", "sarif", "--output", out)
	} else {
		argv = append(argv, "--format", "json", "--list-all-pkgs", "--output", trivyReport(out))
	}
	argv = append(argv,
		"--exit-code", "0",
		"--cache-dir", TrivyCacheDir,
		// Trivy checks for updates and sends usage data to Aqua by default:
		// neither leaves the scanner.
		"--skip-version-check",
		"--disable-telemetry",
		"--quiet",
	)
	if t.offline {
		argv = append(argv, "--offline-scan")
	}
	return append(argv, src), false
}

// SuccessExitCodes implements Adapter: with --exit-code 0, findings exit 0.
func (TrivyFs) SuccessExitCodes() []int { return []int{0} }

// ForwardedEnv implements EnvForwarder: a mirror of the vulnerability
// databases, and TLS verification for that mirror.
func (TrivyFs) ForwardedEnv() []string {
	return []string{"TRIVY_DB_REPOSITORY", "TRIVY_JAVA_DB_REPOSITORY", "TRIVY_INSECURE"}
}

// mavenRateLimited is Trivy's sentence when a Maven repository refuses with
// 429 (Maven Central limits requests per IP, and then blocks the IP for a
// while): Trivy cannot fetch a parent POM and fails the whole scan.
var mavenRateLimited = []byte("Maven repository returned 429 Too Many Requests")

// Fallback implements FallbackAdapter: on Maven's 429, run once more with
// --offline-scan. That run calls no Maven repository, so versions only a
// parent POM or a BOM gives stay unresolved: fewer results, never none.
func (t TrivyFs) Fallback(exitCode int, output []byte) (Adapter, string, bool) {
	if t.offline || exitCode == 0 || !bytes.Contains(output, mavenRateLimited) {
		return nil, "", false
	}
	return TrivyFs{offline: true, sbom: t.sbom}, "a Maven repository refused with 429 Too Many Requests: ran again with --offline-scan, so versions given only by a parent POM or a BOM may be missing", true
}

// trivyReport is where the scan writes Trivy's JSON report, next to out.
func trivyReport(out string) string { return out + ".trivy.json" }

// WithSBOM implements SBOMAdapter.
func (t TrivyFs) WithSBOM(path string) Adapter {
	t.sbom = path
	return t
}

// Conversion implements ConvertingAdapter: with an SBOM, `trivy convert`
// writes the SARIF and the CycloneDX SBOM from the scan's JSON report. It
// reads the report only: no database, no network.
func (t TrivyFs) Conversion(out string) (Conversion, bool) {
	if t.sbom == "" {
		return Conversion{}, false
	}
	report := trivyReport(out)
	return Conversion{
		Report:   report,
		SARIF:    []string{"trivy", "convert", "--format", "sarif", "--output", out, "--quiet", report},
		SBOM:     []string{"trivy", "convert", "--format", "cyclonedx", "--output", t.sbom, "--quiet", report},
		SBOMPath: t.sbom,
	}, true
}

// trivyRootBase is the base id Trivy's SARIF resolves its relative URIs against.
const trivyRootBase = "ROOTPATH"

// RewriteSARIF implements SARIFRewriter. `trivy convert` names the JSON
// report it read as the run's ROOTPATH, where a scan names the directory it
// scanned: ROOTPATH is set back to src, so that the results resolve inside
// the source. A SARIF Trivy wrote directly already names src.
func (TrivyFs) RewriteSARIF(l *sarif.Log, src string, _ map[string]string) int {
	want := (&url.URL{Scheme: "file", Path: path.Clean("/"+filepath.ToSlash(src)) + "/"}).String()
	n := 0
	for i := range l.Runs {
		base, ok := l.Runs[i].OriginalURIBaseIDs[trivyRootBase]
		if !ok || base.URI == want {
			continue
		}
		base.URI, base.URIBaseID = want, ""
		l.Runs[i].OriginalURIBaseIDs[trivyRootBase] = base
		n++
	}
	return n
}
