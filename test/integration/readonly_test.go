//go:build integration

package integration

import (
	"context"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

// normalisedRe is the line appsec-scanner prints once the SARIF is checked.
var normalisedRe = regexp.MustCompile(`normalised: (\d+) results`)

// TestImagesRunOnAReadOnlyRoot runs every image the hardened way a cluster
// runs it: a read-only root filesystem and an empty tmpfs (mounted noexec,
// Docker's default) at /tmp/appsec-scanner, the only place left writable.
// Each tool must still find its sample's findings, so nothing it needs lives
// outside that directory (HOME and TMPDIR point under it, and appsec-scanner
// creates both). The four tools that need no network run with none.
func TestImagesRunOnAReadOnlyRoot(t *testing.T) {
	requireDocker(t)
	root := repoRoot(t)
	sample := func(name string) string { return filepath.Join(root, "testdata", "samples", name) }

	cases := []struct {
		adapter string
		network string
		src     func(t *testing.T) string
		extra   func(t *testing.T) []string
	}{
		{adapter: "opengrep", network: "none", src: func(*testing.T) string { return sample("sast-python") }},
		{adapter: "gitleaks", network: "none", src: func(t *testing.T) string {
			src := copySecretSample(t)
			appendLine(t, filepath.Join(src, "settings.env"), "STRIPE_KEY="+generateStripeKey(t))
			return src
		}},
		{adapter: "trivy-config", network: "none", src: func(*testing.T) string { return sample("iac-terraform") }},
		{adapter: "zizmor", network: "none", src: func(*testing.T) string { return sample("cicd-github-actions") }},
		// Trivy's vulnerability database is downloaded at run time.
		{adapter: "trivy-fs", network: "bridge", src: func(*testing.T) string { return sample("sca-npm") }},
		{adapter: "trivy-image", network: "bridge", src: func(*testing.T) string { return sample("sca-npm") },
			extra: func(t *testing.T) []string {
				dir := buildSampleArchive(t)
				return []string{"-v", dir + ":/archive:ro", "-e", "IMAGE_ARCHIVE=/archive/image.tar", "-e", "CYBEDEFEND_IMAGE=" + sampleImage}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.adapter, func(t *testing.T) {
			if tc.network != "none" {
				trivyFsSkip(t)
			}
			image := buildImage(t, tc.adapter)
			args := []string{
				"run", "--rm", "--network", tc.network,
				"--read-only", "--tmpfs", "/tmp/appsec-scanner:uid=65532,gid=65532,mode=0755",
				"-v", tc.src(t) + ":/src:ro",
			}
			if tc.extra != nil {
				args = append(args, tc.extra(t)...)
			}
			args = append(args, image)

			ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
			defer cancel()
			out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
			if err != nil {
				t.Fatalf("%s on a read-only root: %v\n%s", tc.adapter, err, out)
			}
			m := normalisedRe.FindSubmatch(out)
			if m == nil {
				t.Fatalf("no « normalised: N results » line:\n%s", out)
			}
			if n, _ := strconv.Atoi(string(m[1])); n == 0 {
				t.Fatalf("%s found nothing in its sample on a read-only root:\n%s", tc.adapter, out)
			}
		})
	}
}
