package adapter

// TrivyImage runs `trivy image` for vulnerabilities in a container image's
// OS and language packages (import type container).
//
// Image is the reference the user named; Archive, when set, is a `docker save`
// tar inside the container, read with --input instead of pulling Image. The
// reference is still what is uploaded as the image part: with --input, Trivy
// names the archive path, never the image.
//
// A container import is the image's whole picture, per image and branch: no
// scanner other than vuln is mixed in.
type TrivyImage struct {
	Image, Archive string
}

func init() { Register(TrivyImage{}) }

// Name implements Adapter.
func (TrivyImage) Name() string { return "trivy-image" }

// Type implements Adapter.
func (TrivyImage) Type() ImportType { return TypeContainer }

// Command implements Adapter. The source directory is not scanned: the
// target is the archive, else the image reference.
func (t TrivyImage) Command(_, out string, _ map[string]string) ([]string, bool) {
	argv := []string{
		"trivy", "image",
		"--scanners", "vuln",
		"--format", "sarif",
		"--output", out,
		"--exit-code", "0",
		"--cache-dir", TrivyCacheDir,
		// Trivy checks for updates and sends usage data to Aqua by default:
		// neither leaves the scanner.
		"--skip-version-check",
		"--disable-telemetry",
		"--quiet",
	}
	if t.Archive != "" {
		return append(argv, "--input", t.Archive), false
	}
	return append(argv, t.Image), false
}

// SuccessExitCodes implements Adapter: with --exit-code 0, findings exit 0.
func (TrivyImage) SuccessExitCodes() []int { return []int{0} }

// WithImage implements ImageAdapter.
func (TrivyImage) WithImage(image, archive string) Adapter {
	return TrivyImage{Image: image, Archive: archive}
}

// SourceRoot implements ImageAdapter: Trivy writes an image's paths against
// the image root (app/package-lock.json, /out/image.tar for an archive's OS
// packages), so they are normalised against "/".
func (TrivyImage) SourceRoot() string { return "/" }

// ForwardedEnv implements EnvForwarder: the database mirrors, TLS
// verification, and the registry credentials Trivy pulls the image with.
// The credentials reach Trivy only; they are never printed nor written.
func (TrivyImage) ForwardedEnv() []string {
	return []string{
		"TRIVY_DB_REPOSITORY", "TRIVY_JAVA_DB_REPOSITORY", "TRIVY_INSECURE",
		"TRIVY_USERNAME", "TRIVY_PASSWORD", "TRIVY_REGISTRY_TOKEN",
	}
}
