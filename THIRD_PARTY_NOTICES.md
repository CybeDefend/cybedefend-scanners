# Third-party notices

The images of this repository bundle the open-source tools below. Each is
distributed unmodified, under its own licence; the `appsec-scanner` program
around it is Apache-2.0.

| Image | Tool | Version | Licence | Source | Release asset (sha256) |
|---|---|---|---|---|---|
| `appsec-scanners-opengrep` | Opengrep | v1.33.1 | LGPL-2.1 | https://github.com/opengrep/opengrep | `https://github.com/opengrep/opengrep/releases/download/v1.33.1/opengrep_manylinux_x86` (`46e8133cc490f9f50518061590ce2f6be5a08afaeda034471c0ceda4b3899808`), `opengrep_manylinux_aarch64` (`d1433f63a90b8bc0b6ad4b498a13b372b856ce9a754a43484ba4920fe2d76dcf`) |
| `appsec-scanners-gitleaks` | Gitleaks | 8.30.1 | MIT | https://github.com/gitleaks/gitleaks | built from source: Go module `github.com/zricethezav/gitleaks/v8@v8.30.1` (`h1:PmEvCfVI7ti9dV3s5aMZUY7sS2GxRvG3yzih7E+cS3w=`, tag commit `83d9cd684c87d95d656c1458ef04895a7f1cbd8e`), Go 1.26.10, five dependencies raised (below) |
| `appsec-scanners-trivy-config` | Trivy | v0.76.1 | Apache-2.0 | https://github.com/aquasecurity/trivy | image `aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c` (binary copied) |
| `appsec-scanners-zizmor` | zizmor | 1.31.1 | MIT | https://github.com/zizmorcore/zizmor | image `ghcr.io/zizmorcore/zizmor:1.31.1@sha256:42d409dbb851d4c5d35a058cf042b828bea1e3f2884378c526eb0974780e18d9` (used as the final base) |
| `appsec-scanners-trivy-fs` | Trivy | v0.76.1 | Apache-2.0 | https://github.com/aquasecurity/trivy | image `aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c` (binary copied); vulnerability database downloaded at run time |
| `appsec-scanners-trivy-image` | Trivy | v0.76.1 | Apache-2.0 | https://github.com/aquasecurity/trivy | image `aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c` (binary copied); vulnerability database downloaded at run time |

## Opengrep

Opengrep is licensed under the GNU Lesser General Public License v2.1. Its
source code, and the licence text, are at https://github.com/opengrep/opengrep
(tag `v1.33.1`). The image runs it with CybeDefend's own rules only
(`rules/opengrep/`); no registry rule set is bundled or fetched.

## Gitleaks

- Used by: `appsec-scanners-gitleaks` (adapter `gitleaks`, import type `secret`).
- Version: 8.30.1, built from source in the image (`images/gitleaks/Dockerfile`):
  the Go module `github.com/zricethezav/gitleaks/v8@v8.30.1` (tag commit
  `83d9cd684c87d95d656c1458ef04895a7f1cbd8e`), fetched from the Go module
  proxy, checked by sum.golang.org and against its go.sum hash
  `h1:PmEvCfVI7ti9dV3s5aMZUY7sS2GxRvG3yzih7E+cS3w=`, then built with Go
  1.26.10 as upstream's Dockerfile builds it (`CGO_ENABLED=0`, no build tags,
  `version.Version=v8.30.1`). The upstream image's binary (Go 1.24.13) is no
  longer used: a trivy-image scan found 69 known vulnerabilities in it
  (2026-11-03).
- Dependencies raised from gitleaks' own `go.mod`, each to the first release
  fixing what that scan named (`go get` in the build stage):

  | Module | v8.30.1's version | In our build | Why |
  |---|---|---|---|
  | `golang.org/x/crypto` | v0.35.0 | v0.56.0 | 19 advisories fixed in 0.43.0 to 0.56.0 |
  | `golang.org/x/text` | v0.22.0 | v0.41.0 | 2 advisories fixed in 0.39.0 and 0.41.0 |
  | `golang.org/x/sys` | v0.30.0 | v0.47.0 | CVE-2026-39824 (fixed in 0.44.0); 0.47.0 is what x/crypto v0.56.0 requires |
  | `github.com/klauspost/compress` | v1.17.11 | v1.18.7 | CVE-2026-63209 |
  | `github.com/ulikunitz/xz` | v0.5.12 | v0.5.15 | CVE-2025-58058 |
  | `golang.org/x/sync` | v0.11.0 | v0.22.0 | not flagged: raised by x/crypto v0.56.0's `go.mod` |

  Kept: `github.com/nwaples/rardecode/v2` v2.1.0 (CVE-2025-11579, fixed in
  v2.2.0, whose API `github.com/mholt/archives` v0.1.2 no longer builds
  against). Only archive traversal decodes RAR, and gitleaks does none unless
  `--max-archive-depth` is set, which appsec-scanner never does
  (`sources/file.go` returns before extraction at depth 0; `Rar.Match` only
  compares header bytes). Also reported, not fixable by a release:
  GO-2026-5932, « x/crypto/openpgp is unmaintained », whose only fix is an
  untagged x/crypto commit (`v0.58.1-0.20261009181718-2f1f834330b2`); gitleaks
  imports no `golang.org/x/crypto/openpgp` package (`go list -deps`).
- Licence: MIT, Copyright (c) 2019 Zachary Rice. <https://github.com/gitleaks/gitleaks/blob/v8.30.1/LICENSE>
- Source: <https://github.com/gitleaks/gitleaks>
- Checked at 8.30.1 (`gitleaks dir --help`): the `dir` command (aliases `file`,
  `directory`) scans files, not the git history; the flags `--report-format sarif`,
  `--report-path`, `--redact` (a percentage, `--redact=100` hides the whole match),
  `--no-banner` and `--exit-code` (default 1 when leaks are found) exist.
- Invocation: `gitleaks dir <src> --report-format sarif --report-path <file> --redact=100 --no-banner --exit-code 0`.

## Trivy

- **Images:** `appsec-scanners-trivy-config`, `appsec-scanners-trivy-fs`, `appsec-scanners-trivy-image`.
- **Project:** https://github.com/aquasecurity/trivy
- **Version:** v0.76.1, from `aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c`
  (multi-arch index; the binary `/usr/local/bin/trivy` is copied into the image).
- **Licence:** Apache License 2.0 (https://github.com/aquasecurity/trivy/blob/v0.76.1/LICENSE).
- **Invocation (`trivy-config`, import type `iac`):**
  `trivy config --format sarif --output <file> --exit-code 0 --skip-check-update --skip-version-check --disable-telemetry --quiet <src>`.
  The misconfiguration checks are those embedded in the binary (`--skip-check-update`,
  formerly `--skip-policy-update`, still accepted as a deprecated alias at v0.76.1), so
  the scan downloads nothing and runs with `--network none`. Trivy neither checks for a
  newer version nor sends usage data to Aqua (`--skip-version-check`, `--disable-telemetry`).
  Trivy exits 0 whatever it finds (`--exit-code 0`) and writes `security-severity` on its rules.
- **Invocation (`trivy-fs`, import type `sca`):**
  `trivy fs --scanners vuln --format sarif --output <file> --exit-code 0 --cache-dir /tmp/appsec-scanner/trivy-cache --skip-version-check --disable-telemetry --quiet <src>`.
- **Invocation (`trivy-image`, import type `container`):**
  `trivy image --scanners vuln --format sarif --output <file> --exit-code 0 --cache-dir /tmp/appsec-scanner/trivy-cache --skip-version-check --disable-telemetry --quiet <image>`,
  or `… --quiet --input <archive>` for a `docker save` archive. Trivy pulls the scanned
  image itself from its registry (`TRIVY_USERNAME`, `TRIVY_PASSWORD` or
  `TRIVY_REGISTRY_TOKEN` for a private one), or reads the archive; no Docker socket is used.

### Vulnerability database (trivy-db)

- Used by: `appsec-scanners-trivy-fs` (adapter `trivy-fs`, import type `sca`)
  and `appsec-scanners-trivy-image` (adapter `trivy-image`, import type
  `container`). `trivy-config` downloads nothing.
- Neither image bakes a database: at each run Trivy downloads its
  vulnerability database from `mirror.gcr.io/aquasec/trivy-db`, then
  `ghcr.io/aquasecurity/trivy-db` (and, for Java projects, the Java index from
  `mirror.gcr.io/aquasec/trivy-java-db`, then `ghcr.io/aquasecurity/trivy-java-db`)
  into `/tmp/appsec-scanner/trivy-cache`. `TRIVY_DB_REPOSITORY` and
  `TRIVY_JAVA_DB_REPOSITORY` name a mirror instead.
- Source: <https://github.com/aquasecurity/trivy-db> (and
  <https://github.com/aquasecurity/trivy-java-db>), published by Aqua Security.
- Licence: the code that builds the database is Apache-2.0; the data is
  compiled from public advisory sources (distribution security trackers, GitHub
  Advisory Database, NVD and others), each under its own terms, listed by the
  trivy-db project. The database is not redistributed by this repository: the
  user's own run downloads it.

## zizmor (image `appsec-scanners-zizmor`)

- Version: 1.31.1, from its own image
  `ghcr.io/zizmorcore/zizmor:1.31.1@sha256:42d409dbb851d4c5d35a058cf042b828bea1e3f2884378c526eb0974780e18d9`
  (Wolfi base, `/usr/bin/zizmor`).
- Licence: MIT, Copyright (c) 2024 William Woodruff.
- Source: https://github.com/zizmorcore/zizmor
- Invocation: `zizmor --format sarif --no-exit-codes [--offline] <src>`. The
  SARIF is written to stdout; `--offline` is passed unless `GH_TOKEN` is set,
  and `GH_TOKEN` is the only variable the tool receives.
