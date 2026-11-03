# Third-party notices

The images of this repository bundle the open-source tools below. Each is
distributed unmodified, under its own licence; the `appsec-scanner` program
around it is Apache-2.0.

| Image | Tool | Version | Licence | Source | Release asset (sha256) |
|---|---|---|---|---|---|
| `appsec-scanners-opengrep` | Opengrep | v1.33.1 | LGPL-2.1 | https://github.com/opengrep/opengrep | `https://github.com/opengrep/opengrep/releases/download/v1.33.1/opengrep_manylinux_x86` (`46e8133cc490f9f50518061590ce2f6be5a08afaeda034471c0ceda4b3899808`), `opengrep_manylinux_aarch64` (`d1433f63a90b8bc0b6ad4b498a13b372b856ce9a754a43484ba4920fe2d76dcf`) |
| `appsec-scanners-gitleaks` | Gitleaks | 8.30.1 | MIT | https://github.com/gitleaks/gitleaks | image `zricethezav/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f` (binary copied) |
| `appsec-scanners-trivy-config` | Trivy | v0.76.1 | Apache-2.0 | https://github.com/aquasecurity/trivy | image `aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c` (binary copied) |

## Opengrep

Opengrep is licensed under the GNU Lesser General Public License v2.1. Its
source code, and the licence text, are at https://github.com/opengrep/opengrep
(tag `v1.33.1`). The image runs it with CybeDefend's own rules only
(`rules/opengrep/`); no registry rule set is bundled or fetched.

## Gitleaks

- Used by: `appsec-scanners-gitleaks` (adapter `gitleaks`, import type `secret`).
- Version: 8.30.1, image `zricethezav/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f`
  (only `/usr/bin/gitleaks` is copied into our image).
- Licence: MIT, Copyright (c) 2019 Zachary Rice. <https://github.com/gitleaks/gitleaks/blob/v8.30.1/LICENSE>
- Source: <https://github.com/gitleaks/gitleaks>
- Checked at 8.30.1 (`gitleaks dir --help`): the `dir` command (aliases `file`,
  `directory`) scans files, not the git history; the flags `--report-format sarif`,
  `--report-path`, `--redact` (a percentage, `--redact=100` hides the whole match),
  `--no-banner` and `--exit-code` (default 1 when leaks are found) exist.
- Invocation: `gitleaks dir <src> --report-format sarif --report-path <file> --redact=100 --no-banner --exit-code 0`.

## Trivy

- **Images:** `appsec-scanners-trivy-config`.
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
