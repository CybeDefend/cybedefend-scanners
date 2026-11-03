# Third-party notices

The images of this repository bundle the open-source tools below. Each is
distributed unmodified, under its own licence; the `appsec-scanner` program
around it is Apache-2.0.

| Image | Tool | Version | Licence | Source | Release asset (sha256) |
|---|---|---|---|---|---|
| `appsec-scanners-opengrep` | Opengrep | v1.33.1 | LGPL-2.1 | https://github.com/opengrep/opengrep | `https://github.com/opengrep/opengrep/releases/download/v1.33.1/opengrep_manylinux_x86` (`46e8133cc490f9f50518061590ce2f6be5a08afaeda034471c0ceda4b3899808`), `opengrep_manylinux_aarch64` (`d1433f63a90b8bc0b6ad4b498a13b372b856ce9a754a43484ba4920fe2d76dcf`) |

## Opengrep

Opengrep is licensed under the GNU Lesser General Public License v2.1. Its
source code, and the licence text, are at https://github.com/opengrep/opengrep
(tag `v1.33.1`). The image runs it with CybeDefend's own rules only
(`rules/opengrep/`); no registry rule set is bundled or fetched.
