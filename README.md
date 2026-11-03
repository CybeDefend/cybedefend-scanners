# CybeDefend AppSec scanners

Open-source security scanners, packaged as container images, that send their
results as SARIF to **CybeDefend AppSec**: a self-hosted Community Edition
instance or CybeDefend Cloud.

Each image runs one open-source tool on your code (or on a container image),
normalises the SARIF it writes (relative paths, no secret snippets, the
server's limits checked before anything is sent) and, with `--upload`, sends it
to the project's import route. A GitHub Action and a GitLab CI template wrap
the images.

## Scanners

| Adapter | Image | Tool | Import type | Notes |
|---|---|---|---|---|
| `opengrep` | `ghcr.io/cybedefend/appsec-scanners-opengrep` | Opengrep | `sast` | The 12 bundled rules of [`rules/opengrep/`](rules/opengrep/README.md); no registry rule set |
| `gitleaks` | `ghcr.io/cybedefend/appsec-scanners-gitleaks` | Gitleaks | `secret` | Scans the files, not the git history; matches are redacted before upload |
| `trivy-config` | `ghcr.io/cybedefend/appsec-scanners-trivy-config` | Trivy | `iac` | Terraform, Kubernetes, Dockerfile, CloudFormation, Helm; embedded checks, no download |
| `zizmor` | `ghcr.io/cybedefend/appsec-scanners-zizmor` | zizmor | `cicd` | GitHub Actions workflows; offline unless `GH_TOKEN` is set |
| `trivy-fs` | `ghcr.io/cybedefend/appsec-scanners-trivy-fs` | Trivy | `sca` | Community Edition only. Downloads Trivy's vulnerability database at each run |
| `trivy-image` | `ghcr.io/cybedefend/appsec-scanners-trivy-image` | Trivy | `container` | Community Edition only. Downloads Trivy's vulnerability database at each run |

Images are published for `linux/amd64` and `linux/arm64`, tagged with the
release version without its leading `v` (`:1.2.0`), its major (`:1`) and
`:latest`. They run as uid 65532, and on a read-only root filesystem when
`/tmp/appsec-scanner` is writable (an `emptyDir`, or `--read-only --tmpfs
/tmp/appsec-scanner:uid=65532,gid=65532`): the tools' `HOME` and `TMPDIR`
live there. The versions of the tools and their licences
are in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

## SCA and container

`sca` and `container` imports are accepted by a Community Edition instance
only: CybeDefend Cloud refuses them with `IMPORT_TYPE_NOT_AVAILABLE`.

- **An `sca` import is the branch's whole dependency picture**: the packages it
  does not report are marked resolved. Run `trivy-fs` on the repository root
  (the default `/src`), never on a subdirectory, and use one SCA tool per
  branch.
- **A `container` import is the image's whole picture, per image and branch.**
  `trivy-image` needs the image reference in `CYBEDEFEND_IMAGE` (or `--image`),
  as `registry/name[:tag][@sha256:digest]`, 255 characters at most. That
  reference is what is uploaded, never a name read from the file.
  - It pulls the image itself. A private registry takes `TRIVY_USERNAME` and
    `TRIVY_PASSWORD` (or `TRIVY_REGISTRY_TOKEN`), which reach Trivy only and are
    never printed.
  - An image of your local Docker daemon is scanned from a `docker save`
    archive: mount it and name it with `IMAGE_ARCHIVE` (or `--image-archive`).
    No Docker socket is used.
- **The vulnerability database.** `trivy-fs` and `trivy-image` download Trivy's
  database at each run (`mirror.gcr.io/aquasec/trivy-db`, then
  `ghcr.io/aquasecurity/trivy-db`), so a scan never runs on a database as old as
  the image. An air-gapped network sets `TRIVY_DB_REPOSITORY` (and
  `TRIVY_JAVA_DB_REPOSITORY` for Java projects) to a mirror.

## Quick start

You need a project on the instance and a personal access token of a user with
the `start_scan` permission on it. Keep the token in a secret; never write it in
a file of the repository.

### `docker run`

```bash
read -rs CYBEDEFEND_TOKEN && export CYBEDEFEND_TOKEN
export CYBEDEFEND_API_URL=https://appsec.example.com/api
export CYBEDEFEND_PROJECT_ID=<project id>
export CYBEDEFEND_BRANCH=main

docker run --rm -v "$PWD:/src:ro" \
  -e CYBEDEFEND_API_URL -e CYBEDEFEND_TOKEN -e CYBEDEFEND_PROJECT_ID -e CYBEDEFEND_BRANCH \
  ghcr.io/cybedefend/appsec-scanners-opengrep:1 --upload
```

The image's entrypoint is `appsec-scanner run <adapter>`: flags such as
`--upload` follow the image name. Variables are passed by name (`-e NAME`), so
the token never appears on a command line. A container scan:

```bash
export CYBEDEFEND_IMAGE=registry.example.com/team/api:1.4.0
docker run --rm \
  -e CYBEDEFEND_API_URL -e CYBEDEFEND_TOKEN -e CYBEDEFEND_PROJECT_ID -e CYBEDEFEND_BRANCH \
  -e CYBEDEFEND_IMAGE -e TRIVY_USERNAME -e TRIVY_PASSWORD \
  ghcr.io/cybedefend/appsec-scanners-trivy-image:1 --upload
```

[`examples/local/run.sh`](examples/local/run.sh) does the same for any scanner,
saves a local image with `docker save` for `trivy-image`, and copies the
normalised SARIF to `./cybedefend-<scanner>.sarif`.

### GitHub Action

```yaml
- uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
  with:
    persist-credentials: false
- uses: CybeDefend/cybedefend-scanners@<full commit sha> # v1.2.0
  with:
    scanner: opengrep
    version: 1.2.0
    api-url: ${{ vars.CYBEDEFEND_API_URL }}
    project-id: ${{ vars.CYBEDEFEND_PROJECT_ID }}
    token: ${{ secrets.CYBEDEFEND_TOKEN }}
```

Inputs: `scanner` (one of the six adapters), `api-url`, `project-id`, `token`
(required); `branch` (defaults to the pull request's head branch, else the
branch or tag of the run), `path` (default `.`, the repository root),
`image` (`trivy-image` only, required there), `version` (the image version;
defaults to the tag the action is used at), `upload` (`true`) and
`sarif-output`. The output `sarif-file` is the normalised SARIF, which
`github/codeql-action/upload-sarif` can also send to GitHub code scanning.
Pin the action by commit sha and set `version` to that release. A full
workflow with every scanner is in
[`examples/github/cybedefend-appsec.yml`](examples/github/cybedefend-appsec.yml).

### GitLab CI

```yaml
include:
  - remote: https://raw.githubusercontent.com/CybeDefend/cybedefend-scanners/v1.2.0/templates/gitlab/appsec-scanners.gitlab-ci.yml

sast:
  extends: .cybedefend-sast

container:
  extends: .cybedefend-container
  variables:
    CYBEDEFEND_IMAGE: $CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA
```

The hidden jobs are `.cybedefend-sast`, `.cybedefend-secret`, `.cybedefend-iac`,
`.cybedefend-cicd`, `.cybedefend-sca` and `.cybedefend-container`. Set
`CYBEDEFEND_API_URL`, `CYBEDEFEND_PROJECT_ID` and `CYBEDEFEND_TOKEN` (masked) as
CI/CD variables in the project's settings. The branch is `$CI_COMMIT_REF_NAME`;
`.cybedefend-container` pulls with the job's GitLab registry credentials.
`CYBEDEFEND_SCANNERS_VERSION` picks the image version (default `1`).

## Environment

| Variable | Meaning |
|---|---|
| `CYBEDEFEND_API_URL` | The instance's API URL. A Community Edition instance serves its API under `/api`: `https://<host>/api`. Required with `--upload`. |
| `CYBEDEFEND_PROJECT_ID` | The project the results are imported into. Required with `--upload`. |
| `CYBEDEFEND_TOKEN` (or `CYBEDEFEND_PAT`) | The personal access token, sent as `Authorization: Bearer <token>`. Never printed, never written to the SARIF, never given to the tool. Required with `--upload`. |
| `CYBEDEFEND_BRANCH` | The branch the results belong to. Defaults to `GITHUB_HEAD_REF`, then `GITHUB_REF_NAME`, then `CI_COMMIT_REF_NAME`. Required with `--upload`. |
| `CYBEDEFEND_IMAGE` | The image `trivy-image` scans and uploads (`--image`). Refused by every other scanner. |
| `IMAGE_ARCHIVE` | A `docker save` archive of that image, read instead of pulling it (`--image-archive`, `trivy-image` only). |
| `OPENGREP_CONFIG` | Rule files or directories for `opengrep`, comma-separated, instead of the bundled rules. |
| `GH_TOKEN` | Turns on zizmor's online audits; the only variable zizmor receives. |
| `TRIVY_USERNAME`, `TRIVY_PASSWORD`, `TRIVY_REGISTRY_TOKEN` | Registry credentials of `trivy-image`. |
| `TRIVY_DB_REPOSITORY`, `TRIVY_JAVA_DB_REPOSITORY` | Mirrors of Trivy's databases (`trivy-fs`, `trivy-image`). |
| `TRIVY_INSECURE` | Lets `trivy-fs` and `trivy-image` reach a registry or mirror without TLS verification. |

Flags of `appsec-scanner run <adapter>`: `--source` (default `/src`), `--out`
(default `/tmp/appsec-scanner/results.sarif`), `--upload`, `--timeout`
(default `30m`), and `--image` / `--image-archive` for `trivy-image`. There is
no commit variable: the results are attached to the branch.

The upload is `multipart/form-data` to
`POST <api-url>/project/<project id>/scan/import/start`, gzipped above 1 MiB.
The instance answers `202` with the scan id and processes the file
afterwards; the scanner does not wait. To wait for the outcome, upload the
SARIF with `cybedefend import --wait` (below).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | The tool ran; the SARIF was written, and uploaded with `--upload` |
| 2 | The tool failed: an exit code outside its success set, no SARIF written, or a timeout |
| 3 | The SARIF was refused locally (limits, invalid JSON) or by the API |
| 4 | Configuration error: a missing project id, token, branch or API URL with `--upload`; an unknown adapter; `trivy-image` without an image, or an invalid image reference |

A tool that exits non-zero only because it found something (Gitleaks, zizmor)
counts as a success.

Before sending anything the scanner refuses, as the instance would, a file
larger than 50 MB uploaded (gzipped) or 200 MB decompressed, with more than
100,000 results or more than 20 runs.

## Refusal messages

A refusal is read from the response body's `code`, never from its `message`,
which is never printed. A known code prints `<CODE>: <sentence>`.

| `code` (HTTP) | Message |
|---|---|
| `IMPORT_INVALID_REQUEST` (400) | `The import request is invalid: check the type and the branch.` |
| `IMPORT_UNSUPPORTED_FORMAT` (400) | `The API accepts only the SARIF format.` |
| `IMPORT_UNSUPPORTED_FILE` (400) | `The upload must be named .sarif, .json or .sarif.gz.` |
| `IMPORT_INVALID_SARIF` (400) | `The file is not valid SARIF 2.1.0 JSON.` |
| `IMPORT_UPLOAD_TOO_LARGE` (413) | `The upload is larger than 50 MB even gzipped. Split the scan into smaller SARIF files.` |
| `IMPORT_BUSY` (503, `Retry-After: 15`) | `The instance is busy; retry in <Retry-After> s.` |
| `IMPORT_STORAGE_UNAVAILABLE` (503) | `The instance's file storage is unavailable. Retry later or ask the administrator.` |
| `IMPORT_UNAVAILABLE` (503) | `The instance could not start processing the import. Retry later or ask the administrator.` |
| `WRITES_BLOCKED` (403, cloud) | `The organisation cannot start new scans on its current plan.` |
| `IMPORT_IMAGE_REQUIRED` (400) | `A container import needs the image reference (--image).` |
| `IMPORT_IMAGE_INVALID` (400) | `The image reference is not valid: registry/name[:tag][@sha256:digest], 255 characters at most.` |
| `IMPORT_TYPE_NOT_AVAILABLE` (400, cloud) | `SCA and container imports are available only on a Community Edition instance.` |
| no known code, 401 | `The token was refused: it may be expired or revoked. Create a new personal access token.` |
| no known code, 403 | `This token's user lacks the start_scan permission on the project.` |
| no known code, 404 | `Project not found, or not visible to this token's user.` |
| no known code, 413 | `The upload is larger than 50 MB even gzipped. Split the scan into smaller SARIF files.` |
| no known code, 429 | `The API rate limit was reached; retry in <Retry-After> s.` |
| no known code, 503 | `The API is unavailable. Retry later or ask the administrator.` |
| other | `The API refused the import (HTTP <status><, code <code>>).` |

## CybeDefend Cloud

`appsec-scanner --upload` sends the token as a bearer as it is, which is what a
Community Edition instance expects of its `cdp_…` personal access tokens. A
CybeDefend Cloud personal access token must first be exchanged for an access
token, which the images do not do: on Cloud, write the SARIF without
`--upload` (the action's `upload: false`) and send it with `cybedefend import`,
which performs the exchange. Cloud accepts the `sast`, `secret`, `iac` and
`cicd` types.

## Bring your own tool

Any SARIF 2.1.0 file, from any scanner, can be sent with the
[CybeDefend CLI](https://github.com/CybeDefend/cybedefend-cli):

```bash
semgrep scan --sarif --output semgrep.sarif .
cybedefend import --format sarif --type sast --branch main --project-id <project id> semgrep.sarif
```

`--type` is `sast`, `iac`, `secret`, `cicd`, `sca` or `container`; `--image`
names the image of a container import, and `--wait` waits for the import to be
processed and prints its outcome.

## Opengrep rules

The `opengrep` image bundles 12 rules of our own, for Python, JavaScript and
TypeScript, Java and Go, at `/opt/appsec-scanners/rules/opengrep`. They are
listed, with their CWE and severity, in
[`rules/opengrep/README.md`](rules/opengrep/README.md), and each one is
Apache-2.0 (`metadata.license`).

To run another rule set, mount it and name it in `OPENGREP_CONFIG` (files or
directories, comma-separated):

```bash
docker run --rm -v "$PWD:/src:ro" -v "$PWD/my-rules:/rules:ro" -e OPENGREP_CONFIG=/rules \
  ghcr.io/cybedefend/appsec-scanners-opengrep:1
```

Only local paths are read: a registry name (`auto`, `p/…`, `r/…`, a URL) is
ignored, and the image fetches no rule over the network. A third-party rule set
comes with its own licence, which may restrict how its rules can be used or
redistributed: check it before you mount it, as for any rule your scans depend
on. No third-party rule set is bundled in the image.

## Development

```bash
make fmt vet test      # gofmt, go vet, unit tests (no Docker)
make integration       # builds the six images and runs them against a fake import API
```

Go 1.26, standard library only (plus `gopkg.in/yaml.v3` in tests). Committed
samples hold no real secret: the secret fixtures are generated at test time.

## Licence and contributions

Apache-2.0: see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE). The bundled tools
keep their own licences ([`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)).

Contributions are welcome under the Developer Certificate of Origin: sign off
every commit (`git commit -s`). See [`CONTRIBUTING.md`](CONTRIBUTING.md), the
[code of conduct](CODE_OF_CONDUCT.md) and, to report a vulnerability,
[`SECURITY.md`](SECURITY.md).
