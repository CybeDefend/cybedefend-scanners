# Contributing to CybeDefend AppSec Scanners

Thank you for helping. This repository holds `appsec-scanner`, a Go program that runs an open-source security tool, normalises the SARIF it writes and uploads it to a CybeDefend AppSec Community Edition instance (CybeDefend Cloud does not take imports), plus one container image per tool, a GitHub Action and a GitLab CI template.

## Set-up

- **Go 1.26** (the `go` directive of `go.mod` is `1.26.11`; a newer `go` fetches that toolchain by itself).
- **Docker** with Buildx, only for the images and the integration tests.

Checks every pull request must pass, from the repository root:

```sh
gofmt -l .                              # must print nothing
go vet ./...
CGO_ENABLED=0 go test -count=1 ./...
```

`make fmt`, `make vet` and `make test` run the same commands. `make images` builds the images and `make integration` runs the integration tests (build tag `integration`) against them.

Every change starts with a failing test: write the test, see it fail for the expected reason, then write the code that makes it pass.

## Sign your commits (DCO)

Every commit must be signed off (`git commit -s`): by signing off you certify the Developer Certificate of Origin 1.1, whose full text follows. The sign-off is a line at the end of the commit message:

```
Signed-off-by: Your Name <your.email@example.org>
```

It must carry your real name and an e-mail address. The `DCO` workflow refuses a pull request with an unsigned commit; to fix one, `git commit --amend -s` (last commit) or `git rebase --signoff <base>` (several), then force-push your branch.

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.

Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

## Adding an adapter

An adapter runs one tool for one import type (`sast`, `iac`, `secret`, `cicd`, `sca` or `container`).

1. **Interface.** Implement the adapter interface in `internal/adapter/<name>.go` and register it. It builds the tool's command line (SARIF output, no network unless the tool needs its database, findings never turned into a failing exit code) and names the exit codes that mean « findings were reported ». Test the arguments first.
2. **Dockerfile.** Add `images/<name>/Dockerfile`. Every `FROM` is pinned by digest (`@sha256:`), every downloaded file is checked against a `sha256` written in the Dockerfile, the image runs as uid 65532, and its entrypoint is the static `appsec-scanner` binary.
3. **Sample.** Add a small vulnerable sample under `testdata/samples/<name>/`. Never commit a real or realistic secret: secret fixtures are generated at test time.
4. **Integration test.** Add a test under `test/integration/` (build tag `integration`) that runs the built image on the sample against the fake import API and checks what was uploaded.
5. **Notices.** Record the tool, its pinned version and its licence in `THIRD_PARTY_NOTICES.md`.

## Licence

The scanners and their images are Apache-2.0. The tools they run keep their own licences, listed in THIRD_PARTY_NOTICES.md.

By contributing, you agree that your contribution is licensed under the Apache License 2.0 (see `LICENSE`).

## Conduct and security

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md). Report a vulnerability privately as [SECURITY.md](SECURITY.md) explains, never in a public issue.
