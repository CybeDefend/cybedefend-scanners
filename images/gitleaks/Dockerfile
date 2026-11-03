# appsec-scanners-gitleaks: Gitleaks v8 (MIT) and appsec-scanner.
# Build from the repository root:
#   docker build -f images/gitleaks/Dockerfile -t appsec-scanners-gitleaks:dev .
#
# Pins, resolved from the registries on 2026-11-03 (multi-arch index digests):
#   golang:1.26.10-alpine      sha256:a2012b4a1d1f9f7e9f44e0d39b805a901e856b1dd80b4e6ee4338db547050308
#   alpine:3.22.7              sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f
# Gitleaks is built from source: the module github.com/zricethezav/gitleaks/v8
# v8.30.1 (tag commit 83d9cd684c87d95d656c1458ef04895a7f1cbd8e), fetched from
# the Go module proxy, checked by sum.golang.org and against its go.sum hash.

FROM golang:1.26.10-alpine@sha256:a2012b4a1d1f9f7e9f44e0d39b805a901e856b1dd80b4e6ee4338db547050308 AS build
WORKDIR /build
COPY go.mod go.sum* ./
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/appsec-scanner ./cmd/appsec-scanner

# Gitleaks, built from its v8.30.1 source as upstream's own Dockerfile builds
# it (CGO_ENABLED=0, no build tags, version.Version set to the tag), with the
# patched Go above. The upstream image's binary (Go 1.24.13) carried 69 known
# vulnerabilities (trivy-image, 2026-11-03). Only the modules a scan named are
# raised, each to its first fixed release (THIRD_PARTY_NOTICES.md); x/sys
# (first fixed 0.44.0) is raised to 0.47.0 by x/crypto 0.56.0's own go.mod.
# nwaples/rardecode/v2 stays v2.1.0 (CVE-2025-11579): v2.2.0 changed the API
# mholt/archives v0.1.2 builds on, and only archive traversal decodes RAR,
# which gitleaks does not do unless --max-archive-depth is set (never by
# appsec-scanner).
FROM golang:1.26.10-alpine@sha256:a2012b4a1d1f9f7e9f44e0d39b805a901e856b1dd80b4e6ee4338db547050308 AS gitleaks
ARG GITLEAKS_VERSION=v8.30.1
ARG GITLEAKS_MODULE_SUM=h1:PmEvCfVI7ti9dV3s5aMZUY7sS2GxRvG3yzih7E+cS3w=
# The Go of this stage builds it, never a toolchain named by its go.mod.
ENV GOTOOLCHAIN=local GOFLAGS=-mod=mod
WORKDIR /gitleaks
RUN set -eu; \
    go mod download -json "github.com/zricethezav/gitleaks/v8@${GITLEAKS_VERSION}" > /tmp/module.json; \
    sum="$(sed -n 's/^[[:space:]]*"Sum": "\(.*\)",*$/\1/p' /tmp/module.json)"; \
    if [ "$sum" != "${GITLEAKS_MODULE_SUM}" ]; then echo "gitleaks module sum is '$sum', want ${GITLEAKS_MODULE_SUM}" >&2; exit 1; fi; \
    dir="$(sed -n 's/^[[:space:]]*"Dir": "\(.*\)",*$/\1/p' /tmp/module.json)"; \
    cp -R "$dir"/. .; chmod -R u+w .; \
    go get \
      golang.org/x/crypto@v0.56.0 \
      golang.org/x/text@v0.41.0 \
      github.com/klauspost/compress@v1.18.7 \
      github.com/ulikunitz/xz@v0.5.15; \
    go mod verify; \
    go list -m golang.org/x/crypto golang.org/x/text golang.org/x/sys github.com/klauspost/compress github.com/ulikunitz/xz github.com/nwaples/rardecode/v2; \
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X=github.com/zricethezav/gitleaks/v8/version.Version=${GITLEAKS_VERSION}" -o /out/gitleaks .

FROM alpine:3.22.7@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f
LABEL org.opencontainers.image.title="appsec-scanners-gitleaks" \
      org.opencontainers.image.description="Gitleaks secret scan, redacted SARIF, upload to a CybeDefend import API" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=gitleaks /out/gitleaks /usr/bin/gitleaks
COPY --from=build /out/appsec-scanner /usr/local/bin/appsec-scanner
COPY LICENSE NOTICE /usr/share/doc/appsec-scanners/
# The default --out (/tmp/appsec-scanner/results.sarif) is written by uid
# 65532, with the tools' HOME and TMPDIR under it: those three empty
# directories only are handed to it, nothing recursive.
RUN mkdir -p /tmp/appsec-scanner/home /tmp/appsec-scanner/tmp && chown 65532:65532 /tmp/appsec-scanner /tmp/appsec-scanner/home /tmp/appsec-scanner/tmp
WORKDIR /src
# Tools write their home and temporary files under the default --out
# directory, the only place a hardened run (--read-only --tmpfs
# /tmp/appsec-scanner) leaves writable. The image ships both; appsec-scanner
# creates them again when an empty tmpfs or emptyDir is mounted there.
ENV HOME=/tmp/appsec-scanner/home TMPDIR=/tmp/appsec-scanner/tmp
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/appsec-scanner","run","gitleaks"]
