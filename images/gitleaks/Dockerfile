# cybedefend-scanners/gitleaks: Gitleaks v8 (MIT) and cybedefend-scanner.
# Build from the repository root:
#   docker build -f images/gitleaks/Dockerfile -t cybedefend-scanners/gitleaks:dev .
#
# Pins, resolved from the registries on 2026-11-14 (multi-arch index digests):
#   golang:1.26.11-alpine      sha256:ae52b5bc6ed045a9ed26ab03dc19327a802a9cc9aa8b27ed57f5c6b60579b0bb
#   alpine:3.24.4              sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
# Gitleaks is built from source: the module github.com/zricethezav/gitleaks/v8
# v8.30.1 (tag commit 83d9cd684c87d95d656c1458ef04895a7f1cbd8e), fetched from
# the Go module proxy, checked by sum.golang.org and against its go.sum hash.

FROM --platform=$BUILDPLATFORM golang:1.26.11-alpine@sha256:ecb67f987aa1a57794c91d19ade7ae0209f2f0f5496aaef9e6ae85ddf92d02ab AS build
# Runs on the build machine; Go compiles for the target platform.
ARG TARGETOS TARGETARCH
ENV GOOS=${TARGETOS} GOARCH=${TARGETARCH}
WORKDIR /build
COPY go.mod go.sum* ./
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/cybedefend-scanner ./cmd/cybedefend-scanner

# Gitleaks, built from its v8.30.1 source as upstream's own Dockerfile builds
# it (CGO_ENABLED=0, no build tags, version.Version set to the tag), with the
# patched Go above. The upstream image's binary (Go 1.24.13) carried 69 known
# vulnerabilities (trivy-image, 2026-11-03). Only the modules a scan named are
# raised, each to its first fixed release (THIRD_PARTY_NOTICES.md); x/sys
# (first fixed 0.44.0) is raised to 0.47.0 by x/crypto 0.56.0's own go.mod.
# nwaples/rardecode/v2 stays v2.1.0 (CVE-2025-11579): v2.2.0 changed the API
# mholt/archives v0.1.2 builds on, and only archive traversal decodes RAR,
# which gitleaks does not do unless --max-archive-depth is set (never by
# cybedefend-scanner).
FROM --platform=$BUILDPLATFORM golang:1.26.11-alpine@sha256:ecb67f987aa1a57794c91d19ade7ae0209f2f0f5496aaef9e6ae85ddf92d02ab AS gitleaks
# Runs on the build machine; Go compiles for the target platform.
ARG TARGETOS TARGETARCH
ENV GOOS=${TARGETOS} GOARCH=${TARGETARCH}
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
# The licence files of every module compiled into gitleaks, one directory per
# module@version under /out/licenses. A module without one fails the build:
# its licence would otherwise not ship with the binary.
RUN set -eu; \
    go list -deps -f '{{with .Module}}{{if not .Main}}{{.Path}}@{{.Version}} {{.Dir}}{{end}}{{end}}' . | sort -u > /tmp/modules; \
    test -s /tmp/modules; \
    while read -r mod dir; do \
      dest="/out/licenses/$mod"; mkdir -p "$dest"; found=0; \
      for f in "$dir"/LICENSE* "$dir"/LICENCE* "$dir"/COPYING* "$dir"/NOTICE* "$dir"/PATENTS*; do \
        if [ -f "$f" ]; then cp "$f" "$dest/"; found=1; fi; \
      done; \
      if [ "$found" = 0 ]; then echo "no licence file in $mod ($dir)" >&2; exit 1; fi; \
    done < /tmp/modules; \
    ls -R /out/licenses

FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
LABEL org.opencontainers.image.title="cybedefend-scanners/gitleaks" \
      org.opencontainers.image.description="Gitleaks secret scan, redacted SARIF, upload to a CybeDefend Community Edition import API"
COPY --from=gitleaks /out/gitleaks /usr/bin/gitleaks
COPY --from=build /out/cybedefend-scanner /usr/local/bin/cybedefend-scanner
# What the image redistributes, each with its licence: our program, the Go
# runtime compiled into it, gitleaks and the modules compiled into it
# (THIRD_PARTY_NOTICES.md).
LABEL org.opencontainers.image.licenses="Apache-2.0 AND BSD-3-Clause AND MIT"
COPY LICENSE NOTICE THIRD_PARTY_NOTICES.md /usr/share/licenses/cybedefend-scanners/
COPY licenses/go /usr/share/licenses/cybedefend-scanners/go/
COPY licenses/gitleaks /usr/share/licenses/cybedefend-scanners/gitleaks/
COPY --from=gitleaks /out/licenses /usr/share/licenses/cybedefend-scanners/gitleaks-modules/
# The default --out (/tmp/cybedefend-scanner/results.sarif) is written by uid
# 65532, with the tools' HOME and TMPDIR under it: those three empty
# directories only are handed to it, nothing recursive.
RUN mkdir -p /tmp/cybedefend-scanner/home /tmp/cybedefend-scanner/tmp && chown 65532:65532 /tmp/cybedefend-scanner /tmp/cybedefend-scanner/home /tmp/cybedefend-scanner/tmp
WORKDIR /src
# Tools write their home and temporary files under the default --out
# directory, the only place a hardened run (--read-only --tmpfs
# /tmp/cybedefend-scanner) leaves writable. The image ships both; cybedefend-scanner
# creates them again when an empty tmpfs or emptyDir is mounted there.
ENV HOME=/tmp/cybedefend-scanner/home TMPDIR=/tmp/cybedefend-scanner/tmp
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/cybedefend-scanner","run","gitleaks"]
