# cybedefend-scanners/zizmor: zizmor (MIT) audits GitHub Actions workflows, and
# appsec-scanner normalises its SARIF and uploads it as a `cicd` import.
#
# Build from the repository root:
#   docker build -f images/zizmor/Dockerfile -t cybedefend-scanners/zizmor:dev .

# Stage 1: the static appsec-scanner binary.
FROM --platform=$BUILDPLATFORM golang:1.26.10-alpine@sha256:a2012b4a1d1f9f7e9f44e0d39b805a901e856b1dd80b4e6ee4338db547050308 AS build
# Runs on the build machine; Go compiles for the target platform.
ARG TARGETOS TARGETARCH
ENV GOOS=${TARGETOS} GOARCH=${TARGETARCH}
WORKDIR /build
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/appsec-scanner ./cmd/appsec-scanner
# The default --out directory with HOME and TMPDIR, copied into the final stage.
RUN mkdir -p /out/tmp/appsec-scanner/home /out/tmp/appsec-scanner/tmp

# Stage 2: zizmor's own image (Wolfi base, /usr/bin/zizmor), multi-arch index
# of the 1.31.1 release.
FROM ghcr.io/zizmorcore/zizmor:1.31.1@sha256:42d409dbb851d4c5d35a058cf042b828bea1e3f2884378c526eb0974780e18d9
COPY --from=build /out/appsec-scanner /usr/local/bin/appsec-scanner
# What the image redistributes, each with its licence: our program, the Go
# runtime compiled into it, and the tool (THIRD_PARTY_NOTICES.md).
LABEL org.opencontainers.image.licenses="Apache-2.0 AND BSD-3-Clause AND MIT"
COPY LICENSE NOTICE THIRD_PARTY_NOTICES.md /usr/share/licenses/cybedefend-scanners/
COPY licenses/go /usr/share/licenses/cybedefend-scanners/go/
COPY licenses/zizmor /usr/share/licenses/cybedefend-scanners/zizmor/
# The default --out (/tmp/appsec-scanner/results.sarif) is written by uid
# 65532: the appsec-scanner directory (with empty home/ and tmp/) is copied in,
# owned by it, so the final stage runs no command in the tool's own image.
COPY --from=build --chown=65532:65532 /out/tmp/ /tmp/
# Tools write their home and temporary files under the default --out
# directory, the only place a hardened run (--read-only --tmpfs
# /tmp/appsec-scanner) leaves writable. The image ships both; appsec-scanner
# creates them again when an empty tmpfs or emptyDir is mounted there.
ENV HOME=/tmp/appsec-scanner/home TMPDIR=/tmp/appsec-scanner/tmp
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/appsec-scanner","run","zizmor"]
