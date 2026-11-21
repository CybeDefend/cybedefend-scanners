# cybedefend-scanners/zizmor: zizmor (MIT) audits GitHub Actions workflows, and
# cybedefend-scanner normalises its SARIF and uploads it as a `cicd` import.
#
# Build from the repository root:
#   docker build -f images/zizmor/Dockerfile -t cybedefend-scanners/zizmor:dev .

# Stage 1: the static cybedefend-scanner binary.
FROM --platform=$BUILDPLATFORM golang:1.26.11-alpine@sha256:ecb67f987aa1a57794c91d19ade7ae0209f2f0f5496aaef9e6ae85ddf92d02ab AS build
# Runs on the build machine; Go compiles for the target platform.
ARG TARGETOS TARGETARCH
ENV GOOS=${TARGETOS} GOARCH=${TARGETARCH}
WORKDIR /build
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/cybedefend-scanner ./cmd/cybedefend-scanner
# The default --out directory with HOME and TMPDIR, copied into the final stage.
RUN mkdir -p /out/tmp/cybedefend-scanner/home /out/tmp/cybedefend-scanner/tmp

# Stage 2: zizmor's own image (Wolfi base, /usr/bin/zizmor), multi-arch index
# of the 1.32.0 release.
FROM ghcr.io/zizmorcore/zizmor:1.32.0@sha256:3014cc8f68f663935f69b3c3e0e41f5ce102b268d97db13db0f62208747f860d
COPY --from=build /out/cybedefend-scanner /usr/local/bin/cybedefend-scanner
# What the image redistributes, each with its licence: our program, the Go
# runtime compiled into it, and the tool (THIRD_PARTY_NOTICES.md).
LABEL org.opencontainers.image.licenses="Apache-2.0 AND BSD-3-Clause AND MIT"
COPY LICENSE NOTICE THIRD_PARTY_NOTICES.md /usr/share/licenses/cybedefend-scanners/
COPY licenses/go /usr/share/licenses/cybedefend-scanners/go/
COPY licenses/zizmor /usr/share/licenses/cybedefend-scanners/zizmor/
# The default --out (/tmp/cybedefend-scanner/results.sarif) is written by uid
# 65532: the cybedefend-scanner directory (with empty home/ and tmp/) is copied in,
# owned by it, so the final stage runs no command in the tool's own image.
COPY --from=build --chown=65532:65532 /out/tmp/ /tmp/
# Tools write their home and temporary files under the default --out
# directory, the only place a hardened run (--read-only --tmpfs
# /tmp/cybedefend-scanner) leaves writable. The image ships both; cybedefend-scanner
# creates them again when an empty tmpfs or emptyDir is mounted there.
ENV HOME=/tmp/cybedefend-scanner/home TMPDIR=/tmp/cybedefend-scanner/tmp
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/cybedefend-scanner","run","zizmor"]
