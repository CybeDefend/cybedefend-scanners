# cybedefend-scanners/trivy-config: Trivy's `config` scan (iac), normalised and
# uploaded by cybedefend-scanner. Build from the repository root:
#   docker build -f images/trivy-config/Dockerfile -t cybedefend-scanners/trivy-config:dev .
#
# Trivy runs on its embedded checks only (--skip-check-update): no download at
# run time, so the image works with --network none.

ARG VERSION=dev

# Stage 1: the static cybedefend-scanner binary.
FROM --platform=$BUILDPLATFORM golang:1.26.11-alpine@sha256:ecb67f987aa1a57794c91d19ade7ae0209f2f0f5496aaef9e6ae85ddf92d02ab AS build
# Runs on the build machine; Go compiles for the target platform.
ARG TARGETOS TARGETARCH
ENV GOOS=${TARGETOS} GOARCH=${TARGETARCH}
ARG VERSION
WORKDIR /build
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/cybedefend-scanner ./cmd/cybedefend-scanner

# Stage 2: the tool. Trivy v0.76.2, Apache-2.0 (multi-arch index digest).
FROM aquasec/trivy:0.76.2@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb AS tool

# Final stage.
FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
COPY --from=tool /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=build /out/cybedefend-scanner /usr/local/bin/cybedefend-scanner
# What the image redistributes, each with its licence: our program, the Go
# runtime compiled into it, and the tool (THIRD_PARTY_NOTICES.md).
LABEL org.opencontainers.image.licenses="Apache-2.0 AND BSD-3-Clause"
COPY LICENSE NOTICE THIRD_PARTY_NOTICES.md /usr/share/licenses/cybedefend-scanners/
COPY licenses/go /usr/share/licenses/cybedefend-scanners/go/
COPY licenses/trivy /usr/share/licenses/cybedefend-scanners/trivy/
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
ENTRYPOINT ["/usr/local/bin/cybedefend-scanner","run","trivy-config"]
