# appsec-scanners-trivy-config: Trivy's `config` scan (iac), normalised and
# uploaded by appsec-scanner. Build from the repository root:
#   docker build -f images/trivy-config/Dockerfile -t appsec-scanners-trivy-config:dev .
#
# Trivy runs on its embedded checks only (--skip-check-update): no download at
# run time, so the image works with --network none.

ARG VERSION=dev

# Stage 1: the static appsec-scanner binary.
FROM golang:1.26.10-alpine@sha256:a2012b4a1d1f9f7e9f44e0d39b805a901e856b1dd80b4e6ee4338db547050308 AS build
ARG VERSION
WORKDIR /build
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/appsec-scanner ./cmd/appsec-scanner

# Stage 2: the tool. Trivy v0.76.1, Apache-2.0 (multi-arch index digest).
FROM aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c AS tool

# Final stage.
FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
COPY --from=tool /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=build /out/appsec-scanner /usr/local/bin/appsec-scanner
# What the image redistributes, each with its licence: our program, the Go
# runtime compiled into it, and the tool (THIRD_PARTY_NOTICES.md).
LABEL org.opencontainers.image.licenses="Apache-2.0 AND BSD-3-Clause"
COPY LICENSE NOTICE THIRD_PARTY_NOTICES.md /usr/share/licenses/cybedefend-scanners/
COPY licenses/go /usr/share/licenses/cybedefend-scanners/go/
COPY licenses/trivy /usr/share/licenses/cybedefend-scanners/trivy/
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
ENTRYPOINT ["/usr/local/bin/appsec-scanner","run","trivy-config"]
