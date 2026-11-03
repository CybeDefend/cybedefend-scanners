# appsec-scanners-trivy-config: Trivy's `config` scan (iac), normalised and
# uploaded by appsec-scanner. Build from the repository root:
#   docker build -f images/trivy-config/Dockerfile -t appsec-scanners-trivy-config:dev .
#
# Trivy runs on its embedded checks only (--skip-check-update): no download at
# run time, so the image works with --network none.

ARG VERSION=dev

# Stage 1: the static appsec-scanner binary.
FROM golang:1.26.0-alpine@sha256:d4c4845f5d60c6a974c6000ce58ae079328d03ab7f721a0734277e69905473e5 AS build
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
# The default --out (/tmp/appsec-scanner/results.sarif) is written by uid
# 65532: that empty directory only is handed to it, nothing recursive.
RUN mkdir -p /tmp/appsec-scanner && chown 65532:65532 /tmp/appsec-scanner
# uid 65532 has no home directory: Trivy's default cache directory lives under HOME.
ENV HOME=/tmp
USER 65532:65532
WORKDIR /src
ENTRYPOINT ["/usr/local/bin/appsec-scanner","run","trivy-config"]
