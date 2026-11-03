# appsec-scanners-trivy-image: Trivy vulnerability scan of a container image (type container).
# Build from the repository root: docker build -f images/trivy-image/Dockerfile .
#
# The tool stage is the one images/trivy-fs uses (same version, same digest).
# No vulnerability database is baked in: Trivy downloads it at run time into
# /tmp/appsec-scanner/trivy-cache (ghcr.io/aquasecurity/trivy-db, or the mirror
# named by TRIVY_DB_REPOSITORY), so a scan never runs on a database as old as
# the image.
#
# No Docker socket is used: an image built in the job reaches the scanner as a
# `docker save` archive (IMAGE_ARCHIVE or --image-archive), and a registry
# image is pulled by Trivy itself (TRIVY_USERNAME, TRIVY_PASSWORD or
# TRIVY_REGISTRY_TOKEN for a private registry). CYBEDEFEND_IMAGE names the
# image in both cases.

# Trivy 0.76.1 (Apache-2.0).
FROM aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c AS trivy

FROM golang:1.26.0-alpine@sha256:d4c4845f5d60c6a974c6000ce58ae079328d03ab7f721a0734277e69905473e5 AS build
ARG VERSION=dev
WORKDIR /build
COPY go.* ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/appsec-scanner ./cmd/appsec-scanner

FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=build /out/appsec-scanner /usr/local/bin/appsec-scanner
# The two directories uid 65532 writes: the default --out
# (/tmp/appsec-scanner/results.sarif) and Trivy's cache. Nothing else is chowned.
RUN mkdir -p /tmp/appsec-scanner/trivy-cache && chown 65532:65532 /tmp/appsec-scanner /tmp/appsec-scanner/trivy-cache
USER 65532:65532
# uid 65532 has no passwd entry: give the tool a writable HOME.
ENV HOME=/tmp
WORKDIR /src
ENTRYPOINT ["/usr/local/bin/appsec-scanner","run","trivy-image"]
