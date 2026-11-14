# cybedefend-scanners/trivy-image: Trivy vulnerability scan of a container image (type container).
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
FROM aquasec/trivy:0.76.2@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb AS trivy

FROM --platform=$BUILDPLATFORM golang:1.26.11-alpine@sha256:ae52b5bc6ed045a9ed26ab03dc19327a802a9cc9aa8b27ed57f5c6b60579b0bb AS build
# Runs on the build machine; Go compiles for the target platform.
ARG TARGETOS TARGETARCH
ENV GOOS=${TARGETOS} GOARCH=${TARGETARCH}
ARG VERSION=dev
WORKDIR /build
COPY go.* ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/appsec-scanner ./cmd/appsec-scanner

FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=build /out/appsec-scanner /usr/local/bin/appsec-scanner
# What the image redistributes, each with its licence: our program, the Go
# runtime compiled into it, and the tool (THIRD_PARTY_NOTICES.md).
LABEL org.opencontainers.image.licenses="Apache-2.0 AND BSD-3-Clause"
COPY LICENSE NOTICE THIRD_PARTY_NOTICES.md /usr/share/licenses/cybedefend-scanners/
COPY licenses/go /usr/share/licenses/cybedefend-scanners/go/
COPY licenses/trivy /usr/share/licenses/cybedefend-scanners/trivy/
# The two directories uid 65532 writes: the default --out
# (/tmp/appsec-scanner/results.sarif), Trivy's cache, HOME and TMPDIR.
# Nothing else is chowned.
RUN mkdir -p /tmp/appsec-scanner/trivy-cache /tmp/appsec-scanner/home /tmp/appsec-scanner/tmp && chown 65532:65532 /tmp/appsec-scanner /tmp/appsec-scanner/trivy-cache /tmp/appsec-scanner/home /tmp/appsec-scanner/tmp
WORKDIR /src
# Tools write their home and temporary files under the default --out
# directory, the only place a hardened run (--read-only --tmpfs
# /tmp/appsec-scanner) leaves writable. The image ships both; appsec-scanner
# creates them again when an empty tmpfs or emptyDir is mounted there.
ENV HOME=/tmp/appsec-scanner/home TMPDIR=/tmp/appsec-scanner/tmp
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/appsec-scanner","run","trivy-image"]
