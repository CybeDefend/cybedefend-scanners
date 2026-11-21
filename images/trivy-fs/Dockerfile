# cybedefend-scanners/trivy-fs: Trivy vulnerability scan of a source tree (type sca).
# Build from the repository root: docker build -f images/trivy-fs/Dockerfile .
#
# The tool stage is the one images/trivy-config uses (same version, same
# digest). No vulnerability database is baked in: Trivy downloads it at run
# time into /tmp/cybedefend-scanner/trivy-cache (ghcr.io/aquasecurity/trivy-db, or
# the mirror named by TRIVY_DB_REPOSITORY), so a scan never runs on a database
# as old as the image.

# Trivy 0.76.2 (Apache-2.0).
FROM aquasec/trivy:0.76.2@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb AS trivy

FROM --platform=$BUILDPLATFORM golang:1.26.11-alpine@sha256:ecb67f987aa1a57794c91d19ade7ae0209f2f0f5496aaef9e6ae85ddf92d02ab AS build
# Runs on the build machine; Go compiles for the target platform.
ARG TARGETOS TARGETARCH
ENV GOOS=${TARGETOS} GOARCH=${TARGETARCH}
ARG VERSION=dev
WORKDIR /build
COPY go.* ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/cybedefend-scanner ./cmd/cybedefend-scanner

FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=build /out/cybedefend-scanner /usr/local/bin/cybedefend-scanner
# What the image redistributes, each with its licence: our program, the Go
# runtime compiled into it, and the tool (THIRD_PARTY_NOTICES.md).
LABEL org.opencontainers.image.licenses="Apache-2.0 AND BSD-3-Clause"
COPY LICENSE NOTICE THIRD_PARTY_NOTICES.md /usr/share/licenses/cybedefend-scanners/
COPY licenses/go /usr/share/licenses/cybedefend-scanners/go/
COPY licenses/trivy /usr/share/licenses/cybedefend-scanners/trivy/
# The two directories uid 65532 writes: the default --out
# (/tmp/cybedefend-scanner/results.sarif), Trivy's cache, HOME and TMPDIR.
# Nothing else is chowned.
RUN mkdir -p /tmp/cybedefend-scanner/trivy-cache /tmp/cybedefend-scanner/home /tmp/cybedefend-scanner/tmp && chown 65532:65532 /tmp/cybedefend-scanner /tmp/cybedefend-scanner/trivy-cache /tmp/cybedefend-scanner/home /tmp/cybedefend-scanner/tmp
WORKDIR /src
# Tools write their home and temporary files under the default --out
# directory, the only place a hardened run (--read-only --tmpfs
# /tmp/cybedefend-scanner) leaves writable. The image ships both; cybedefend-scanner
# creates them again when an empty tmpfs or emptyDir is mounted there.
ENV HOME=/tmp/cybedefend-scanner/home TMPDIR=/tmp/cybedefend-scanner/tmp
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/cybedefend-scanner","run","trivy-fs"]
