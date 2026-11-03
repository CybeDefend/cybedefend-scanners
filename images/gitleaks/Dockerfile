# appsec-scanners-gitleaks: Gitleaks v8 (MIT) and appsec-scanner.
# Build from the repository root:
#   docker build -f images/gitleaks/Dockerfile -t appsec-scanners-gitleaks:dev .
#
# Pins, resolved from the registries on 2026-11-03 (multi-arch index digests):
#   golang:1.26.0-alpine3.22   sha256:169d3991a4f795124a88b33c73549955a3d856e26e8504b5530c30bd245f9f1b
#   zricethezav/gitleaks:v8.30.1 sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f
#   alpine:3.22.7              sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f
# Nothing is downloaded outside these images.

FROM golang:1.26.0-alpine3.22@sha256:169d3991a4f795124a88b33c73549955a3d856e26e8504b5530c30bd245f9f1b AS build
WORKDIR /build
COPY go.mod go.sum* ./
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/appsec-scanner ./cmd/appsec-scanner

# The upstream image only provides the binary, a static Go build (CGO_ENABLED=0).
FROM zricethezav/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f AS gitleaks

FROM alpine:3.22.7@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f
LABEL org.opencontainers.image.title="appsec-scanners-gitleaks" \
      org.opencontainers.image.description="Gitleaks secret scan, redacted SARIF, upload to a CybeDefend import API" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=gitleaks /usr/bin/gitleaks /usr/bin/gitleaks
COPY --from=build /out/appsec-scanner /usr/local/bin/appsec-scanner
COPY LICENSE NOTICE /usr/share/doc/appsec-scanners/
# The default --out (/tmp/appsec-scanner/results.sarif) is written by uid
# 65532: that empty directory only is handed to it, nothing recursive.
RUN mkdir -p /tmp/appsec-scanner && chown 65532:65532 /tmp/appsec-scanner
WORKDIR /src
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/appsec-scanner","run","gitleaks"]
