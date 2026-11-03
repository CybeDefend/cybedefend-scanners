# appsec-scanners-opengrep: Opengrep (LGPL-2.1) with CybeDefend's own rules.
# Build from the repository root: docker build -f images/opengrep/Dockerfile .

# golang:1.26.0-alpine (multi-arch index)
FROM golang:1.26.0-alpine@sha256:d4c4845f5d60c6a974c6000ce58ae079328d03ab7f721a0734277e69905473e5 AS build
ARG VERSION=dev
WORKDIR /build
COPY go.mod go.sum* ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/appsec-scanner ./cmd/appsec-scanner

# The Opengrep release binary, checked against the sha256 GitHub publishes
# for each asset of https://github.com/opengrep/opengrep/releases/tag/v1.33.1
FROM golang:1.26.0-alpine@sha256:d4c4845f5d60c6a974c6000ce58ae079328d03ab7f721a0734277e69905473e5 AS opengrep
ARG TARGETARCH
ARG OPENGREP_VERSION=v1.33.1
ARG OPENGREP_SHA256_AMD64=46e8133cc490f9f50518061590ce2f6be5a08afaeda034471c0ceda4b3899808
ARG OPENGREP_SHA256_ARM64=d1433f63a90b8bc0b6ad4b498a13b372b856ce9a754a43484ba4920fe2d76dcf
RUN set -eu; \
    case "${TARGETARCH:-amd64}" in \
      amd64) asset=opengrep_manylinux_x86; sum="${OPENGREP_SHA256_AMD64}" ;; \
      arm64) asset=opengrep_manylinux_aarch64; sum="${OPENGREP_SHA256_ARM64}" ;; \
      *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    wget -q -O /tmp/opengrep "https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/${asset}"; \
    echo "${sum}  /tmp/opengrep" | sha256sum -c -; \
    install -m 0755 /tmp/opengrep /out-opengrep

# Opengrep's release binary is linked against glibc.
# debian:bookworm-slim (multi-arch index)
FROM debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3
COPY --from=opengrep /out-opengrep /usr/local/bin/opengrep
COPY --from=build /out/appsec-scanner /usr/local/bin/appsec-scanner
COPY rules/opengrep /opt/appsec-scanners/rules/opengrep
# The default --out (/tmp/appsec-scanner/results.sarif) is written by uid
# 65532: that empty directory only is handed to it, nothing recursive.
RUN mkdir -p /tmp/appsec-scanner && chown 65532:65532 /tmp/appsec-scanner
ENV HOME=/tmp
USER 65532:65532
WORKDIR /tmp
ENTRYPOINT ["/usr/local/bin/appsec-scanner", "run", "opengrep"]
