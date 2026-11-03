# appsec-scanners-opengrep: Opengrep (LGPL-2.1) with CybeDefend's own rules.
# Build from the repository root: docker build -f images/opengrep/Dockerfile .

# golang:1.26.10-alpine (multi-arch index)
FROM golang:1.26.10-alpine@sha256:a2012b4a1d1f9f7e9f44e0d39b805a901e856b1dd80b4e6ee4338db547050308 AS build
ARG VERSION=dev
WORKDIR /build
COPY go.mod go.sum* ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/appsec-scanner ./cmd/appsec-scanner

# The Opengrep release binary, checked against the sha256 GitHub publishes
# for each asset of https://github.com/opengrep/opengrep/releases/tag/v1.33.1
FROM golang:1.26.10-alpine@sha256:a2012b4a1d1f9f7e9f44e0d39b805a901e856b1dd80b4e6ee4338db547050308 AS opengrep
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
# The release binary is a one-file bundle that unpacks itself (244 MB) under
# XDG_CACHE_HOME, then runs from there. Unpacked once here, root-owned and
# read-only for uid 65532: a run writes none of it, and a noexec tmpfs at
# /tmp/appsec-scanner (Docker's --tmpfs default) does not stop it.
ENV XDG_CACHE_HOME=/opt/appsec-scanners/opengrep-cache
RUN XDG_CACHE_HOME=/opt/appsec-scanners/opengrep-cache opengrep --version > /dev/null \
    && chmod -R a+rX,go-w /opt/appsec-scanners/opengrep-cache
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
ENTRYPOINT ["/usr/local/bin/appsec-scanner", "run", "opengrep"]
