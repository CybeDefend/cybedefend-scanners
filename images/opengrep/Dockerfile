# cybedefend-scanners/opengrep: Opengrep (LGPL-2.1) with CybeDefend's own rules.
# Build from the repository root: docker build -f images/opengrep/Dockerfile .

# golang:1.26.11-alpine (multi-arch index)
FROM --platform=$BUILDPLATFORM golang:1.26.11-alpine@sha256:ecb67f987aa1a57794c91d19ade7ae0209f2f0f5496aaef9e6ae85ddf92d02ab AS build
# Runs on the build machine; Go compiles for the target platform.
ARG TARGETOS TARGETARCH
ENV GOOS=${TARGETOS} GOARCH=${TARGETARCH}
ARG VERSION=dev
WORKDIR /build
COPY go.mod go.sum* ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/cybedefend-scanner ./cmd/cybedefend-scanner

# The Opengrep release binary, checked against the sha256 GitHub publishes
# for each asset of https://github.com/opengrep/opengrep/releases/tag/v1.33.1
FROM --platform=$BUILDPLATFORM golang:1.26.11-alpine@sha256:ecb67f987aa1a57794c91d19ade7ae0209f2f0f5496aaef9e6ae85ddf92d02ab AS opengrep
# Runs on the build machine; downloads the target platform's binary.
ARG TARGETOS TARGETARCH
ENV GOOS=${TARGETOS} GOARCH=${TARGETARCH}
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
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
COPY --from=opengrep /out-opengrep /usr/local/bin/opengrep
COPY --from=build /out/cybedefend-scanner /usr/local/bin/cybedefend-scanner
# What the image redistributes, each with its licence: our program, the Go
# runtime compiled into it, and the tool (THIRD_PARTY_NOTICES.md).
LABEL org.opencontainers.image.licenses="Apache-2.0 AND BSD-3-Clause AND LGPL-2.1-only"
COPY LICENSE NOTICE THIRD_PARTY_NOTICES.md /usr/share/licenses/cybedefend-scanners/
COPY licenses/go /usr/share/licenses/cybedefend-scanners/go/
COPY licenses/opengrep /usr/share/licenses/cybedefend-scanners/opengrep/
COPY rules/opengrep /opt/cybedefend-scanners/rules/opengrep
# The release binary is a one-file bundle that unpacks itself (244 MB) under
# XDG_CACHE_HOME, then runs from there. Unpacked once here, root-owned and
# read-only for uid 65532: a run writes none of it, and a noexec tmpfs at
# /tmp/cybedefend-scanner (Docker's --tmpfs default) does not stop it.
ENV XDG_CACHE_HOME=/opt/cybedefend-scanners/opengrep-cache
RUN XDG_CACHE_HOME=/opt/cybedefend-scanners/opengrep-cache opengrep --version > /dev/null \
    && chmod -R a+rX,go-w /opt/cybedefend-scanners/opengrep-cache
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
ENTRYPOINT ["/usr/local/bin/cybedefend-scanner", "run", "opengrep"]
