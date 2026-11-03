# appsec-scanners-zizmor: zizmor (MIT) audits GitHub Actions workflows, and
# appsec-scanner normalises its SARIF and uploads it as a `cicd` import.
#
# Build from the repository root:
#   docker build -f images/zizmor/Dockerfile -t appsec-scanners-zizmor:dev .

# Stage 1: the static appsec-scanner binary.
FROM golang:1.26.0-alpine@sha256:d4c4845f5d60c6a974c6000ce58ae079328d03ab7f721a0734277e69905473e5 AS build
WORKDIR /build
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/appsec-scanner ./cmd/appsec-scanner

# Stage 2: zizmor's own image (Wolfi base, /usr/bin/zizmor), multi-arch index
# of the 1.31.1 release.
FROM ghcr.io/zizmorcore/zizmor:1.31.1@sha256:42d409dbb851d4c5d35a058cf042b828bea1e3f2884378c526eb0974780e18d9
COPY --from=build /out/appsec-scanner /usr/local/bin/appsec-scanner
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/appsec-scanner","run","zizmor"]
