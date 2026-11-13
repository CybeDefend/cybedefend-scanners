#!/usr/bin/env bash
# Run one CybeDefend AppSec scanner on a local directory, the way the GitHub
# Action and the GitLab template do.
#
#   examples/local/run.sh <scanner> [directory]          scan, write the SARIF
#   examples/local/run.sh trivy-image <image>            scan a local or remote image
#
# <scanner> is opengrep, gitleaks, trivy-config, zizmor, trivy-fs or
# trivy-image. The normalised SARIF is written to ./cybedefend-<scanner>.sarif.
#
# To upload it, export CYBEDEFEND_API_URL, CYBEDEFEND_PROJECT_ID and
# CYBEDEFEND_TOKEN (and CYBEDEFEND_BRANCH outside a git checkout) first. The
# token is passed to the container by name, never on a command line; read it
# without echo, for example: read -rs CYBEDEFEND_TOKEN && export CYBEDEFEND_TOKEN
#
# SCANNERS_VERSION picks the image version (default: latest).
set -euo pipefail

usage() {
  echo "usage: $0 <opengrep|gitleaks|trivy-config|zizmor|trivy-fs> [directory]" >&2
  echo "       $0 trivy-image <image>" >&2
  exit 4
}

[ $# -ge 1 ] || usage
scanner="$1"
version="${SCANNERS_VERSION:-latest}"
case "$scanner" in
  opengrep|gitleaks|trivy-config|zizmor|trivy-fs|trivy-image) ;;
  *) usage ;;
esac

args=(run --network host)
if [ "$scanner" = trivy-image ]; then
  [ $# -eq 2 ] || usage
  case "$2" in -*) usage ;; esac
  export CYBEDEFEND_IMAGE="$2"
  src="$(pwd -P)"
  args+=(-e CYBEDEFEND_IMAGE -e TRIVY_USERNAME -e TRIVY_PASSWORD -e TRIVY_REGISTRY_TOKEN)
  # An image of the local daemon is saved and scanned from its archive.
  if docker image inspect "$CYBEDEFEND_IMAGE" > /dev/null 2>&1; then
    work="$(mktemp -d)"
    chmod 0755 "$work"
    docker save -o "$work/cybedefend-image.tar" "$CYBEDEFEND_IMAGE"
    chmod 0644 "$work/cybedefend-image.tar"
    export IMAGE_ARCHIVE=/out/cybedefend-image.tar
    args+=(-v "$work:/out:ro" -e IMAGE_ARCHIVE)
  fi
else
  [ $# -le 2 ] || usage
  src="$(cd "${2:-.}" && pwd -P)"
  # zizmor's online audits.
  [ "$scanner" != zizmor ] || args+=(-e GH_TOKEN)
fi

if [ -z "${CYBEDEFEND_BRANCH:-}" ] && git -C "$src" rev-parse --abbrev-ref HEAD > /dev/null 2>&1; then
  CYBEDEFEND_BRANCH="$(git -C "$src" rev-parse --abbrev-ref HEAD)"
  export CYBEDEFEND_BRANCH
fi

upload=()
if [ -n "${CYBEDEFEND_API_URL:-}" ]; then
  upload=(--upload)
fi

name="cybedefend-$scanner-$$"
trap 'docker rm -f "$name" > /dev/null 2>&1 || true; rm -rf "${work:-}"' EXIT

sarif="cybedefend-$scanner.sarif"
status=0
docker "${args[@]}" --name "$name" -v "$src:/src:ro" \
  -e CYBEDEFEND_API_URL -e CYBEDEFEND_TOKEN -e CYBEDEFEND_PROJECT_ID -e CYBEDEFEND_BRANCH \
  "ghcr.io/cybedefend/cybedefend-scanners/$scanner:$version" --out "/tmp/appsec-scanner/$sarif" ${upload[@]+"${upload[@]}"} || status=$?

# The SARIF is owned by the scanner's user in the container: docker cp gives a
# copy owned by you.
if docker cp "$name:/tmp/appsec-scanner/$sarif" "./$sarif" > /dev/null 2>&1; then
  echo "wrote ./$sarif"
fi
exit "$status"
