#!/usr/bin/env bash
# Runs every generated CIS benchmark in a container of its target platform
# and reports broken commands (see analyze.py).
#
#   test/linux/run-cis.sh [benchmark ...]      default: all
set -euo pipefail

cd "$(dirname "$0")/../.."
root=$(pwd)
out="$root/test/linux/out-cis"
mkdir -p "$out" bin

# Container image of each benchmark's platform (portable: no associative
# arrays, which bash 3.2 on macOS lacks).
image_for() {
  case "$1" in
    rhel7) echo centos:7 ;;          rhel8) echo rockylinux:8 ;;
    rhel9) echo rockylinux:9 ;;      rhel10) echo rockylinux/rockylinux:10 ;;
    debian11) echo debian:11 ;;      debian12) echo debian:12 ;;      debian13) echo debian:13 ;;
    ubuntu20) echo ubuntu:20.04 ;;   ubuntu22) echo ubuntu:22.04 ;;   ubuntu24) echo ubuntu:24.04 ;;
    suse15) echo opensuse/leap:15.6 ;; suse16) echo opensuse/leap:16.0 ;;
    amazon2) echo amazonlinux:2 ;;   amazon2023) echo amazonlinux:2023 ;;
    *) echo "unknown benchmark $1" >&2; return 1 ;;
  esac
}

arch=$(docker info --format '{{.Architecture}}')
case "$arch" in aarch64|arm64) goarch=arm64 ;; *) goarch=amd64 ;; esac
GOOS=linux GOARCH=$goarch CGO_ENABLED=0 go build -o bin/checkmate-linux ./cmd/checkmate

benches=("$@")
if [ ${#benches[@]} -eq 0 ]; then
  benches=(rhel7 rhel8 rhel9 rhel10 debian11 debian12 debian13 ubuntu20 ubuntu22 ubuntu24 suse15 suse16 amazon2 amazon2023)
fi

for b in "${benches[@]}"; do
  image=$(image_for "$b")
  echo "== $b ($image)"
  docker run --rm -v "$root:/src:ro" -w /src "$image" \
    /src/bin/checkmate-linux run --allow-insecure-policy --format json "cis/$b.yml" \
    > "$out/$b-cis_$b.json" 2>"$out/$b-cis_$b.err" || true
done

python3 test/linux/analyze.py "$out"
