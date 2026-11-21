#!/usr/bin/env bash
# Runs every example policy and the escape test policy inside Linux
# containers and reports results that indicate broken commands (shell,
# awk, sed, grep or regex syntax errors) rather than findings.
#
#   test/linux/run.sh [image ...]      default: all images
set -euo pipefail

cd "$(dirname "$0")/../.."
root=$(pwd)
out="$root/test/linux/out"
mkdir -p "$out" bin

arch=$(docker info --format '{{.Architecture}}')
case "$arch" in
  aarch64|arm64) goarch=arm64 ;;
  *) goarch=amd64 ;;
esac
GOOS=linux GOARCH=$goarch CGO_ENABLED=0 go build -o bin/checkmate-linux ./cmd/checkmate

images=("$@")
if [ ${#images[@]} -eq 0 ]; then
  images=(rocky9 rocky8 debian12 ubuntu24 leap15 alpine apps-debian apps-rocky9)
fi

for image in "${images[@]}"; do
  tag="checkmate-test:$image"
  docker build -q -t "$tag" -f "test/linux/$image.Dockerfile" test/linux >/dev/null
  echo "== $image"
  policies=$(cd "$root" && find examples -name '*.yml' -not -path '*/vars/*' | sort)
  policies="$policies internal/engine/testdata/escapes.yml"
  for policy in $policies; do
    name=$(echo "$policy" | tr '/' '_' | sed 's/\.yml$//')
    docker run --rm -v "$root:/src:ro" -w /src "$tag" \
      /src/bin/checkmate-linux run --allow-insecure-policy --format json "$policy" \
      > "$out/$image-$name.json" 2>"$out/$image-$name.err" || true
  done
done

python3 test/linux/analyze.py "$out"
