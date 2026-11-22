#!/usr/bin/env bash
# Checks the export formats against the tools that consume them:
#   - XCCDF and ARF are validated with OpenSCAP and rendered by it,
#   - the Prometheus metrics are linted with promtool,
#   - syslog messages arrive in rsyslog,
#   - merged exports and diffs work on reports of two distributions.
set -euo pipefail
cd "$(dirname "$0")/../.."

arch=$(docker info -f '{{.Architecture}}' | sed 's/x86_64/amd64/;s/aarch64/arm64/')
out=test/linux/out-cis/exports
rm -rf "$out" && mkdir -p "$out"
CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o test/linux/out-cis/checkmate-linux ./cmd/checkmate
status=0
fail() { echo "FAIL: $*"; status=1; }

echo "== reports of two hosts, exported to every format and to syslog"
for img in debian:12-slim rockylinux:9-minimal; do
  name=${img%%:*}
  docker run --rm -h "$name-host" -v "$PWD:/src:ro" -v "$PWD/$out:/out" "$img" sh -c "
    if command -v apt-get >/dev/null; then apt-get -qq update >/dev/null && apt-get -qq install -y rsyslog >/dev/null 2>&1;
    else microdnf -y install rsyslog >/dev/null 2>&1; fi
    # A minimal configuration: RHEL's default reads from journald, which a
    # container does not run, instead of opening /dev/log.
    printf 'module(load=\"imuxsock\")\n*.* /var/log/messages\n' > /tmp/rsyslog.conf
    rsyslogd -f /tmp/rsyslog.conf 2>/dev/null; sleep 1
    /src/test/linux/out-cis/checkmate-linux run /src/examples/platforms/linux.yml --allow-insecure-policy -q \
      --export json,html,pdf,csv,jsonl,junit,xccdf,arf,prom,syslog -o /out/$name >/dev/null 2>/out/$name.stderr
    sleep 1
    grep -h 'checkmate\[' /var/log/messages 2>/dev/null > /out/$name.syslog || true
    # Reports are created with mode 0640 as root; let the runner read them.
    chown -R $(id -u):$(id -g) /out
  " || true
  for ext in json html pdf csv jsonl junit.xml xccdf.xml arf.xml prom; do
    [ -s "$out/$name.$ext" ] || fail "$name.$ext missing: $(cat "$out/$name.stderr")"
  done
  events=$(wc -l < "$out/$name.syslog")
  results=$(python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); print(sum(1 for x in r["results"] if x["status"] not in ("SKIP","N/A"))+1)' "$out/$name.json")
  [ "$events" -eq "$results" ] && echo "ok: $name: $events syslog messages" || fail "$name: $events syslog messages, want $results"
done

echo "== merged export of both reports"
cm=test/linux/out-cis/checkmate-linux
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/src" -w /src debian:12-slim \
  "$cm" export -f html,pdf,xccdf,arf,csv,prom,junit -o "$out/fleet" "$out/debian.json" "$out/rockylinux.json" || fail "merged export"
grep -q 'debian-host' "$out/fleet.html" && grep -q 'rockylinux-host' "$out/fleet.html" && echo "ok: merged HTML has both hosts" || fail "merged HTML"

echo "== diff of the two reports"
rc=0
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/src" -w /src debian:12-slim "$cm" diff "$out/debian.json" "$out/rockylinux.json" > "$out/diff.txt" || rc=$?
[ "$rc" -le 1 ] && grep -q '^score ' "$out/diff.txt" && echo "ok: diff (exit $rc)" || fail "diff exit $rc"

echo "== OpenSCAP validates XCCDF and ARF"
docker run --rm -v "$PWD/$out:/x:ro" fedora:43 sh -c '
  dnf -q -y install openscap-scanner >/dev/null 2>&1
  cd /x; rc=0
  for f in debian.xccdf.xml fleet.xccdf.xml; do oscap xccdf validate "$f" >/dev/null 2>&1 || { echo "invalid $f"; oscap xccdf validate "$f"; rc=1; }; done
  for f in debian.arf.xml fleet.arf.xml; do oscap ds rds-validate "$f" || { echo "invalid $f"; rc=1; }; done
  oscap xccdf generate report fleet.arf.xml > /tmp/oscap-report.html || rc=1
  exit $rc' && echo "ok: XCCDF/ARF valid, OpenSCAP report rendered" || fail "OpenSCAP"

echo "== promtool lints the metrics"
for f in debian.prom fleet.prom; do
  docker run -i --rm --entrypoint promtool prom/prometheus:v3.5.0 check metrics < "$out/$f" && echo "ok: $f" || fail "promtool $f"
done

exit $status
