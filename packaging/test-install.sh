#!/bin/sh
# Installs a checkmate package the way an end user would and smoke-tests it.
# Runs inside the target distribution's container:
#
#   packaging/test-install.sh <package file> <policy below /usr/share/checkmate>
#
# A real apt-get/dnf/zypper install, so the package metadata must be
# acceptable to that distribution's package manager.
set -eu
pkg=$1
policy=$2

case "$pkg" in
  *.deb)
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$pkg" >/dev/null
    files=$(dpkg -L checkmate)
    ;;
  *.rpm)
    if command -v zypper >/dev/null; then
      zypper --non-interactive install --allow-unsigned-rpm "$pkg" >/dev/null
    else
      dnf install -y -q "$pkg" >/dev/null
    fi
    files=$(rpm -ql checkmate)
    ;;
esac

checkmate version
# Checked via the package manifest: slim images exclude man pages and docs
# from being written to disk, the package still has to ship them.
for f in /usr/bin/checkmate /usr/share/man/man1/checkmate.1.gz /usr/share/man/man5/checkmate-policy.5.gz \
         /usr/share/checkmate/cis/NOTICE /usr/share/checkmate/examples/attack/linux.yml; do
  echo "$files" | grep -qx "$f" || { echo "missing in package: $f"; exit 1; }
done
if echo "$files" | grep -q '\.go$'; then echo "Go test files in package"; exit 1; fi

checkmate validate "/usr/share/checkmate/$policy"
# Exit code 1 (findings) is expected in a bare container; 2 would mean the
# policy could not be used.
rc=0
checkmate run "/usr/share/checkmate/$policy" -q --no-color >/tmp/report.txt 2>&1 || rc=$?
tail -n 3 /tmp/report.txt
[ "$rc" -le 1 ] || { echo "checkmate run exited with $rc"; exit 1; }
echo "OK: $pkg"
