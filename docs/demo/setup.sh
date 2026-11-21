#!/bin/sh
# Creates the files the demo policy checks, so the demo looks the same on
# every machine.
d=/tmp/checkmate-demo
mkdir -p "$d"
printf 'Port 22\nPermitRootLogin yes\nCiphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com\n' > "$d/sshd_config"
printf 'sshd\nchronyd\ncrond\n' > "$d/enabled-services"
printf '/ 41%%\n/var 63%%\n/var/log 93%%\n' | tr -d '%' > "$d/df"
printf '0.82\n' > "$d/clock-offset"
