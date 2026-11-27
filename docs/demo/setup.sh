#!/bin/sh
# Creates the files the demo policy checks, so the demo looks the same on
# every machine.
d=/tmp/checkmate-demo
mkdir -p "$d"
printf 'Port 22\nPermitRootLogin yes\nCiphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com\n' > "$d/sshd_config"
printf 'sshd\nchronyd\ncrond\n' > "$d/enabled-services"
printf 'root 41\nvar 63\nlog 93\n' > "$d/df"
printf '0.82\n' > "$d/clock-offset"
