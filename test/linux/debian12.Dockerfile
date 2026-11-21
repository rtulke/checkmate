FROM debian:12
# mawk stays the default awk, as on real Debian systems.
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      procps iproute2 openssl openssh-server sudo cron chrony auditd lsof curl jq ca-certificates \
      unattended-upgrades apparmor libpam-pwquality debsums netcat-openbsd && rm -rf /var/lib/apt/lists/* && ssh-keygen -A && mkdir -p /run/sshd
