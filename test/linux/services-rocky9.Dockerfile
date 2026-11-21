FROM rockylinux:9
RUN dnf -y -q install epel-release >/dev/null && \
    dnf -y -q install postfix nfs-utils vsftpd bind bind-utils kea dhcp-server dovecot samba \
      openssl procps-ng iproute findutils >/dev/null && dnf clean all >/dev/null
