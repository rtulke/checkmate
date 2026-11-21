FROM debian:12
ENV DEBIAN_FRONTEND=noninteractive
RUN echo "slapd slapd/no_configuration boolean false" | debconf-set-selections && \
    echo "slapd slapd/domain string example.net" | debconf-set-selections && \
    echo "slapd shared/organization string Example" | debconf-set-selections && \
    echo "slapd slapd/password1 password secret" | debconf-set-selections && \
    echo "slapd slapd/password2 password secret" | debconf-set-selections && \
    echo "postfix postfix/main_mailer_type select Internet Site" | debconf-set-selections && \
    echo "postfix postfix/mailname string mail.example.net" | debconf-set-selections && \
    apt-get update -qq && apt-get install -y -qq --no-install-recommends \
      postfix nfs-kernel-server vsftpd bind9 bind9-utils kea-dhcp4-server kea-ctrl-agent isc-dhcp-server \
      dovecot-imapd dovecot-pop3d samba slapd ldap-utils openssl procps iproute2 ca-certificates >/dev/null && \
    rm -rf /var/lib/apt/lists/*
