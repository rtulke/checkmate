#!/usr/bin/env bash
# Runs examples/services/*.yml against real installations of Postfix, NFS,
# vsftpd, BIND, Kea, ISC dhcpd, Dovecot, Samba and OpenLDAP on Debian 12:
#   1. default configuration: no check may end in an error,
#   2. hardened configuration: every check passes (or is skipped),
#   3. dangerous NFS exports: the matching checks fail.
set -euo pipefail
cd "$(dirname "$0")/../.."

arch=$(docker info -f '{{.Architecture}}' | sed 's/x86_64/amd64/;s/aarch64/arm64/')
mkdir -p test/linux/out-cis
CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o test/linux/out-cis/checkmate-linux ./cmd/checkmate
docker build -q -t checkmate-test:services-debian -f test/linux/services-debian.Dockerfile test/linux >/dev/null 2>&1

docker run --rm -i -v "$PWD:/src:ro" checkmate-test:services-debian bash -s <<'SCRIPT'
set -u
cm=/src/test/linux/out-cis/checkmate-linux
status=0
start() {
  slapd -h "ldapi:/// ldap:///" -u openldap -g openldap >/dev/null 2>&1
  named -u bind >/dev/null 2>&1
  postfix start >/dev/null 2>&1
  sleep 2
}
results() {  # prints "STATUS ID" for every non-passing check of all policies
  for p in /src/examples/services/*.yml; do
    $cm run "$p" --allow-insecure-policy --format json 2>/dev/null |
      python3 -c 'import json,sys; [print(r["status"], r["id"]) for r in json.load(sys.stdin)["results"] if r["status"] not in ("PASS","SKIP")]' 2>/dev/null || true
  done
}

start
echo "== 1. default configuration"
errors=$(results | grep '^ERROR' || true)
if [ -n "$errors" ]; then echo "$errors"; status=1; else echo "ok: no errors ($(results | grep -c '^FAIL') findings)"; fi

echo "== 2. hardened configuration"
postconf -e "inet_interfaces = loopback-only" 'smtpd_banner = $myhostname ESMTP' "disable_vrfy_command = yes" \
  "smtpd_helo_required = yes" "smtpd_tls_mandatory_protocols = >=TLSv1.2" "smtp_tls_mandatory_protocols = >=TLSv1.2" \
  "smtp_tls_security_level = may"
postfix reload >/dev/null 2>&1
mkdir -p /srv/export && echo "/srv/export 192.0.2.0/24(rw,sync,root_squash,sec=krb5p)" > /etc/exports
nfsconf --set nfsd vers2 n && nfsconf --set nfsd vers3 n
cat >> /etc/vsftpd.conf <<'CONF'
ssl_enable=YES
ssl_tlsv1=NO
chroot_local_user=YES
ftpd_banner=FTP service
CONF
sed -i 's|^options {|options {\n\tversion "none";\n\tallow-transfer { none; };|' /etc/bind/named.conf.options
echo "ssl = required" > /etc/dovecot/conf.d/99-hardening.conf
sed -i '/^[[:space:]]*map to guest/d' /etc/samba/smb.conf
sed -i 's|^\[global\]|[global]\n   server min protocol = SMB3\n   server signing = mandatory\n   server smb encrypt = required\n   map to guest = Never\n   restrict anonymous = 2|' /etc/samba/smb.conf
openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=ldap.example.net -days 2 \
  -keyout /etc/ldap/ldap.key -out /etc/ldap/ldap.crt 2>/dev/null
chown openldap /etc/ldap/ldap.key && chmod 600 /etc/ldap/ldap.key
ldapmodify -Q -Y EXTERNAL -H ldapi:/// >/dev/null <<'LDIF'
dn: cn=config
changetype: modify
replace: olcTLSCertificateFile
olcTLSCertificateFile: /etc/ldap/ldap.crt
-
replace: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: /etc/ldap/ldap.key
-
replace: olcTLSProtocolMin
olcTLSProtocolMin: 3.3
-
replace: olcDisallows
olcDisallows: bind_anon
-
replace: olcLocalSSF
olcLocalSSF: 128
-
replace: olcSecurity
olcSecurity: ssf=128
-
replace: olcPasswordHash
olcPasswordHash: {SSHA}
LDIF
left=$(results)
if [ -n "$left" ]; then echo "$left"; status=1; else echo "ok: every check passes"; fi

echo "== 3. dangerous NFS exports"
echo "/srv/export *(rw,no_root_squash,insecure)" > /etc/exports
for id in NFS-NO-WORLD-EXPORT NFS-NO-NO-ROOT-SQUASH NFS-NO-INSECURE; do
  if results | grep -qx "FAIL $id"; then echo "found $id"; else echo "NOT FOUND $id"; status=1; fi
done
exit $status
SCRIPT
