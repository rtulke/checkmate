#!/usr/bin/env bash
# Runs cis/apache.yml against hardened Apache installations (Debian and Rocky
# Linux 9). Remaining failures are components missing from the images
# (ModSecurity, a trusted certificate) or limits of containers (SELinux).
set -euo pipefail
cd "$(dirname "$0")/../.."

arch=$(docker info -f '{{.Architecture}}' | sed 's/x86_64/amd64/;s/aarch64/arm64/')
mkdir -p test/linux/out-cis
CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o test/linux/out-cis/checkmate-linux ./cmd/checkmate
for image in apps-debian apps-rocky9; do
  docker build -q -t "checkmate-test:$image" -f "test/linux/$image.Dockerfile" test/linux >/dev/null 2>&1
done

common="CIS-APACHE-6.6-modsecurity
CIS-APACHE-6.7-owasp-crs
CIS-APACHE-7.2-certificates-valid"

harden_debian='
  a2dismod -q -f status autoindex auth_basic >/dev/null; rm -f /etc/apache2/mods-enabled/alias.conf
  a2enmod -q ssl headers rewrite >/dev/null
  mkdir -p /etc/apache2/tls
  openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=www.example.com -days 2 \
    -keyout /etc/apache2/tls/server.key -out /etc/apache2/tls/server.crt 2>/dev/null
  chmod 600 /etc/apache2/tls/server.key
  sed -i -e "s|/etc/ssl/certs/ssl-cert-snakeoil.pem|/etc/apache2/tls/server.crt|" \
    -e "s|/etc/ssl/private/ssl-cert-snakeoil.key|/etc/apache2/tls/server.key|" /etc/apache2/sites-available/default-ssl.conf
  a2ensite -q default-ssl >/dev/null
  sed -i "s|</VirtualHost>|Redirect permanent / https://www.example.com/\n</VirtualHost>|" /etc/apache2/sites-enabled/000-default.conf
  sed -i -E "s/^([[:space:]]*)Listen ([0-9]+)$/\1Listen 127.0.0.1:\2/" /etc/apache2/ports.conf
  echo "<html>ok</html>" > /var/www/html/index.html
  cp /src/test/linux/fixtures/apache-cis.conf /etc/apache2/conf-enabled/zz-cis.conf
  apache2ctl start'

harden_rocky='
  sed -i -E "s/^(LoadModule (dav|status|autoindex|proxy|lbmethod|userdir|info|auth_basic|auth_digest)[a-z0-9_]*_module)/#\1/" /etc/httpd/conf.modules.d/*.conf
  rm -f /etc/httpd/conf.d/welcome.conf /etc/httpd/conf.d/autoindex.conf /etc/httpd/conf.d/userdir.conf
  rm -rf /usr/share/httpd/noindex
  /usr/libexec/httpd-ssl-gencerts >/dev/null 2>&1
  sed -i -E "/^[[:space:]]*SSL(Protocol|CipherSuite)/d" /etc/httpd/conf.d/ssl.conf
  sed -i -E "s/^Listen ([0-9]+)/Listen 127.0.0.1:\1/" /etc/httpd/conf/httpd.conf /etc/httpd/conf.d/ssl.conf
  sed -i -E "/<Directory \"\/var\/www\/html\">/,/<\/Directory>/ s/^([[:space:]]*)Options .*/\1Options None/" /etc/httpd/conf/httpd.conf
  sed -i "s/^\([[:space:]]*\)missingok/\1missingok\n\1rotate 13/" /etc/logrotate.d/httpd
  cp /src/test/linux/fixtures/apache-cis.conf /etc/httpd/conf.d/zz-cis.conf
  httpd -k start'

status=0
for image in apps-debian apps-rocky9; do
  echo "== $image"
  if [ "$image" = apps-debian ]; then harden=$harden_debian; expected=$common; else
    harden=$harden_rocky
    expected=$(printf '%s\nCIS-APACHE-11.1-selinux-enforcing\nCIS-APACHE-11.2-httpd-confined' "$common")
  fi
  got=$(docker run --rm -v "$PWD:/src:ro" "checkmate-test:$image" bash -c "{ $harden
    } >&2
    sleep 1
    /src/test/linux/out-cis/checkmate-linux run /src/cis/apache.yml --format json --allow-insecure-policy || true" |
    python3 -c 'import json,sys; r=json.load(sys.stdin); print("\n".join(sorted(x["id"] for x in r["results"] if x["status"] in ("FAIL","ERROR"))))')
  expected=$(echo "$expected" | sort)
  if [ "$got" = "$expected" ]; then echo ok; else
    echo "unexpected failures:"; diff <(echo "$expected") <(echo "$got") || true
    status=1
  fi
done
exit $status
