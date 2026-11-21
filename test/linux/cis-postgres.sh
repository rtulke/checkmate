#!/usr/bin/env bash
# Runs cis/postgresql.yml against hardened PostgreSQL servers in containers.
# Two violations are planted (a role with CREATEDB, a SECURITY DEFINER
# function); the other failures are components missing from the image.
set -euo pipefail
cd "$(dirname "$0")/../.."

arch=$(docker info -f '{{.Architecture}}' | sed 's/x86_64/amd64/;s/aarch64/arm64/')
mkdir -p test/linux/out-cis
CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o test/linux/out-cis/checkmate-linux ./cmd/checkmate

expected="CIS-PG-3.2-pgaudit
CIS-PG-4.2-admin-roles
CIS-PG-4.3-security-definer
CIS-PG-4.6-set-user
CIS-PG-6.7-fips
CIS-PG-8.2-pgbackrest"

status=0
for version in ${PG_VERSIONS:-13 16 17}; do
  echo "== postgres:$version"
  got=$(docker run --rm -e POSTGRES_PASSWORD=x -e POSTGRES_HOST_AUTH_METHOD=scram-sha-256 \
    -e "POSTGRES_INITDB_ARGS=--auth-local=peer --auth-host=scram-sha-256" \
    -v "$PWD:/src:ro" "postgres:$version" bash -c '
    openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=db -keyout /tmp/server.key -out /tmp/server.crt -days 2 2>/dev/null
    chown postgres /tmp/server.*; chmod 600 /tmp/server.key
    mkdir -p /var/log/pg && chown postgres /var/log/pg
    echo "umask 077" >> /var/lib/postgresql/.profile; chown postgres /var/lib/postgresql/.profile
    (docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tmp/server.crt -c ssl_key_file=/tmp/server.key \
      -c logging_collector=on -c log_directory=/var/log/pg -c log_truncate_on_rotation=on \
      -c log_connections=on -c log_disconnections=on -c log_statement=ddl \
      -c "log_line_prefix=%m [%p]: db=%d,user=%u,client=%h " -c log_replication_commands=on \
      -c archive_mode=on -c "archive_command=test ! -f /tmp/%f" -c log_timezone=UTC >/tmp/pg.log 2>&1 &)
    for i in $(seq 60); do pg_isready -q -h /var/run/postgresql && break; sleep 1; done; sleep 3
    cd / && runuser -u postgres -- psql -Xq \
      -c "CREATE FUNCTION public.f() RETURNS int LANGUAGE sql SECURITY DEFINER AS \$\$SELECT 1\$\$" \
      -c "CREATE ROLE dba CREATEDB"
    /src/test/linux/out-cis/checkmate-linux run /src/cis/postgresql.yml --format json --allow-insecure-policy || true' |
    python3 -c 'import json,sys; r=json.load(sys.stdin); print("\n".join(sorted(x["id"] for x in r["results"] if x["status"] in ("FAIL","ERROR"))))')
  if [ "$got" = "$expected" ]; then
    echo "ok"
  else
    echo "unexpected failures:"; diff <(echo "$expected") <(echo "$got") || true
    status=1
  fi
done
exit $status
