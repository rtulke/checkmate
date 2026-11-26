# PostgreSQL

Server availability and security settings, queried with SQL through a snippet. checkmate runs as root and switches to the postgres user.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/applications/postgresql.yml`](https://github.com/rtulke/checkmate/blob/main/examples/applications/postgresql.yml)
- :material-format-list-checks: **Checks**  
  9 from 6 definitions, 1 with loops
- :material-monitor: **Platforms**  
  any (POSIX shell)

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/applications/postgresql.yml

# Run the checks
checkmate run examples/applications/postgresql.yml

# Override a variable from the command line
checkmate run examples/applications/postgresql.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `PG-001` | PostgreSQL accepts connections | <span class="sev sev-critical">critical</span> | applications, postgresql |
| `PG-002` | Server is PostgreSQL 14 or newer | <span class="sev sev-medium">medium</span> | applications, postgresql, updates |
| `PG-SET-ssl` | ssl is on | <span class="sev sev-high">high</span> | applications, postgresql |
| `PG-SET-password_encryption` | password_encryption is scram-sha-256 | <span class="sev sev-high">high</span> | applications, postgresql |
| `PG-SET-log_connections` | log_connections is on | <span class="sev sev-high">high</span> | applications, postgresql |
| `PG-SET-log_disconnections` | log_disconnections is on | <span class="sev sev-high">high</span> | applications, postgresql |
| `PG-003` | Only approved roles are superusers | <span class="sev sev-critical">critical</span> | applications, postgresql |
| `PG-004` | pg_hba.conf does not use trust authentication | <span class="sev sev-critical">critical</span> | applications, postgresql |
| `PG-005` | PostgreSQL does not listen on all interfaces | <span class="sev sev-medium">medium</span> | applications, postgresql, network |

## Policy

```yaml title="examples/applications/postgresql.yml" linenums="1"
name: PostgreSQL
version: 1.0.0
description: >
  Server availability and security settings, queried with SQL through a
  snippet. checkmate runs as root and switches to the postgres user.

vars:
  min_server_version_num: 140000
  allowed_superusers: [postgres]

snippets:
  # Runs the SQL in {{ arg }} and prints the bare result.
  psql: sudo -u postgres psql -X -A -t -c "{{ arg }}"

checks:
  - id: PG-001
    name: PostgreSQL accepts connections
    tags: [applications, postgresql]
    severity: critical
    only_if: command -v pg_isready
    run: pg_isready -q
    expect: true
    rationale: Applications fail when the database does not accept connections, and the other checks of this policy need a running server.
    remediation: Start the PostgreSQL service and read the server log if it does not come up.

  - id: PG-002
    name: "Server is PostgreSQL {{ (min_server_version_num / 10000) | int }} or newer"
    tags: [applications, postgresql, updates]
    only_if: command -v pg_isready && pg_isready -q
    run: { use: psql, arg: SHOW server_version_num }
    expect: ">= {{ min_server_version_num }}"
    rationale: Major versions that have reached end of life get no security fixes.
    remediation: Upgrade the cluster to a supported major version with pg_upgrade or dump and restore.

  - id: "PG-SET-{{ item.key }}"
    name: "{{ item.key }} is {{ item.value }}"
    tags: [applications, postgresql]
    severity: high
    only_if: command -v pg_isready && pg_isready -q
    loop:
      ssl: "on"
      password_encryption: scram-sha-256
      log_connections: "on"
      log_disconnections: "on"
    run: { use: psql, arg: "SHOW {{ item.key }}" }
    expect: "== {{ item.value }}"
    rationale: "Another value of {{ item.key }} allows clear-text connections, weak password hashes or sessions that leave no log entry."
    remediation: "Set {{ item.key }} = {{ item.value }} in postgresql.conf and reload the server."

  - id: PG-003
    name: Only approved roles are superusers
    tags: [applications, postgresql]
    severity: critical
    only_if: command -v pg_isready && pg_isready -q
    run: |
      sudo -u postgres psql -X -A -t -c "SELECT rolname FROM pg_roles WHERE rolsuper" |
        grep -vxF {% for r in allowed_superusers %}-e {{ r }} {% endfor %}
    allow_rc: [0, 1]
    expect: empty
    rationale: A superuser bypasses all permission checks and can run operating system commands as the server account.
    remediation: Run `ALTER ROLE <role> NOSUPERUSER` for the listed roles or add them to allowed_superusers.

  - id: PG-004
    name: pg_hba.conf does not use trust authentication
    tags: [applications, postgresql]
    severity: critical
    only_if: command -v pg_isready && pg_isready -q
    run: |
      hba=$(sudo -u postgres psql -X -A -t -c "SHOW hba_file")
      grep -E '^[[:space:]]*(local|host)' "$hba" | awk '$NF == "trust" {print}'
    allow_rc: [0, 1]
    expect: empty
    rationale: trust lets everyone who matches the line connect as any database user without a password.
    remediation: Replace trust with scram-sha-256 or peer in pg_hba.conf and reload the server.

  - id: PG-005
    name: PostgreSQL does not listen on all interfaces
    tags: [applications, postgresql, network]
    only_if: command -v pg_isready && pg_isready -q
    run: { use: psql, arg: SHOW listen_addresses }
    expect: "!~ ^(\\*|0\\.0\\.0\\.0)"
    rationale: A database that listens on all interfaces is reachable from every network the host is connected to.
    remediation: Set listen_addresses in postgresql.conf to localhost or the addresses that clients use and restart the server.
```
