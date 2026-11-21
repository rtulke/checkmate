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

  - id: PG-002
    name: "Server is PostgreSQL {{ (min_server_version_num / 10000) | int }} or newer"
    tags: [applications, postgresql, updates]
    only_if: command -v pg_isready && pg_isready -q
    run: { use: psql, arg: SHOW server_version_num }
    expect: ">= {{ min_server_version_num }}"

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

  - id: PG-005
    name: PostgreSQL does not listen on all interfaces
    tags: [applications, postgresql, network]
    only_if: command -v pg_isready && pg_isready -q
    run: { use: psql, arg: SHOW listen_addresses }
    expect: "!~ ^(\\*|0\\.0\\.0\\.0)"
```
