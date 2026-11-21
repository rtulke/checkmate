# MongoDB

MongoDB authentication, network exposure, transport encryption, server-side scripting, auditing and the service account, read from the configuration file mongod.conf (YAML).

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/applications/mongodb.yml`](https://github.com/rtulke/checkmate/blob/main/examples/applications/mongodb.yml)
- :material-format-list-checks: **Checks**  
  10 from 10 definitions
- :material-monitor: **Platforms**  
  any (POSIX shell)

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/applications/mongodb.yml

# Run the checks
checkmate run examples/applications/mongodb.yml

# Override a variable from the command line
checkmate run examples/applications/mongodb.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `MONGO-AUTH` | Authorization is enabled | <span class="sev sev-critical">critical</span> | applications, mongodb |
| `MONGO-BIND` | mongod does not listen on all interfaces | <span class="sev sev-high">high</span> | applications, mongodb, network |
| `MONGO-NO-BINDALL` | bindIpAll is not set | <span class="sev sev-high">high</span> | applications, mongodb, network |
| `MONGO-TLS` | Connections require TLS | <span class="sev sev-high">high</span> | applications, mongodb, tls |
| `MONGO-JAVASCRIPT` | Server-side JavaScript is disabled | <span class="sev sev-medium">medium</span> | applications, mongodb |
| `MONGO-LOG-APPEND` | Log files are appended, not overwritten | <span class="sev sev-low">low</span> | applications, mongodb, logging |
| `MONGO-AUDIT` | Auditing is configured (Enterprise and Percona) | <span class="sev sev-low">low</span> | applications, mongodb, logging |
| `MONGO-USER` | mongod does not run as root | <span class="sev sev-high">high</span> | applications, mongodb, accounts |
| `MONGO-CONF-PERMS` | mongod.conf is not readable by others | <span class="sev sev-medium">medium</span> | applications, mongodb, permissions |
| `MONGO-DATA-PERMS` | The data directory is only accessible by the mongod user | <span class="sev sev-high">high</span> | applications, mongodb, permissions |

## Policy

```yaml title="examples/applications/mongodb.yml" linenums="1"
name: MongoDB
version: 1.0.0
description: >
  MongoDB authentication, network exposure, transport encryption,
  server-side scripting, auditing and the service account, read from the
  configuration file mongod.conf (YAML).

vars:
  mongod_conf: /etc/mongod.conf

snippets:
  # Prints the value of a dotted mongod.conf key, e.g. security.authorization.
  mongo_conf: |
    awk -v want='{{ arg }}' '
      /^[[:space:]]*#/ || /^[[:space:]]*$/ {next}
      {
        match($0, /^[[:space:]]*/); depth = RLENGTH / 2
        line = $0; sub(/^[[:space:]]*/, "", line)
        key = line; sub(/:.*/, "", key)
        value = line; sub(/^[^:]*:[[:space:]]*/, "", value); sub(/[[:space:]]*#.*/, "", value)
        path[depth] = key
        full = path[0]; for (i = 1; i <= depth; i++) full = full "." path[i]
        if (full == want) {gsub(/"/, "", value); print value}
      }' {{ mongod_conf }}

defaults:
  when: facts.os == "linux"

checks:
  - id: MONGO-AUTH
    name: Authorization is enabled
    tags: [applications, mongodb]
    severity: critical
    only_if: test -f {{ mongod_conf }}
    run: { use: mongo_conf, arg: security.authorization }
    expect: "== enabled"

  - id: MONGO-BIND
    name: mongod does not listen on all interfaces
    tags: [applications, mongodb, network]
    severity: high
    only_if: test -f {{ mongod_conf }}
    run: { use: mongo_conf, arg: net.bindIp }
    expect: ["!empty", "!~ (0\\.0\\.0\\.0|::,|\\*)", "!~ ^::$"]

  - id: MONGO-NO-BINDALL
    name: bindIpAll is not set
    tags: [applications, mongodb, network]
    severity: high
    only_if: test -f {{ mongod_conf }}
    run: { use: mongo_conf, arg: net.bindIpAll }
    expect: "in ['', 'false']"

  - id: MONGO-TLS
    name: Connections require TLS
    tags: [applications, mongodb, tls]
    severity: high
    only_if: test -f {{ mongod_conf }}
    run: { use: mongo_conf, arg: net.tls.mode }
    expect: "== requireTLS"

  - id: MONGO-JAVASCRIPT
    name: Server-side JavaScript is disabled
    tags: [applications, mongodb]
    only_if: test -f {{ mongod_conf }}
    run: { use: mongo_conf, arg: security.javascriptEnabled }
    expect: "== false"

  - id: MONGO-LOG-APPEND
    name: Log files are appended, not overwritten
    tags: [applications, mongodb, logging]
    severity: low
    only_if: test -f {{ mongod_conf }}
    run: { use: mongo_conf, arg: systemLog.logAppend }
    expect: "== true"

  - id: MONGO-AUDIT
    name: Auditing is configured (Enterprise and Percona)
    tags: [applications, mongodb, logging]
    severity: low
    only_if: test -f {{ mongod_conf }}
    run: { use: mongo_conf, arg: auditLog.destination }
    expect: "!empty"

  - id: MONGO-USER
    name: mongod does not run as root
    tags: [applications, mongodb, accounts]
    severity: high
    only_if: pgrep -x mongod >/dev/null
    run: ps -o user= -p "$(pgrep -x mongod | sed -n 1p)"
    expect: "!= root"

  - id: MONGO-CONF-PERMS
    name: mongod.conf is not readable by others
    tags: [applications, mongodb, permissions]
    only_if: test -f {{ mongod_conf }}
    run: find {{ mongod_conf }} -perm /007
    expect: empty

  - id: MONGO-DATA-PERMS
    name: The data directory is only accessible by the mongod user
    tags: [applications, mongodb, permissions]
    severity: high
    only_if: test -f {{ mongod_conf }}
    run: |
      dir=$(awk '$1 == "dbPath:" {print $2}' {{ mongod_conf }})
      [ -n "$dir" ] && [ -d "$dir" ] && find "$dir" -maxdepth 0 -perm /077
    allow_rc: [0, 1]
    expect: empty
```
