# Redis

Redis exposure and authentication: bind address, protected mode, passwords or ACLs, dangerous commands and file permissions. The settings are read from the running server with CONFIG GET when possible.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/applications/redis.yml`](https://github.com/rtulke/checkmate/blob/main/examples/applications/redis.yml)
- :material-format-list-checks: **Checks**  
  7 from 7 definitions
- :material-monitor: **Platforms**  
  any (POSIX shell)

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/applications/redis.yml

# Run the checks
checkmate run examples/applications/redis.yml

# Override a variable from the command line
checkmate run examples/applications/redis.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `REDIS-001` | Redis answers locally | <span class="sev sev-high">high</span> | applications, redis |
| `REDIS-002` | Redis requires authentication | <span class="sev sev-critical">critical</span> | applications, redis, authentication |
| `REDIS-003` | Redis only listens on loopback or a private address | <span class="sev sev-high">high</span> | applications, redis, network |
| `REDIS-004` | Protected mode is on | <span class="sev sev-medium">medium</span> | applications, redis |
| `REDIS-005` | Dangerous commands are disabled or renamed | <span class="sev sev-high">high</span> | applications, redis |
| `REDIS-006` | The configuration file is not readable by others | <span class="sev sev-high">high</span> | applications, redis, permissions |
| `REDIS-007` | Redis does not run as root | <span class="sev sev-high">high</span> | applications, redis |

## Policy

```yaml title="examples/applications/redis.yml" linenums="1"
name: Redis
version: 1.0.0
description: >
  Redis exposure and authentication: bind address, protected mode,
  passwords or ACLs, dangerous commands and file permissions. The settings
  are read from the running server with CONFIG GET when possible.

vars:
  redis_port: 6379

snippets:
  # Prints the value of a configuration parameter of the running server.
  redis_config: redis-cli -p {{ redis_port }} --no-auth-warning config get {{ arg }} | tail -n 1

checks:
  - id: REDIS-001
    name: Redis answers locally
    tags: [applications, redis]
    severity: high
    only_if: command -v redis-cli
    run: redis-cli -p {{ redis_port }} ping
    expect: "in [PONG, NOAUTH Authentication required.]"

  - id: REDIS-002
    name: Redis requires authentication
    tags: [applications, redis, authentication]
    severity: critical
    only_if: command -v redis-cli
    # An unauthenticated PING must be rejected.
    run: redis-cli -p {{ redis_port }} --no-auth-warning ping
    expect: "~ NOAUTH"

  - id: REDIS-003
    name: Redis only listens on loopback or a private address
    tags: [applications, redis, network]
    severity: high
    only_if: command -v ss
    run: ss -Hlnt 'sport = :{{ redis_port }}' | awk '{print $4}'
    expect: { each: "~ ^(127\\.|\\[::1\\]|10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.)" }

  - id: REDIS-004
    name: Protected mode is on
    tags: [applications, redis]
    only_if: command -v redis-cli && redis-cli -p {{ redis_port }} ping | grep PONG >/dev/null
    run: { use: redis_config, arg: protected-mode }
    expect: "== yes"

  - id: REDIS-005
    name: Dangerous commands are disabled or renamed
    tags: [applications, redis]
    severity: high
    only_if: test -r /etc/redis/redis.conf -o -r /etc/redis.conf
    run: cat /etc/redis/redis.conf /etc/redis.conf 2>/dev/null
    expect:
      all:
        - { some: "~ ^rename-command[[:space:]]+FLUSHALL" }
        - { some: "~ ^rename-command[[:space:]]+CONFIG" }
        - { some: "~ ^rename-command[[:space:]]+DEBUG" }

  - id: REDIS-006
    name: The configuration file is not readable by others
    tags: [applications, redis, permissions]
    severity: high
    run: find /etc/redis/redis.conf /etc/redis.conf -perm /o+r 2>/dev/null
    allow_rc: [0, 1]
    expect: empty

  - id: REDIS-007
    name: Redis does not run as root
    tags: [applications, redis]
    severity: high
    only_if: pgrep -x redis-server >/dev/null
    run: ps -o user= -p "$(pgrep -x redis-server | sed -n 1p)"
    expect: "!= root"
```
