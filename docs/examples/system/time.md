# Time synchronisation

Clock synchronisation with chrony or systemd-timesyncd, the allowed clock offset and the configured time zone.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/system/time.yml`](https://github.com/rtulke/checkmate/blob/main/examples/system/time.yml)
- :material-format-list-checks: **Checks**  
  5 from 5 definitions
- :material-monitor: **Platforms**  
  linux, macos

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/system/time.yml

# Run the checks
checkmate run examples/system/time.yml

# Override a variable from the command line
checkmate run examples/system/time.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `TIME-001` | The clock is synchronised | <span class="sev sev-high">high</span> | system, time |
| `TIME-002` | chrony reports a normal leap status | <span class="sev sev-medium">medium</span> | system, time |
| `TIME-003` | Clock offset is below 0.5 seconds | <span class="sev sev-medium">medium</span> | system, time |
| `TIME-004` | At least two time sources are reachable | <span class="sev sev-low">low</span> | system, time |
| `TIME-005` | Time zone is UTC | <span class="sev sev-low">low</span> | system, time |

## Policy

```yaml title="examples/system/time.yml" linenums="1"
name: Time synchronisation
version: 1.0.0
description: >
  Clock synchronisation with chrony or systemd-timesyncd, the allowed clock
  offset and the configured time zone.

vars:
  max_offset_seconds: 0.5
  expected_timezone: UTC

checks:
  - id: TIME-001
    name: The clock is synchronised
    tags: [system, time]
    severity: high
    run:
      linux: |
        timedatectl status | awk -F': ' '/(NTP|System clock) synchronized/ {print $2}'
      macos: sntp -t 3 time.apple.com >/dev/null 2>&1 && echo yes || echo no
    expect: "== yes"
    rationale: A drifting clock breaks Kerberos and certificate validation and makes log timestamps useless for correlation.
    remediation: Enable an NTP client (`timedatectl set-ntp true` on Linux) and check that the time servers are reachable.

  - id: TIME-002
    name: chrony reports a normal leap status
    tags: [system, time]
    only_if: command -v chronyc
    # chronyc exits 1 if chronyd is not running: that is a failure, not an error.
    run: |
      chronyc -n tracking 2>/dev/null | awk -F': ' '/^Leap status/ {print $2}'
    allow_rc: [0, 1]
    expect: "== Normal"
    rationale: A leap status other than Normal usually means that chronyd is not running or not synchronised.
    remediation: Start chronyd with `systemctl enable --now chronyd` and check its sources with `chronyc sources`.

  - id: TIME-003
    name: "Clock offset is below {{ max_offset_seconds }} seconds"
    tags: [system, time]
    only_if: command -v chronyc
    # "System time : 0.000012 seconds fast of NTP time"
    run: |
      chronyc -n tracking 2>/dev/null | awk '/^System time/ {print $4}'
    allow_rc: [0, 1]
    expect: ["!empty", "< {{ max_offset_seconds }}"]
    rationale: A large offset breaks time-based authentication and puts log entries of different hosts in the wrong order.
    remediation: Check the sources with `chronyc sources` and step the clock with `chronyc makestep`.

  - id: TIME-004
    name: At least two time sources are reachable
    tags: [system, time]
    severity: low
    only_if: command -v chronyc
    # Selected (*) and combined (+) sources count as usable.
    run: |
      chronyc -n sources 2>/dev/null | grep -cE '^\^[*+]'
    allow_rc: [0, 1]
    expect: ">= 2"
    rationale: With a single source a failed or wrong time server goes unnoticed.
    remediation: Add further `server` or `pool` lines to the chrony configuration and restart chronyd.

  - id: TIME-005
    name: "Time zone is {{ expected_timezone }}"
    tags: [system, time]
    severity: low
    run:
      linux: |
        timedatectl status | awk -F': ' '/Time zone/ {print $2}' | cut -d' ' -f1
      macos: readlink /etc/localtime | sed 's#.*/zoneinfo/##'
    expect: "== {{ expected_timezone }}"
    rationale: A uniform time zone keeps log timestamps comparable across hosts.
    remediation: "Set the time zone, on Linux with `timedatectl set-timezone {{ expected_timezone }}`."
```
