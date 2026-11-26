# Inventory

An inventory lists the hosts a policy is run against over SSH:

```bash
checkmate run baseline.yml --inventory hosts.yml
checkmate run baseline.yml -i hosts.yml --limit web --export html,pdf -o reports/
```

```yaml
defaults:                         # for every host, optional
  user: audit
  become: true                    # run commands through sudo -n
  vars:
    ntp_server: time.example.net

groups:
  web:
    vars: { role: web }
    hosts:
      - web01.example.net
      - web02.example.net
      - name: web03               # a host with its own settings
        address: 10.0.0.13
        port: 2222
        vars: { role: web-canary }
  db:
    become: false
    hosts: [db01.example.net]

hosts:                            # hosts outside of any group
  - backup01.example.net
```

Every host is checked the way [`--host`](../guides/remote.md#a-whole-policy-on-another-host) checks one: nothing is installed there, the facts are those of the host, and the same policy file is used for all of them.

## Keys

| Key | Where | Description |
|---|---|---|
| `defaults` | top level | Settings and variables for every host. |
| `groups` | top level | Mapping of group names to groups. `all` is reserved. |
| `hosts` | top level, group | List of hosts: a name, or a mapping with `name` and settings. |
| `name` | host | Name of the host in reports, `--limit` and `inventory_hostname`. Required. |
| `address` | host | Where to connect, if not the name: an IP address or another DNS name. |
| `user` | defaults, group, host | Remote user. Without it, ssh decides (`~/.ssh/config`, the local user). |
| `port` | defaults, group, host | SSH port. Without it, ssh decides. |
| `become` | defaults, group, host | `true` runs every command through `sudo -n`. |
| `vars` | defaults, group, host | Variables for the policy. |

Unknown keys are rejected, so a typo does not silently drop a setting.

## What wins

Settings and variables go from general to specific; the later one wins:

1. `defaults`
2. the groups of the host, in the order they appear in the file
3. the host itself

A host may be listed in several groups and gets the settings of all of them. For the variables of a run, the order is:

1. `vars` and `vars_files` of the policy
2. the inventory, as above
3. `-e key=value` on the command line

Two more variables are set for every host:

| Variable | Content |
|---|---|
| `inventory_hostname` | The name of the host in the inventory. |
| `group_names` | The list of its groups. |

```yaml
- id: NGINX-RUNNING
  when: '"web" in group_names'
  run: systemctl is-active nginx
  expect: active
```

## Selecting hosts

`--limit` takes a comma-separated list of group names and host names. Host names may contain `*` and `?`:

```bash
checkmate run baseline.yml -i hosts.yml --limit web
checkmate run baseline.yml -i hosts.yml --limit 'db,web0?.example.net'
```

A pattern that matches nothing is an error.

## Parallel runs

`--forks N` checks N hosts at the same time (default 5). On each host, up to 8 commands run in parallel, see `--jobs`. One line per finished host is written to stderr.

## Hosts that cannot be checked

A host that does not answer, refuses the key, or does not let `sudo -n` through has no results. Nothing is known about it, so it is neither compliant nor non-compliant:

```text
HOST                  SCORE   PASS   FAIL   WARN  ERROR  WAIVED  RESULT
web01.example.net    100.0%     42      0      0      0       0  compliant
db01.example.net      92.5%     39      2      1      0       0  not compliant
web02.example.net         -      -      -      -      -       -  unreachable: ssh: connect to host ...
```

It does not count in the totals and the score, and the run gets an exit code of its own:

| Code | Meaning |
|---|---|
| `0` | Every host was checked and is compliant. |
| `1` | At least one host is not compliant. |
| `3` | No host is non-compliant, but at least one could not be checked. |
| `2` | Usage error, invalid policy or inventory. |

Every export format says so in its own way and none of them invents a result:

| Format | A host that could not be checked |
|---|---|
| text | A line in the overview with the reason instead of numbers. |
| `json` | A report with `error`, no results, and `"unreachable": true` if it did not answer. |
| `html`, `pdf` | A row in the host table with the reason; not a column of the check table, not part of totals and score. |
| `csv` | One row with the status `UNREACHABLE` or `NOT CHECKED` and the reason, without a check. |
| `jsonl`, syslog | One event `unchecked` with the reason (syslog severity `err`); no result and no summary event. |
| `prom` | `checkmate_host_checked` is 0. No score, `checkmate_compliant` or check series for the host. |
| `junit` | A suite with one errored test case, so that a pipeline does not turn green. |
| `xccdf`, `arf` | Left out: these formats hold test results, and there are none. |

## Reports

A run with an inventory produces one report per host. On the console they appear as an overview; `--export` writes them as one document per format, exactly like `checkmate export` does for several report files. See [Reports and exports](exports.md).

Reports name a host as the inventory does, not as the host calls itself. With more than one group, the overview, the HTML and the PDF report add a table per group: hosts, compliant, not compliant, not checked and the score of the group. The HTML report has one column per host in the check table; the PDF report shows the same as a matrix of the checks with problems.
