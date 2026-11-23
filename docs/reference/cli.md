# Command line

```text
checkmate run      [flags] <policy.yml>   run checks and report results
checkmate validate [flags] <policy.yml>   check a policy for errors without running it
checkmate list     [flags] <policy.yml>   list checks and the commands they would run
checkmate export   [flags] <report.json>...  convert or merge JSON reports (html, pdf, csv, ...)
checkmate diff     [flags] <old> <new>    compare two reports (.json) or two policies (.yml)
checkmate facts                           print the facts gathered for this host
checkmate version                         print the version
```

Flags may come before or after the policy file.

## checkmate run

| Flag | Description |
|---|---|
| `-t`, `--tags EXPR` | Select checks by tags. `,` means *or*, `+` means *and*: `compliance+full,quality` |
| `--skip-tags EXPR` | Exclude checks by tags, same syntax. |
| `--id PATTERNS` | Select checks by id, comma-separated glob patterns: `SSH-*,USR-001` |
| `-e`, `--extra-var KEY=VALUE` | Set a variable (repeatable). Values are parsed as YAML: `-e ports='[22, 443]'` |
| `--fail-on SEVERITY` | Lowest severity whose failures make the run non-compliant. Default: `defaults.fail_on`, else `low`. |
| `--waivers FILE` | File with accepted deviations (repeatable). See [Waivers](waivers.md). |
| `--ignore-waivers` | Report every result as if no waiver existed. |
| `--format FORMAT` | Output on stdout: `text` (default), `json`, `jsonl`, `csv`, `html`, `junit`, `xccdf`, `arf`, `prom`, `attack`. See [Reports and exports](exports.md). |
| `--export LIST` | Also write these formats to files, comma-separated: `html,pdf,json`. `syslog` or `syslog:udp://host` sends the results to syslog. |
| `-o`, `--output BASE` | Base name or directory of the `--export` files. Default: `checkmate-<host>-<time>` in the current directory. |
| `-j`, `--jobs N` | Checks to run in parallel. Default: number of CPUs. |
| `-v`, `--verbose` | More output, repeatable (`-v -v` = `-vv`). See [Output levels](#output-levels). |
| `-vv` | Details of failed, warned and errored checks. |
| `-vvv`, `--debug` | Debug details of every check, facts and loaded files. |
| `-q`, `--quiet` | Show only failed checks and the summary. |
| `--color WHEN` | `auto` (default: on a terminal), `always`, `never`. `NO_COLOR` is honored. |
| `--no-color` | Same as `--color never`. |
| `--allow-insecure-policy` | Load policy and waiver files as root that are owned by another user or writable by others. See [Running as root](../getting-started/installation.md#running-as-root). |

### Output levels

| Level | Shows |
|---|---|
| default | one line per check: status, ID, name |
| `-v` | plus severity and the reason of every failed, warned, errored or skipped check |
| `-vv` | plus, below each problem: command, exit code, stdout, stderr, rationale, remediation and where the check is defined |
| `-vvv`, `--debug` | for **every** check: severity, tags, `when`, `only_if`, expectation, command, exit code, shell, duration and output; before the results: facts, platform keys and all loaded policy files |

Up to `-v`, every check stays on a single line; long reasons are shortened to the terminal width (`COLUMNS` overrides the detected width). `-q` hides passed and skipped checks at every level.

```console
$ checkmate run demo.yml
FAIL   SSH-ROOT     Root login over SSH is disabled
PASS   SSH-CIPHERS  No weak SSH ciphers

$ checkmate run demo.yml -v
FAIL   SSH-ROOT     Root login over SSH is disabled  [critical]  expected stdout == "no", got "yes"
PASS   SSH-CIPHERS  No weak SSH ciphers

$ checkmate run demo.yml -vv
FAIL   SSH-ROOT     Root login over SSH is disabled  [critical]  expected stdout == "no", got "yes"
       command: awk '$1 == "PermitRootLogin" {print $2}' /etc/ssh/sshd_config
       exit code: 0
       stdout: yes
       fix: Set PermitRootLogin no in /etc/ssh/sshd_config
       defined at: /etc/checkmate/demo.yml:7
PASS   SSH-CIPHERS  No weak SSH ciphers
```

### Examples

```bash
# Everything
checkmate run baseline.yml

# Only compliance checks for fully managed servers
checkmate run baseline.yml --tags compliance+full

# Only SSH checks, with commands and output of failures
checkmate run baseline.yml --id 'SSH-*' -vv

# Everything about one check, for debugging a policy
checkmate run baseline.yml --id SSH-ROOT --debug

# Fail only on high and critical findings, everything else is a warning
checkmate run baseline.yml --fail-on high

# Console output plus reports: report.json, report.junit.xml, report.html
checkmate run baseline.yml --export json,junit,html -o report

# Send every result to a SIEM
checkmate run baseline.yml -q --export syslog:tls://siem.example.com

# Override a variable
checkmate run baseline.yml -e min_free_mb=2048
```

## checkmate validate

Loads the policy, expands loops, renders templates for this host and checks every definition: required keys, unknown keys, duplicate ids, invalid expectations, unknown snippets, undefined variables. Nothing is executed.

```console
$ checkmate validate baseline.yml
baseline.yml: OK (184 checks from 6 file(s), 4 snippets)
```

## checkmate list

Prints the selected checks. With `-v`, it also shows the command each check runs on this host and its expectation, which is the quickest way to debug templates and platform variants.

```console
$ checkmate list -v examples/system/ssh.yml --id SSH-003
ID       SEVERITY  TAGS                NAME
SSH-003  high      system,ssh,crypto   No weak ciphers
                                         $ sshd -T 2>/dev/null | awk '$1 == "ciphers" {print $2}'
                                         expect: stdout not to be empty and stdout !~ "(cbc|arcfour|3des|blowfish)"
```

## checkmate export

Converts JSON reports into other formats and merges several reports (hosts or runs) into one document. See [Reports and exports](exports.md#checkmate-export).

| Flag | Description |
|---|---|
| `-f`, `--format LIST` | Formats, comma-separated (default: `text`). |
| `-o`, `--output BASE` | Base name or directory of the files; `-` for stdout. A single format without `-o` goes to stdout. |
| `--color WHEN` | Colors of the text format: `auto`, `always`, `never`. |

```bash
checkmate export -f html,pdf -o fleet reports/*.json
```

## checkmate diff

Compares two JSON reports or two policies, recognised by the file extension. See [Reports and exports](exports.md#checkmate-diff).

| Flag | Description |
|---|---|
| `--format FORMAT` | `text` (default) or `json`. |
| `--color WHEN` | `auto`, `always`, `never`. |
| `-e`, `--extra-var KEY=VALUE` | Variables for expanding policies. |
| `--allow-insecure-policy` | Load policy and waiver files as root that are owned by another user or writable by others. See [Running as root](../getting-started/installation.md#running-as-root). |

Exit codes: `0` no differences, `1` differences, `2` error.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Compliant |
| `1` | Not compliant: at least one FAIL or ERROR |
| `2` | Usage error, invalid policy, no checks selected, or no check evaluated |
