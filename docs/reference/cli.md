# Command line

```text
checkmate run      [flags] <policy.yml>   run checks and report results
checkmate validate [flags] <policy.yml>   check a policy for errors without running it
checkmate list     [flags] <policy.yml>   list checks and the commands they would run
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
| `--format FORMAT` | Output on stdout: `text` (default), `json`, `junit`. |
| `--json-out FILE` | Also write a JSON report to a file. |
| `--junit-out FILE` | Also write a JUnit XML report to a file. |
| `-j`, `--jobs N` | Checks to run in parallel. Default: number of CPUs. |
| `-v`, `--verbose` | Show command, exit code, stdout, stderr and remediation of failed checks below the result line. Without `-v`, every check is a single line whose reason is shortened to the terminal width (`COLUMNS` overrides the width). |
| `-q`, `--quiet` | Show only failed checks and the summary. |
| `--color WHEN` | `auto` (default: on a terminal), `always`, `never`. `NO_COLOR` is honored. |
| `--no-color` | Same as `--color never`. |
| `--allow-insecure-policy` | Load policy files writable by other users while running as root. |

### Examples

```bash
# Everything
checkmate run baseline.yml

# Only compliance checks for fully managed servers
checkmate run baseline.yml --tags compliance+full

# Only SSH checks, with details on failures
checkmate run baseline.yml --id 'SSH-*' -v

# Fail only on high and critical findings, everything else is a warning
checkmate run baseline.yml --fail-on high

# Console output plus reports for a dashboard and the CI server
checkmate run baseline.yml --json-out report.json --junit-out junit.xml

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

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Compliant |
| `1` | Not compliant: at least one FAIL or ERROR |
| `2` | Usage error, invalid policy or no checks selected |
