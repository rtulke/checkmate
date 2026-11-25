# Reports and exports

checkmate writes the results of a run in eleven formats and to syslog. The
same format names apply everywhere:

| Format | File | For |
|---|---|---|
| `text` | `.txt` | people: the console output |
| `json` | `.json` | complete results; the input of `checkmate export` and `checkmate diff` |
| `jsonl` | `.jsonl` | log pipelines and SIEMs: one JSON event per check, then a summary |
| `csv` | `.csv` | spreadsheets and audit lists: one row per check and host |
| `html` | `.html` | a self-contained report with filters, for auditors and management |
| `pdf` | `.pdf` | the same report for printing and archiving |
| `junit` | `.junit.xml` | test views of GitLab, GitHub, Jenkins and Azure DevOps |
| `xccdf` | `.xccdf.xml` | SCAP tools: XCCDF 1.2 benchmark with test results |
| `arf` | `.arf.xml` | SCAP tools: Asset Reporting Format 1.1 |
| `prom` | `.prom` | Prometheus via the node_exporter textfile collector |
| `attack` | `.attack.json` | [ATT&CK Navigator](../standards.md#mitre-attck) layer of the checks tagged `attack-t*` |
| `syslog` | – | the local syslog daemon, or a collector over UDP, TCP or TLS |

## Three flags

```text
--format FORMAT   what checkmate run prints on stdout (default: text)
--export LIST     formats written to files at the same time, comma-separated
-o, --output BASE base name or directory of the files
```

```bash
# console output as usual, plus an HTML and a PDF report
checkmate run baseline.yml --export html,pdf

# into a directory: reports/checkmate-<host>-<time>.html, .pdf, .json
checkmate run baseline.yml --export html,pdf,json -o reports/

# with a fixed name: web01.html, web01.json, web01.prom
checkmate run baseline.yml --export html,json,prom -o web01

# JSON on stdout for a pipe, nothing on the console
checkmate run baseline.yml --format json | jq '.summary'
```

Each file gets the extension of its format; `-o web01.html` and `-o web01`
are the same. Without `-o` the files are named
`checkmate-<host>-<YYYYMMDD-HHMMSS>` in the current directory. Files are
written atomically (to a temporary file that replaces the target when it is
complete) with mode `0640`, since reports describe weaknesses of the host.
A directory that does not exist yet is created. Whether the files can be
written is checked before the checks run, and the result is printed before
the exports are written, so a failing export never costs the result of a run.

## checkmate export

Converts saved JSON reports into any other format, later and on any machine.
Several reports, from several hosts or runs, become **one** document: one
HTML or PDF report with all hosts, one CSV, one ARF collection with one asset
per host, one JUnit file with one suite per host.

```bash
# run on every server, collect the JSON reports, report centrally
checkmate run baseline.yml --export json -o /var/lib/checkmate/

checkmate export -f html,pdf,csv -o fleet reports/*.json   # fleet.html, fleet.pdf, fleet.csv
checkmate export reports/*.json                            # overview of all hosts on the console
checkmate export -f csv web01.json > web01.csv             # one format without -o goes to stdout

# "-" reads the report from stdin
checkmate run baseline.yml --format json | checkmate export -f pdf -o now -
```

A single format without `-o` is written to stdout; several formats are
written next to the report (`web01.json` → `web01.html`, `web01.pdf`), or to
`checkmate-report.*` when several reports are merged. `pdf` is never written
to a terminal.

## checkmate diff

Compares two JSON reports, or two policies. The file extension decides:
`.json` is a report, `.yml` and `.yaml` are policies (other names are
recognised by their content).

```console
$ checkmate diff monday.json tuesday.json
--- web01 · CIS Debian Linux 12 · 2026-11-23 06:00
+++ web01 · CIS Debian Linux 12 · 2026-11-24 06:00
score 81.4% -> 79.9% (-1.5)

New problems (1)
  + PASS -> FAIL     CIS-DEBIAN12-5.1.20-sshd_permitrootlogin  [high] PermitRootLogin is no
      expected stdout ~ "^permitrootlogin no", got "permitrootlogin yes"

Fixed (1)
  - FAIL -> PASS     CIS-DEBIAN12-1.5.3-aslr  [medium] ASLR is enabled
```

- **Reports:** new problems (a check that now fails, warns or errors), fixed
  checks, checks newly accepted by a waiver (listed apart from the fixed
  ones), other status changes, added and removed checks and the score. Two
  single reports are compared directly, even from two different hosts ("why
  does web02 differ from web01?"); merged reports are paired by host and
  policy.
- **Policies:** changed policy settings (version, defaults, variables),
  added, removed and changed checks, field by field, with a line diff for
  commands. Checks are compared after loops, templates and snippets are
  expanded, so a change to a snippet shows up in every check that uses it:

```console
$ checkmate diff baseline-1.4.yml baseline-1.5.yml
Changed checks (1)
  ~ SSH-003  No weak ciphers
      severity: medium -> high
      run:
        - sshd -T | awk '$1 == "ciphers" {print $2}'
        + sshd -T 2>/dev/null | awk '$1 == "ciphers" {print $2}'
```

`--format json` prints the diff as JSON. The exit code is `0` without
differences, `1` with differences and `2` on errors, like `diff(1)`.

Merging policies is not a separate command: that is what
[`include:`](policy.md) does, without losing comments and anchors.

## Formats in detail

### HTML and PDF

Both contain the score, the verdict, the result counts, failures by
severity, the hosts, every finding with reason, expected value, command,
output, rationale and remediation, the waivers with their reasons, and a
table of all checks. The HTML page needs no network access, filters by
text, status and severity, and follows the light or dark mode of the
browser. Output is escaped, and command output is shortened to 4000
characters; JSON keeps it all. The PDF is built into checkmate (standard PDF fonts, no external
tools), so it works on every server.

### CSV

Columns: `host, os, distro, policy, policy_version, started, run_id, id,
name, status, severity, tags, reason, expected, waiver_reason, waiver_until,
waived_status, reference, rationale, remediation, duration_ms, location`.
Cells that a spreadsheet would evaluate as a formula (starting with `=`,
`+`, `-`, `@`) get a leading `'`, since check output can contain text from
the inspected host.

### JSON Lines and syslog

Each check becomes one self-contained event, followed by a summary event:

```json
{"time":"2026-11-23T06:00:00Z","event":"result","tool":"checkmate","version":"2.1.0","run_id":"3f9c1d2e8a7b6c5d","host":"web01","os":"linux","distro":"Debian GNU/Linux 12 (bookworm)","policy":"CIS Debian Linux 12","policy_version":"1.1.0","id":"CIS-DEBIAN12-5.1.20-sshd_permitrootlogin","name":"PermitRootLogin is no","status":"FAIL","severity":"high","tags":["cis","cis-level-1"],"reason":"expected stdout ~ \"^permitrootlogin no\", got \"permitrootlogin yes\"","duration_ms":12}
```

`run_id` is the same in every output of one run, so events, reports and
metrics can be joined. Syslog sends the same events as messages; skipped and
not applicable checks and the rationale are left out, and long fields are
shortened to 512 characters.

| Target | Sends to |
|---|---|
| `syslog` | the local daemon (`/dev/log`, `/var/run/syslog`), RFC 3164, also read by journald |
| `syslog:udp://host[:514]` | a collector over UDP, RFC 5424 |
| `syslog:tcp://host[:514]` | over TCP, RFC 5424 with octet counting (RFC 6587) |
| `syslog:tls://host[:6514]` | over TLS 1.2+, RFC 5425, server certificate verified |

`?facility=local3` selects the facility (default `user`), e.g.
`--export json,syslog:tls://siem.example.com?facility=local3`. The syslog
severity follows the result: a failed check of severity critical is
`crit`, high `err`, medium `warning`, low `notice`; errors are `err`;
passed, waived and summary events of compliant hosts are `info` or
`notice`. Splunk, Elastic, Graylog and Wazuh parse the JSON message
directly.

### Prometheus

For the textfile collector of the node_exporter; the file is replaced
atomically, as the collector requires:

```bash
checkmate run baseline.yml -q --export prom -o /var/lib/node_exporter/textfile/checkmate
```

| Metric | Labels | Value |
|---|---|---|
| `checkmate_score` | policy, host | score 0–100, -1 if nothing was evaluated |
| `checkmate_compliant` | policy, host | 1 or 0 |
| `checkmate_checks` | policy, host, status | checks per status |
| `checkmate_failed_checks` | policy, host, severity | FAIL and ERROR per severity |
| `checkmate_check_problem` | policy, host, id, severity, status | 1 per failed, warned or errored check |
| `checkmate_last_run_timestamp_seconds` | policy, host | start of the run |
| `checkmate_run_duration_seconds` | policy, host | duration |

Only problems get a series per check, which keeps the number of series small
and still tells an alert which checks fail. Example alerts:
`checkmate_compliant == 0`, `checkmate_failed_checks{severity="critical"} > 0`,
`time() - checkmate_last_run_timestamp_seconds > 2 * 86400`.

### XCCDF and ARF

checkmate has no SCAP source content, so it generates it: a Benchmark with
one Rule per check (title, description, severity, weight, `rationale`,
remediation as `fixtext`, the command as `check-content`, DISA CCI and STIG
vulnerability IDs as `ident`), and one TestResult per report with target
facts, one `rule-result` per check and two scores (`urn:xccdf:scoring:flat`
and checkmate's weighted score). ARF 1.1 wraps the Benchmark as report
request and every TestResult as report about an asset
(`ai:computing-device`).

| checkmate | XCCDF result |
|---|---|
| PASS | `pass` |
| FAIL, WARN | `fail` |
| ERROR | `error` |
| SKIP | `notselected` |
| N/A | `notapplicable` |
| WAIVED | `pass` with an `override` that keeps the original result and the reason; `notchecked` if the check was not run |
| critical | severity `high` (XCCDF has no critical) |

Both formats pass the schema validation of OpenSCAP (`oscap xccdf validate`,
`oscap ds rds-validate`), and OpenSCAP renders them like its own results:

```bash
oscap xccdf generate report web01.arf.xml > web01-openscap.html
```

### JUnit

One test suite per report: FAIL becomes a failure, ERROR an error, SKIP,
N/A and WAIVED are skipped, WARN is logged on stderr of the test case.
