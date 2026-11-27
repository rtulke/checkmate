# Results, severity and score

## Severity

Every check has a severity: `info`, `low`, `medium` (default), `high` or `critical`. It decides two things: whether a failure makes the run non-compliant, and how much the check weighs in the score.

## fail_on: when a failure counts

`fail_on` is the lowest severity whose failures count. Failures below it are reported as <span class="st st-warn">WARN</span>: visible, but not blocking.

```yaml
defaults:
  fail_on: medium        # low and info findings become warnings
```

```bash
checkmate run baseline.yml --fail-on high   # overrides the policy
```

| Severity of the failed check | `fail_on: low` (default) | `fail_on: medium` | `fail_on: high` |
|---|---|---|---|
| `critical` | FAIL | FAIL | FAIL |
| `high` | FAIL | FAIL | FAIL |
| `medium` | FAIL | FAIL | WARN |
| `low` | FAIL | WARN | WARN |
| `info` | WARN | WARN | WARN |

Two rules are fixed on purpose:

- **`info` never fails.** Use it for inventory-style checks you want to see but never enforce.
- **Errors are never downgraded.** A check that could not be evaluated says nothing about the system, so it always counts, whatever its severity.

Findings that are real but accepted for a documented reason are handled with [waivers](waivers.md), not by raising the threshold: a waiver names the check, the reason and an expiry date, and the check stays visible as WAIVED.

A typical rollout: start with `--fail-on critical` to get a baseline without blocking anything, fix findings, then lower the threshold step by step.

## Score

The score is the weighted share of passed checks:

| Severity | Weight |
|---|---|
| `critical` | 10 |
| `high` | 7 |
| `medium` | 3 |
| `low` | 1 |
| `info` | 0 |

```text
score = sum(weights of PASS) / sum(weights of PASS + FAIL + WARN + ERROR) × 100
```

Skipped and not-applicable checks do not count. A failed critical check therefore costs as much as ten failed low checks. The score is part of the text and JSON reports, so it can be tracked over time; compliance itself is decided only by FAIL and ERROR.

## How other tools do it

| Tool | Model |
|---|---|
| OpenSCAP | Severity per rule, weighted score, any failure fails the scan |
| Chef InSpec | `impact` 0.0–1.0 per control, impact 0 is informational |
| Trivy, Checkov | Severity filter and a "hard fail" threshold, below it a soft fail |
| Lynis | Hardening index 0–100, warnings and suggestions |

checkmate combines the threshold of Trivy/Checkov, the informational level of InSpec and a weighted score similar to OpenSCAP, and adds the strict handling of errors.

## JSON report

```json
{
  "tool": "checkmate",
  "version": "2.4.0",
  "run_id": "3f9c1d2e8a7b6c5d",
  "policy": "Web server baseline",
  "policy_path": "/etc/checkmate/baseline.yml",
  "policy_sources": [
    { "path": "/etc/checkmate/baseline.yml", "sha256": "9c1f…e2a7", "origin": "local", "signer": "release-team" }
  ],
  "facts": { "os": "linux", "distro": "rocky", "hostname": "web01", "...": "..." },
  "started": "2026-11-23T06:00:00Z",
  "duration_ms": 1840,
  "summary": {
    "total": 42, "passed": 38, "failed": 1, "warnings": 2, "errors": 1,
    "skipped": 0, "not_applicable": 0, "waived": 0, "evaluated": 42,
    "fail_on": "low", "score": 91.3, "compliant": false
  },
  "results": [
    {
      "id": "FS-001",
      "name": "/tmp has at least 500 MB free",
      "tags": ["files", "disk"],
      "severity": "high",
      "status": "FAIL",
      "message": "expected stdout >= \"500\", got \"312\"",
      "expected": "stdout >= \"500\"",
      "command": "df -Pm /tmp | awk 'NR == 2 {print $4}'",
      "shell": "bash",
      "rc": 0,
      "stdout": "312\n",
      "duration_ms": 4,
      "rationale": "A full /tmp makes programs fail that need temporary files.",
      "remediation": "Remove old files from /tmp or enlarge the file system.",
      "location": "/etc/checkmate/baseline.yml:57"
    }
  ]
}
```

| Field | Content |
|---|---|
| `run_id` | The same in every output of one run, to tie reports, events and metrics together. |
| `policy_sources` | Every file the policy was loaded from: `path`, `sha256`, `origin` (`shipped`, `modified`, `local`) and, if signed by a trusted key, `signer`. See [Where a policy comes from](trust.md). |
| `summary.evaluated` | Checks that passed, failed, warned, errored or were waived; skipped and not applicable ones do not count. |
| `results[].no_log` | `true` for a check with `no_log`: `command`, `stdout` and `stderr` are missing, and `expected` and `message` are general. See [Secrets](checks.md#secrets). |
| `results[].waiver` | Reason, expiry and source of the waiver that accepts the result. See [Waivers](waivers.md). |

A run with an [inventory](inventory.md), like `checkmate export` with several reports, writes one document with the reports of all hosts:

```json
{
  "tool": "checkmate",
  "version": "2.4.0",
  "reports": [
    { "host": "web01.example.net", "groups": ["web"], "facts": { "...": "..." }, "summary": { "...": "..." }, "results": [] },
    { "host": "db02.example.net", "groups": ["db"], "error": "host is not reachable over SSH: ...", "unreachable": true, "results": [] }
  ]
}
```

`host` and `groups` are the names of the inventory. A host with `error` could not be checked: it has no results, and its summary says nothing about compliance.
