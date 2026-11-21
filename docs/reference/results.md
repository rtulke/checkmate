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
  "version": "1.0.0",
  "policy": "Web server baseline",
  "facts": { "os": "linux", "distro": "rocky", "...": "..." },
  "summary": {
    "total": 42, "passed": 38, "failed": 1, "warnings": 2, "errors": 1,
    "skipped": 0, "not_applicable": 0,
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
      "rc": 0,
      "stdout": "312\n",
      "duration_ms": 4,
      "location": "/etc/checkmate/baseline.yml:57"
    }
  ]
}
```
