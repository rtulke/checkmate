# CI and reporting

## Exit codes

`checkmate run` exits with `0` when the run is compliant, `1` when it is not and `2` on usage or policy errors, so it works in any pipeline without extra scripting.

## Reports

```bash
checkmate run baseline.yml --export json,junit,html -o report
```

- **Text** on stdout for people reading the log.
- **JSON** (`report.json`) with facts, summary, score and every result, for dashboards, archives, `checkmate export` and `checkmate diff`.
- **JUnit XML** (`report.junit.xml`) for test views in GitLab, GitHub, Jenkins and Azure DevOps. FAIL becomes a failure, ERROR an error, SKIP and N/A are skipped, WARN is logged on stderr of the test case.
- **HTML** (`report.html`) as a browsable build artifact.

All formats, including PDF, CSV, XCCDF/ARF, Prometheus and syslog, are described in [Reports and exports](../reference/exports.md).

## Regressions between runs

`checkmate diff` compares the report of a branch with the one of the main branch, or today's run with yesterday's:

```bash
checkmate diff main.json report.json   # exit 1 if anything changed
checkmate diff --format json main.json report.json | jq '.hosts[0].regressions | length'
```

## GitLab CI

```yaml
compliance:
  image: rockylinux:9
  script:
    - curl -fsSLo /usr/local/bin/checkmate https://github.com/rtulke/checkmate/releases/latest/download/checkmate-linux-amd64
    - chmod +x /usr/local/bin/checkmate
    - checkmate run policies/baseline.yml --color always --export junit,json,html -o report
  artifacts:
    when: always
    reports:
      junit: report.junit.xml
    paths: [report.json, report.html]
```

## GitHub Actions

```yaml
jobs:
  compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install checkmate
        run: |
          curl -fsSLo checkmate https://github.com/rtulke/checkmate/releases/latest/download/checkmate-linux-amd64
          sudo install -m 0755 checkmate /usr/local/bin/checkmate
      - name: Run policy
        run: checkmate run policies/baseline.yml --color always --export junit,html -o report
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: compliance-report
          path: report.*
```

## Scheduled runs on servers

A systemd timer runs the policy daily. One run writes the latest JSON report and Prometheus metrics, sends every result to the local syslog and keeps a dated copy of the report:

```ini title="/etc/systemd/system/checkmate.service"
[Unit]
Description=checkmate compliance run

[Service]
Type=oneshot
# Exit code 1 means "not compliant", not a failure of the service.
SuccessExitStatus=1
ExecStart=/usr/local/bin/checkmate run /etc/checkmate/baseline.yml --quiet --color never --export json,prom,syslog -o /var/lib/checkmate/latest
ExecStartPost=/bin/sh -c 'cp /var/lib/checkmate/latest.json /var/log/checkmate/report-$(date +%%F).json'
```

Start the node_exporter with `--collector.textfile.directory=/var/lib/checkmate` to pick up `latest.prom`; the file is replaced atomically.

```ini title="/etc/systemd/system/checkmate.timer"
[Unit]
Description=Daily checkmate compliance run

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
install -d -m 0750 /var/log/checkmate
systemctl enable --now checkmate.timer
```

The text output goes to the journal (`journalctl -u checkmate`), the JSON reports can be collected centrally.

## Rolling out thresholds

Introduce a policy without breaking pipelines on day one:

1. `--fail-on critical`: only critical findings block.
2. Fix findings, watch the score in the reports.
3. Lower to `high`, then `medium`, then the default `low`.
