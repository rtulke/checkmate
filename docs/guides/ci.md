# CI and reporting

## Exit codes

`checkmate run` exits with `0` when the run is compliant, `1` when it is not and `2` on usage or policy errors, so it works in any pipeline without extra scripting.

## Reports

```bash
checkmate run baseline.yml \
  --json-out report.json \
  --junit-out junit.xml
```

- **Text** on stdout for people reading the log.
- **JSON** with facts, summary, score and every result, for dashboards and archives.
- **JUnit XML** for test views in GitLab, GitHub, Jenkins and Azure DevOps. FAIL becomes a failure, ERROR an error, SKIP and N/A are skipped, WARN is logged on stderr of the test case.

## GitLab CI

```yaml
compliance:
  image: rockylinux:9
  script:
    - curl -fsSLo /usr/local/bin/checkmate https://github.com/rtulke/checkmate/releases/latest/download/checkmate-linux-amd64
    - chmod +x /usr/local/bin/checkmate
    - checkmate run policies/baseline.yml --color always --junit-out junit.xml --json-out report.json
  artifacts:
    when: always
    reports:
      junit: junit.xml
    paths: [report.json]
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
        run: checkmate run policies/baseline.yml --color always --junit-out junit.xml
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: compliance-report
          path: junit.xml
```

## Scheduled runs on servers

A systemd timer runs the policy daily and keeps the JSON reports:

```ini title="/etc/systemd/system/checkmate.service"
[Unit]
Description=checkmate compliance run

[Service]
Type=oneshot
ExecStart=/bin/sh -c '/usr/local/bin/checkmate run /etc/checkmate/baseline.yml --quiet --color never --json-out /var/log/checkmate/report-$(date +%%F).json'
```

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
