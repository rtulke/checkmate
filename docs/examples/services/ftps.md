# FTP servers (vsftpd, ProFTPD)

Security of vsftpd and ProFTPD: no anonymous access, encrypted logins and data (FTPS) with TLS 1.2 or newer, users locked into their home, no version in the banner, and transfer logging. FTP without TLS sends passwords in clear text; prefer SFTP where possible.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/services/ftps.yml`](https://github.com/rtulke/checkmate/blob/main/examples/services/ftps.yml)
- :material-format-list-checks: **Checks**  
  16 from 5 definitions, 2 with loops
- :material-monitor: **Platforms**  
  any (POSIX shell)

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/services/ftps.yml

# Run the checks
checkmate run examples/services/ftps.yml
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `VSFTPD-ANONYMOUS-ENABLE` | Anonymous logins are disabled | <span class="sev sev-critical">critical</span> | services, ftp, vsftpd |
| `VSFTPD-SSL-ENABLE` | TLS is enabled | <span class="sev sev-high">high</span> | services, ftp, vsftpd |
| `VSFTPD-FORCE-LOCAL-LOGINS-SSL` | Passwords are only sent over TLS | <span class="sev sev-high">high</span> | services, ftp, vsftpd |
| `VSFTPD-FORCE-LOCAL-DATA-SSL` | File transfers are encrypted | <span class="sev sev-medium">medium</span> | services, ftp, vsftpd |
| `VSFTPD-SSL-SSLV3` | SSL 3 is disabled | <span class="sev sev-high">high</span> | services, ftp, vsftpd |
| `VSFTPD-SSL-TLSV1` | TLS 1.0 is disabled | <span class="sev sev-medium">medium</span> | services, ftp, vsftpd |
| `VSFTPD-SSL-TLSV1-1` | TLS 1.1 is disabled | <span class="sev sev-medium">medium</span> | services, ftp, vsftpd |
| `VSFTPD-CHROOT-LOCAL-USER` | Users are locked into their home directory | <span class="sev sev-medium">medium</span> | services, ftp, vsftpd |
| `VSFTPD-XFERLOG-ENABLE` | Transfers are logged | <span class="sev sev-low">low</span> | services, ftp, vsftpd |
| `VSFTPD-BANNER` | The vsftpd banner does not reveal the version | <span class="sev sev-low">low</span> | services, ftp, vsftpd |
| `PROFTPD-ANONYMOUS` | ProFTPD offers no anonymous access | <span class="sev sev-critical">critical</span> | services, ftp, proftpd |
| `PROFTPD-TLSENGINE` | TLS is enabled | <span class="sev sev-high">high</span> | services, ftp, proftpd |
| `PROFTPD-TLSREQUIRED` | TLS is required for logins and data | <span class="sev sev-high">high</span> | services, ftp, proftpd |
| `PROFTPD-SERVERIDENT` | The banner does not reveal the version | <span class="sev sev-low">low</span> | services, ftp, proftpd |
| `PROFTPD-DEFAULTROOT` | Users are locked into their home directory | <span class="sev sev-medium">medium</span> | services, ftp, proftpd |
| `PROFTPD-TLSPROTOCOL` | ProFTPD offers only TLS 1.2 and newer | <span class="sev sev-medium">medium</span> | services, ftp, proftpd, tls |

## Policy

```yaml title="examples/services/ftps.yml" linenums="1"
name: FTP servers (vsftpd, ProFTPD)
version: 1.0.0
description: >
  Security of vsftpd and ProFTPD: no anonymous access, encrypted logins and
  data (FTPS) with TLS 1.2 or newer, users locked into their home, no
  version in the banner, and transfer logging. FTP without TLS sends
  passwords in clear text; prefer SFTP where possible.

defaults:
  when:
    - facts.os == "linux"
    - facts.is_root

snippets:
  # Last value of a vsftpd option, lower-cased; empty if unset.
  vsftpd: >-
    { cat /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null || true; }
    | awk -F= '$1 == "{{ arg }}" {v = tolower($2)} END {print v}'
  # Last value of a ProFTPD directive, lower-cased; empty if unset.
  proftpd: >-
    { cat /etc/proftpd/proftpd.conf /etc/proftpd.conf /etc/proftpd/tls.conf /etc/proftpd/conf.d/*.conf 2>/dev/null || true; }
    | awk 'tolower($1) == tolower("{{ arg }}") {v = tolower($2)} END {print v}'

checks:
  # ===== vsftpd ================================================================
  - id: "VSFTPD-{{ item.key | upper | replace('_', '-') }}"
    name: "{{ item.value.name }}"
    description: "vsftpd option {{ item.key }}; vsftpd default: {{ item.value.default }}."
    tags: [services, ftp, vsftpd]
    severity: "{{ item.value.severity }}"
    only_if: command -v vsftpd
    loop:
      anonymous_enable: { name: Anonymous logins are disabled, default: "NO", expect: "== no", severity: critical }
      ssl_enable: { name: TLS is enabled, default: "NO", expect: "== yes", severity: high }
      force_local_logins_ssl: { name: Passwords are only sent over TLS, default: "YES once ssl_enable", expect: "!= no", severity: high }
      force_local_data_ssl: { name: File transfers are encrypted, default: "YES once ssl_enable", expect: "!= no", severity: medium }
      ssl_sslv3: { name: SSL 3 is disabled, default: "NO", expect: "!= yes", severity: high }
      ssl_tlsv1: { name: TLS 1.0 is disabled, default: "YES", expect: "== no", severity: medium }
      ssl_tlsv1_1: { name: TLS 1.1 is disabled, default: "NO", expect: "!= yes", severity: medium }
      chroot_local_user: { name: Users are locked into their home directory, default: "NO", expect: "== yes", severity: medium }
      xferlog_enable: { name: Transfers are logged, default: "NO", expect: "== yes", severity: low }
    run: { use: vsftpd, arg: "{{ item.key }}" }
    expect: "{{ item.value.expect }}"
    rationale: "Another value of {{ item.key }} allows anonymous or unencrypted access, old protocol versions, access outside the home directory or transfers without a log entry."
    remediation: "Set {{ item.key }} in vsftpd.conf to a value that satisfies `{{ item.value.expect }}` and restart vsftpd."

  - id: VSFTPD-BANNER
    name: The vsftpd banner does not reveal the version
    description: Without ftpd_banner, vsftpd greets with its name and version.
    tags: [services, ftp, vsftpd]
    severity: low
    only_if: command -v vsftpd
    run: |
      { cat /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null || true; } | awk -F= '$1 == "ftpd_banner" || $1 == "banner_file" {v = $2} END {print v}'
    expect: "!empty"
    rationale: The version in the greeting tells an attacker which known vulnerabilities to try.
    remediation: Set ftpd_banner in vsftpd.conf to a neutral text.

  # ===== ProFTPD ===============================================================
  - id: PROFTPD-ANONYMOUS
    name: ProFTPD offers no anonymous access
    tags: [services, ftp, proftpd]
    severity: critical
    only_if: command -v proftpd
    run: grep -rihE '^[[:space:]]*<Anonymous' /etc/proftpd /etc/proftpd.conf 2>/dev/null || true
    expect: empty
    rationale: Anonymous access lets everyone download files and, with a writable directory, store their own.
    remediation: Remove the <Anonymous> sections from the ProFTPD configuration.

  - id: "PROFTPD-{{ item.key | upper }}"
    name: "{{ item.value.name }}"
    tags: [services, ftp, proftpd]
    severity: "{{ item.value.severity }}"
    only_if: command -v proftpd
    loop:
      TLSEngine: { name: TLS is enabled, expect: "== on", severity: high }
      TLSRequired: { name: TLS is required for logins and data, expect: "in [on, both, auth+data]", severity: high }
      ServerIdent: { name: The banner does not reveal the version, expect: "== off", severity: low }
      DefaultRoot: { name: Users are locked into their home directory, expect: "== ~", severity: medium }
    run: { use: proftpd, arg: "{{ item.key }}" }
    expect: "{{ item.value.expect }}"
    rationale: "Another value of {{ item.key }} allows unencrypted logins or transfers, shows the server version or lets users leave their home directory."
    remediation: "Set {{ item.key }} in the ProFTPD configuration to a value that satisfies `{{ item.value.expect }}` and restart ProFTPD."

  - id: PROFTPD-TLSPROTOCOL
    name: ProFTPD offers only TLS 1.2 and newer
    tags: [services, ftp, proftpd, tls]
    severity: medium
    only_if: command -v proftpd
    run: |
      { cat /etc/proftpd/proftpd.conf /etc/proftpd.conf /etc/proftpd/tls.conf /etc/proftpd/conf.d/*.conf 2>/dev/null || true; } |
        awk 'tolower($1) == "tlsprotocol" {$1 = ""; v = tolower($0)} END {print v}'
    expect:
      - "!empty"
      - "!~ (^|[[:space:]])(sslv3|tlsv1|tlsv1\\.1)([[:space:]]|$)"
    rationale: SSLv3, TLS 1.0 and TLS 1.1 have known weaknesses and are deprecated.
    remediation: Set `TLSProtocol TLSv1.2 TLSv1.3` in the ProFTPD configuration.
```
