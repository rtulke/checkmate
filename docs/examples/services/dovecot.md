# Dovecot

Security of the Dovecot IMAP/POP3 server: valid configuration, TLS required with TLS 1.2 or newer, no clear-text authentication without TLS, a protected private key and no clear-text POP3/IMAP listeners. Values come from doveconf, so defaults and included files count. Works with Dovecot 2.3 and 2.4 (renamed settings).

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/services/dovecot.yml`](https://github.com/rtulke/checkmate/blob/main/examples/services/dovecot.yml)
- :material-format-list-checks: **Checks**  
  7 from 7 definitions
- :material-monitor: **Platforms**  
  any (POSIX shell)

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/services/dovecot.yml

# Run the checks
checkmate run examples/services/dovecot.yml
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `DOVECOT-CONFIG` | The Dovecot configuration is valid | <span class="sev sev-high">high</span> | services, mail, dovecot |
| `DOVECOT-SERVICE` | Dovecot is running | <span class="sev sev-medium">medium</span> | services, mail, dovecot |
| `DOVECOT-SSL-REQUIRED` | TLS is required for every connection | <span class="sev sev-high">high</span> | services, mail, dovecot, tls |
| `DOVECOT-SSL-MIN-PROTOCOL` | TLS 1.2 or newer is required | <span class="sev sev-medium">medium</span> | services, mail, dovecot, tls |
| `DOVECOT-NO-CLEARTEXT-AUTH` | Passwords are never accepted without TLS | <span class="sev sev-high">high</span> | services, mail, dovecot |
| `DOVECOT-PRIVATE-KEY` | The TLS private key is readable only by root | <span class="sev sev-high">high</span> | services, mail, dovecot, tls, permissions |
| `DOVECOT-PLAINTEXT-LISTENERS` | Clear-text IMAP and POP3 listeners are disabled | <span class="sev sev-low">low</span> | services, mail, dovecot |

## Policy

```yaml title="examples/services/dovecot.yml" linenums="1"
name: Dovecot
version: 1.0.0
description: >
  Security of the Dovecot IMAP/POP3 server: valid configuration, TLS
  required with TLS 1.2 or newer, no clear-text authentication without
  TLS, a protected private key and no clear-text POP3/IMAP listeners.
  Values come from doveconf, so defaults and included files count. Works
  with Dovecot 2.3 and 2.4 (renamed settings).

defaults:
  when:
    - facts.os == "linux"
    - facts.is_root

checks:
  - id: DOVECOT-CONFIG
    name: The Dovecot configuration is valid
    tags: [services, mail, dovecot]
    severity: high
    only_if: command -v doveconf
    run: doveconf -n >/dev/null 2>&1
    expect: true

  - id: DOVECOT-SERVICE
    name: Dovecot is running
    tags: [services, mail, dovecot]
    severity: medium
    only_if: command -v doveconf && command -v systemctl && test -d /run/systemd/system
    run: systemctl show -p ActiveState dovecot | cut -d= -f2
    expect: "== active"

  - id: DOVECOT-SSL-REQUIRED
    name: TLS is required for every connection
    tags: [services, mail, dovecot, tls]
    severity: high
    only_if: command -v doveconf
    run: doveconf -h ssl 2>/dev/null
    expect: "== required"

  - id: DOVECOT-SSL-MIN-PROTOCOL
    name: TLS 1.2 or newer is required
    tags: [services, mail, dovecot, tls]
    severity: medium
    only_if: command -v doveconf
    run: doveconf -h ssl_min_protocol 2>/dev/null
    expect: "in [TLSv1.2, TLSv1.3]"

  - id: DOVECOT-NO-CLEARTEXT-AUTH
    name: Passwords are never accepted without TLS
    description: disable_plaintext_auth = yes (2.3) or auth_allow_cleartext = no (2.4).
    tags: [services, mail, dovecot]
    severity: high
    only_if: command -v doveconf
    run: |
      # doveconf prints unknown settings as empty, so try the 2.4 name first.
      v=$(doveconf -h auth_allow_cleartext 2>/dev/null || true)
      if [ -n "$v" ]; then
        [ "$v" = no ] && echo ok || echo "auth_allow_cleartext = $v"
      else
        v=$(doveconf -h disable_plaintext_auth 2>/dev/null || true)
        [ "$v" = yes ] && echo ok || echo "disable_plaintext_auth = $v"
      fi
    expect: "== ok"

  - id: DOVECOT-PRIVATE-KEY
    name: The TLS private key is readable only by root
    tags: [services, mail, dovecot, tls, permissions]
    severity: high
    only_if: command -v doveconf
    run: |
      k=$(doveconf -h ssl_server_key_file 2>/dev/null || true)
      [ -n "$k" ] || k=$(doveconf -h ssl_key 2>/dev/null || true)
      k=${k#<}
      if [ -z "$k" ]; then echo "no private key configured"; exit 0; fi
      if [ ! -e "$k" ]; then echo "$k does not exist"; exit 0; fi
      stat -L -c '%a %U' "$k"
    expect: "~ ^[46][04]0 root$"

  - id: DOVECOT-PLAINTEXT-LISTENERS
    name: Clear-text IMAP and POP3 listeners are disabled
    description: Ports 143 and 110 are only acceptable if STARTTLS is enforced; listeners on 993/995 avoid the question. Lists active inet listeners on 110 and 143.
    tags: [services, mail, dovecot]
    severity: low
    only_if: command -v doveconf
    run: doveconf -n service imap-login service pop3-login 2>/dev/null | awk '/inet_listener (imap|pop3) \{/ {l = 1} l && /port = [1-9]/ {print} /\}/ {l = 0}'
    expect: empty
```
