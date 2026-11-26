# Postfix

Security and operation of the Postfix mail server: no open relay, no information disclosure, TLS for incoming and outgoing mail, SASL only over TLS, and the mail queue. Values are read with postconf, so the effective configuration including defaults is checked. Set postfix_role to "mx" for a server that receives mail from the internet; the default "null-client" expects a server that only sends.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/services/postfix.yml`](https://github.com/rtulke/checkmate/blob/main/examples/services/postfix.yml)
- :material-format-list-checks: **Checks**  
  13 from 12 definitions, 1 with loops
- :material-monitor: **Platforms**  
  any (POSIX shell)

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/services/postfix.yml

# Run the checks
checkmate run examples/services/postfix.yml

# Override a variable from the command line
checkmate run examples/services/postfix.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `POSTFIX-CONFIG` | The Postfix configuration has no errors | <span class="sev sev-high">high</span> | services, postfix, mail |
| `POSTFIX-SERVICE` | Postfix is running | <span class="sev sev-medium">medium</span> | services, postfix, mail |
| `POSTFIX-NO-OPEN-RELAY` | Mail to foreign domains is only relayed for permitted clients | <span class="sev sev-critical">critical</span> | services, postfix, mail |
| `POSTFIX-MYNETWORKS` | mynetworks does not trust the whole internet | <span class="sev sev-critical">critical</span> | services, postfix, mail |
| `POSTFIX-LISTEN` | A send-only server listens only on loopback | <span class="sev sev-medium">medium</span> | services, postfix, mail |
| `POSTFIX-BANNER` | The SMTP banner does not name the mail software | <span class="sev sev-low">low</span> | services, postfix, mail |
| `POSTFIX-DISABLE-VRFY-COMMAND` | The VRFY command is disabled (no address harvesting) | <span class="sev sev-medium">medium</span> | services, postfix, mail |
| `POSTFIX-SMTPD-HELO-REQUIRED` | Clients must send HELO or EHLO | <span class="sev sev-medium">medium</span> | services, postfix, mail |
| `POSTFIX-TLS-INCOMING` | A receiving server offers TLS with a certificate | <span class="sev sev-high">high</span> | services, postfix, mail, tls |
| `POSTFIX-TLS-PROTOCOLS` | TLS below version 1.2 is not accepted for mandatory encryption | <span class="sev sev-medium">medium</span> | services, postfix, mail, tls |
| `POSTFIX-TLS-OUTGOING` | Outgoing mail uses TLS when the receiver offers it | <span class="sev sev-medium">medium</span> | services, postfix, mail, tls |
| `POSTFIX-SASL-TLS` | SMTP authentication is only offered over TLS | <span class="sev sev-high">high</span> | services, postfix, mail, tls |
| `POSTFIX-QUEUE` | The mail queue holds fewer than 100 messages | <span class="sev sev-low">low</span> | services, postfix, mail |

## Policy

```yaml title="examples/services/postfix.yml" linenums="1"
name: Postfix
version: 1.0.0
description: >
  Security and operation of the Postfix mail server: no open relay, no
  information disclosure, TLS for incoming and outgoing mail, SASL only
  over TLS, and the mail queue. Values are read with postconf, so the
  effective configuration including defaults is checked. Set
  postfix_role to "mx" for a server that receives mail from the internet;
  the default "null-client" expects a server that only sends.

vars:
  # null-client (sends only, listens on loopback) or mx (receives mail)
  postfix_role: null-client
  postfix_queue_max: 100

snippets:
  # Effective value of a parameter, with $variables expanded.
  postconf: postconf -xh {{ arg }}

defaults:
  when:
    - facts.os == "linux"
    - facts.is_root

checks:
  - id: POSTFIX-CONFIG
    name: The Postfix configuration has no errors
    tags: [services, postfix, mail]
    severity: high
    only_if: command -v postfix
    run: postfix check 2>&1
    allow_rc: [0, 1]
    expect: [true, empty]
    rationale: Configuration errors keep Postfix from starting or from delivering mail.
    remediation: Run `postfix check`, correct the reported problems and reload Postfix.

  - id: POSTFIX-SERVICE
    name: Postfix is running
    tags: [services, postfix, mail]
    severity: medium
    only_if: command -v postfix && command -v systemctl && test -d /run/systemd/system
    run: systemctl show -p ActiveState postfix | cut -d= -f2
    expect: "== active"
    rationale: Mail stays undelivered while Postfix is stopped.
    remediation: systemctl enable --now postfix

  - id: POSTFIX-NO-OPEN-RELAY
    name: Mail to foreign domains is only relayed for permitted clients
    description: reject_unauth_destination or defer_unauth_destination must be part of the relay or recipient restrictions; without one the server is an open relay.
    tags: [services, postfix, mail]
    severity: critical
    only_if: command -v postconf
    run: |
      postconf -xh smtpd_relay_restrictions smtpd_recipient_restrictions | tr ', ' '\n\n' | grep -xE '(reject|defer)_unauth_destination' || true
    expect: "!empty"
    rationale: An open relay is found and used by spammers, and the server ends up on blocklists.
    remediation: Add reject_unauth_destination to smtpd_relay_restrictions in main.cf and reload Postfix.

  - id: POSTFIX-MYNETWORKS
    name: mynetworks does not trust the whole internet
    tags: [services, postfix, mail]
    severity: critical
    only_if: command -v postconf
    run: { use: postconf, arg: mynetworks }
    expect: "!~ (^|[[:space:],])(0\\.0\\.0\\.0/0|\\[?::\\]?/0|\\*)([[:space:],]|$)"
    rationale: Clients in mynetworks may relay mail to any destination, so a catch-all entry makes the server an open relay.
    remediation: Limit mynetworks in main.cf to loopback and the networks of trusted clients.

  - id: POSTFIX-LISTEN
    name: A send-only server listens only on loopback
    description: For postfix_role null-client, inet_interfaces must be loopback-only.
    tags: [services, postfix, mail]
    severity: medium
    when: postfix_role == "null-client"
    only_if: command -v postconf
    run: { use: postconf, arg: inet_interfaces }
    expect: "in [loopback-only, localhost, 127.0.0.1]"
    rationale: A server that only sends mail has no reason to accept SMTP connections from the network.
    remediation: postconf -e 'inet_interfaces = loopback-only' && systemctl restart postfix

  - id: POSTFIX-BANNER
    name: The SMTP banner does not name the mail software
    tags: [services, postfix, mail]
    severity: low
    only_if: command -v postconf
    run: postconf -h smtpd_banner
    expect: "!~ (?i)(\\$mail_name|\\$mail_version|postfix)"
    rationale: Software name and version in the banner tell an attacker which known vulnerabilities to try.
    remediation: Set smtpd_banner in main.cf to `$myhostname ESMTP`.

  - id: "POSTFIX-{{ item.key | upper | replace('_', '-') }}"
    name: "{{ item.value.name }}"
    tags: [services, postfix, mail]
    severity: medium
    only_if: command -v postconf
    loop:
      disable_vrfy_command: { name: The VRFY command is disabled (no address harvesting), expect: "== yes" }
      smtpd_helo_required: { name: Clients must send HELO or EHLO, expect: "== yes" }
    run: { use: postconf, arg: "{{ item.key }}" }
    expect: "{{ item.value.expect }}"
    rationale: "Without {{ item.key }} the server confirms which addresses exist or accepts clients that skip the SMTP greeting, as spam software often does."
    remediation: "postconf -e '{{ item.key }} = yes' && systemctl reload postfix"

  - id: POSTFIX-TLS-INCOMING
    name: A receiving server offers TLS with a certificate
    tags: [services, postfix, mail, tls]
    severity: high
    when: postfix_role == "mx"
    only_if: command -v postconf
    run: |
      level=$(postconf -xh smtpd_tls_security_level)
      cert=$(postconf -xh smtpd_tls_cert_file smtpd_tls_chain_files | tr -d '\n')
      echo "level=$level cert=${cert:-none}"
    expect:
      - "~ level=(may|encrypt)"
      - "!~ cert=none$"
    rationale: Without TLS on the receiving side incoming mail crosses the internet in clear text.
    remediation: Set smtpd_tls_security_level = may in main.cf and configure the certificate with smtpd_tls_cert_file and smtpd_tls_key_file.

  - id: POSTFIX-TLS-PROTOCOLS
    name: TLS below version 1.2 is not accepted for mandatory encryption
    tags: [services, postfix, mail, tls]
    severity: medium
    only_if: command -v postconf
    run: |
      for p in smtpd_tls_mandatory_protocols smtp_tls_mandatory_protocols; do
        v=$(postconf -xh "$p")
        toks=$(echo "$v" | tr ', :' '\n\n\n' | grep -v '^$' || true)
        if echo "$toks" | grep -xE '>=TLSv1\.[23]' >/dev/null; then continue; fi
        if echo "$toks" | grep -x '!TLSv1' >/dev/null && echo "$toks" | grep -x '!TLSv1.1' >/dev/null; then continue; fi
        if [ -n "$toks" ] && ! echo "$toks" | grep -vE '^TLSv1\.[23]$' >/dev/null; then continue; fi
        echo "$p = $v"
      done
    expect: empty
    rationale: SSLv3, TLS 1.0 and TLS 1.1 have known weaknesses and are deprecated.
    remediation: Set smtpd_tls_mandatory_protocols and smtp_tls_mandatory_protocols to `>=TLSv1.2` in main.cf.

  - id: POSTFIX-TLS-OUTGOING
    name: Outgoing mail uses TLS when the receiver offers it
    tags: [services, postfix, mail, tls]
    severity: medium
    only_if: command -v postconf
    run: { use: postconf, arg: smtp_tls_security_level }
    expect: "in [may, encrypt, dane, dane-only, verify, secure]"
    rationale: Without opportunistic TLS outgoing mail crosses the network in clear text even when the receiver supports encryption.
    remediation: postconf -e 'smtp_tls_security_level = may' && systemctl reload postfix

  - id: POSTFIX-SASL-TLS
    name: SMTP authentication is only offered over TLS
    tags: [services, postfix, mail, tls]
    severity: high
    only_if: command -v postconf
    run: |
      if [ "$(postconf -xh smtpd_sasl_auth_enable)" = yes ] && [ "$(postconf -xh smtpd_tls_auth_only)" != yes ]; then
        echo "smtpd_sasl_auth_enable = yes without smtpd_tls_auth_only = yes"
      fi
    expect: empty
    rationale: SMTP authentication without TLS sends the password in a form that anyone on the network path can read.
    remediation: Set smtpd_tls_auth_only = yes in main.cf and reload Postfix.

  - id: POSTFIX-QUEUE
    name: "The mail queue holds fewer than {{ postfix_queue_max }} messages"
    tags: [services, postfix, mail]
    severity: low
    only_if: command -v postqueue && postqueue -j >/dev/null 2>&1
    run: postqueue -j | grep -c . || true
    expect: "< {{ postfix_queue_max }}"
    rationale: A growing queue means that mail is not being delivered or that the server is sending spam.
    remediation: Inspect the queue with `postqueue -p`, fix the delivery problem and flush the queue with `postqueue -f`.
```
