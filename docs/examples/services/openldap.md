# OpenLDAP

Security of an OpenLDAP server (slapd) configured through cn=config: TLS with TLS 1.2 or newer, encryption required, no anonymous binds, hashed passwords, protected userPassword attributes and an unprivileged process. Reads cn=config as root over ldapi:/// with SASL EXTERNAL.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/services/openldap.yml`](https://github.com/rtulke/checkmate/blob/main/examples/services/openldap.yml)
- :material-format-list-checks: **Checks**  
  8 from 8 definitions
- :material-monitor: **Platforms**  
  any (POSIX shell)

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/services/openldap.yml

# Run the checks
checkmate run examples/services/openldap.yml

# Override a variable from the command line
checkmate run examples/services/openldap.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `LDAP-CONFIG-ACCESS` | The slapd configuration can be read over ldapi | <span class="sev sev-info">info</span> | services, ldap, openldap |
| `LDAP-TLS-CERTIFICATE` | slapd has a TLS certificate | <span class="sev sev-high">high</span> | services, ldap, openldap, tls |
| `LDAP-TLS-PROTOCOL` | TLS 1.2 or newer is required | <span class="sev sev-medium">medium</span> | services, ldap, openldap, tls |
| `LDAP-REQUIRE-ENCRYPTION` | Connections must be encrypted | <span class="sev sev-high">high</span> | services, ldap, openldap, tls |
| `LDAP-NO-ANONYMOUS-BIND` | Anonymous binds are disabled | <span class="sev sev-high">high</span> | services, ldap, openldap |
| `LDAP-PASSWORD-HASH` | Passwords are stored hashed | <span class="sev sev-high">high</span> | services, ldap, openldap |
| `LDAP-USERPASSWORD-ACL` | userPassword is not readable by other users | <span class="sev sev-critical">critical</span> | services, ldap, openldap |
| `LDAP-USER` | slapd does not run as root | <span class="sev sev-high">high</span> | services, ldap, openldap |

## Policy

```yaml title="examples/services/openldap.yml" linenums="1"
name: OpenLDAP
version: 1.0.0
description: >
  Security of an OpenLDAP server (slapd) configured through cn=config:
  TLS with TLS 1.2 or newer, encryption required, no anonymous binds,
  hashed passwords, protected userPassword attributes and an unprivileged
  process. Reads cn=config as root over ldapi:/// with SASL EXTERNAL.

vars:
  # ldapsearch on cn=config as root
  ldap_config: ldapsearch -LLL -Q -o ldif-wrap=no -Y EXTERNAL -H ldapi:/// -b cn=config

defaults:
  when:
    - facts.os == "linux"
    - facts.is_root

checks:
  - id: LDAP-CONFIG-ACCESS
    name: The slapd configuration can be read over ldapi
    description: Precondition for the other checks.
    tags: [services, ldap, openldap]
    severity: info
    only_if: command -v slapd && command -v ldapsearch && pgrep -x slapd
    run: "{{ ldap_config }} -s base dn"
    expect: "~ ^dn: cn=config"

  - id: LDAP-TLS-CERTIFICATE
    name: slapd has a TLS certificate
    tags: [services, ldap, openldap, tls]
    severity: high
    only_if: pgrep -x slapd && command -v ldapsearch
    run: "{{ ldap_config }} -s base olcTLSCertificateFile"
    expect: { some: "~ ^olcTLSCertificateFile: ." }

  - id: LDAP-TLS-PROTOCOL
    name: TLS 1.2 or newer is required
    description: olcTLSProtocolMin 3.3 is TLS 1.2, 3.4 is TLS 1.3.
    tags: [services, ldap, openldap, tls]
    severity: medium
    only_if: pgrep -x slapd && command -v ldapsearch
    run: "{{ ldap_config }} -s base olcTLSProtocolMin"
    expect: { some: "~ ^olcTLSProtocolMin: 3\\.[34]" }

  - id: LDAP-REQUIRE-ENCRYPTION
    name: Connections must be encrypted
    description: olcSecurity with tls or ssf of at least 128 rejects operations over unencrypted connections.
    tags: [services, ldap, openldap, tls]
    severity: high
    only_if: pgrep -x slapd && command -v ldapsearch
    run: "{{ ldap_config }} -s base olcSecurity"
    expect: { some: "~ ^olcSecurity: .*(ssf|tls)=(12[89]|1[3-9][0-9]|[2-9][0-9]{2})" }

  - id: LDAP-NO-ANONYMOUS-BIND
    name: Anonymous binds are disabled
    tags: [services, ldap, openldap]
    severity: high
    only_if: pgrep -x slapd && command -v ldapsearch
    run: "{{ ldap_config }} -s base olcDisallows olcRequires"
    expect: { some: "~ ^(olcDisallows: .*bind_anon|olcRequires: .*authc)" }

  - id: LDAP-PASSWORD-HASH
    name: Passwords are stored hashed
    tags: [services, ldap, openldap]
    severity: high
    only_if: pgrep -x slapd && command -v ldapsearch
    run: "{{ ldap_config }} olcPasswordHash"
    expect: { none: "~ (?i)olcPasswordHash: .*\\{(CLEARTEXT|MD5|SMD5|CRYPT)\\}" }

  - id: LDAP-USERPASSWORD-ACL
    name: userPassword is not readable by other users
    description: Every database with an ACL on userPassword must give others at most auth access.
    tags: [services, ldap, openldap]
    severity: critical
    only_if: pgrep -x slapd && command -v ldapsearch
    run: |
      {{ ldap_config }} '(olcSuffix=*)' olcAccess | grep -i 'userPassword' || echo "no ACL for userPassword"
    expect:
      - { none: "~ ^no ACL" }
      - { none: "~ (?i)by \\* (read|write|manage|search)" }

  - id: LDAP-USER
    name: slapd does not run as root
    tags: [services, ldap, openldap]
    severity: high
    only_if: pgrep -x slapd
    run: ps -o user= -C slapd | sort -u
    expect:
      - "!empty"
      - { none: "== root" }
```
