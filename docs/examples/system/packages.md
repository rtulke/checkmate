# Packages and updates

Pending updates, forbidden and required packages, minimum versions and package integrity. A snippet with platform variants makes the package checks work on RHEL, Debian and SUSE families alike.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/system/packages.yml`](https://github.com/rtulke/checkmate/blob/main/examples/system/packages.yml)
- :material-format-list-checks: **Checks**  
  17 from 6 definitions, 3 with loops
- :material-monitor: **Platforms**  
  alpine, debian, macos, rhel, suse

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/system/packages.yml

# Run the checks
checkmate run examples/system/packages.yml

# Override a variable from the command line
checkmate run examples/system/packages.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `PKG-FORBIDDEN-telnet-server` | telnet-server is not installed | <span class="sev sev-high">high</span> | system, packages |
| `PKG-FORBIDDEN-rsh-server` | rsh-server is not installed | <span class="sev sev-high">high</span> | system, packages |
| `PKG-FORBIDDEN-ypserv` | ypserv is not installed | <span class="sev sev-high">high</span> | system, packages |
| `PKG-FORBIDDEN-tftp-server` | tftp-server is not installed | <span class="sev sev-high">high</span> | system, packages |
| `PKG-FORBIDDEN-talk-server` | talk-server is not installed | <span class="sev sev-high">high</span> | system, packages |
| `PKG-FORBIDDEN-xinetd` | xinetd is not installed | <span class="sev sev-high">high</span> | system, packages |
| `PKG-FORBIDDEN-nis` | nis is not installed | <span class="sev sev-high">high</span> | system, packages |
| `PKG-REQUIRED-sudo` | sudo is installed | <span class="sev sev-medium">medium</span> | system, packages |
| `PKG-REQUIRED-openssh-server` | openssh-server is installed | <span class="sev sev-medium">medium</span> | system, packages |
| `PKG-001` | OpenSSL is version 3.0 or newer | <span class="sev sev-high">high</span> | system, packages, crypto |
| `PKG-002` | No updates are pending | <span class="sev sev-medium">medium</span> | system, packages, updates |
| `PKG-INTEGRITY-coreutils` | Files of coreutils are unmodified | <span class="sev sev-high">high</span> | system, packages, integrity |
| `PKG-INTEGRITY-sudo` | Files of sudo are unmodified | <span class="sev sev-high">high</span> | system, packages, integrity |
| `PKG-INTEGRITY-openssh-server` | Files of openssh-server are unmodified | <span class="sev sev-high">high</span> | system, packages, integrity |
| `PKG-INTEGRITY-shadow-utils` | Files of shadow-utils are unmodified | <span class="sev sev-high">high</span> | system, packages, integrity |
| `PKG-INTEGRITY-passwd` | Files of passwd are unmodified | <span class="sev sev-high">high</span> | system, packages, integrity |
| `PKG-003` | Package signatures are verified | <span class="sev sev-high">high</span> | system, packages |

## Policy

```yaml title="examples/system/packages.yml" linenums="1"
name: Packages and updates
version: 1.0.0
description: >
  Pending updates, forbidden and required packages, minimum versions and
  package integrity. A snippet with platform variants makes the package
  checks work on RHEL, Debian and SUSE families alike.

vars:
  forbidden_packages: [telnet-server, rsh-server, ypserv, tftp-server, talk-server, xinetd, nis]
  required_packages: [sudo, openssh-server]
  min_openssl: "3.0"
  integrity_packages: [coreutils, sudo, openssh-server, shadow-utils, passwd]

snippets:
  # Exit code 0 if the package {{ arg }} is installed.
  pkg_installed:
    rhel,suse: rpm -q --quiet {{ arg }}
    debian: dpkg-query -W -f='${Status}' {{ arg }} 2>/dev/null | grep 'install ok installed' >/dev/null
    alpine: apk info -e {{ arg }} >/dev/null
    macos: brew list --formula {{ arg }} >/dev/null 2>&1

  # Prints the installed version of {{ arg }}.
  pkg_version:
    rhel,suse: rpm -q --qf '%{VERSION}' {{ arg }}
    debian: dpkg-query -W -f='${Version}' {{ arg }} | sed -E 's/^[0-9]+://; s/-[^-]*$//'
    alpine: apk info -v {{ arg }} 2>/dev/null | sed -E 's/^{{ arg }}-//; s/-r[0-9]+$//'

checks:
  - id: "PKG-FORBIDDEN-{{ item }}"
    name: "{{ item }} is not installed"
    tags: [system, packages]
    severity: high
    loop: "{{ forbidden_packages }}"
    run: { use: pkg_installed, arg: "{{ item }}" }
    expect: false
    rationale: "{{ item }} belongs to a legacy network service without encryption or sound authentication."
    remediation: "Remove the {{ item }} package."

  - id: "PKG-REQUIRED-{{ item }}"
    name: "{{ item }} is installed"
    tags: [system, packages]
    loop: "{{ required_packages }}"
    run: { use: pkg_installed, arg: "{{ item }}" }
    expect: true
    rationale: "Administration of the host relies on {{ item }}."
    remediation: "Install the {{ item }} package."

  - id: PKG-001
    name: "OpenSSL is version {{ min_openssl }} or newer"
    tags: [system, packages, crypto]
    severity: high
    run: { use: pkg_version, arg: openssl }
    as: version
    expect: ">= {{ min_openssl }}"
    rationale: Old OpenSSL release series no longer get security fixes, which leaves known TLS flaws open.
    remediation: Upgrade the openssl package, if necessary by moving to a newer distribution release.

  - id: PKG-002
    name: No updates are pending
    tags: [system, packages, updates]
    timeout: 3m
    run:
      rhel: dnf -q check-update >/dev/null; echo $?
      suse: zypper -q --non-interactive list-updates | grep -c '^v '
      debian: apt-get -s -o Debug::NoLocking=1 upgrade | grep -c '^Inst '
    allow_rc: [0, 1]
    # dnf check-update exits 100 when updates exist; the echo turns that into output.
    expect: "== 0"
    rationale: Pending updates often contain fixes for publicly known vulnerabilities.
    remediation: Install the updates with `dnf upgrade`, `apt-get upgrade` or `zypper update`.

  - id: "PKG-INTEGRITY-{{ item }}"
    name: "Files of {{ item }} are unmodified"
    tags: [system, packages, integrity]
    severity: high
    loop: "{{ integrity_packages }}"
    only_if: { use: pkg_installed, arg: "{{ item }}" }
    # Changed configuration files (marked "c") and files left out by minimal
    # installations ("missing", e.g. documentation) are accepted.
    run:
      rhel,suse: rpm -V {{ item }} | awk '$1 != "missing" && $2 != "c"'
      debian: debsums -c {{ item }} 2>/dev/null
    allow_rc: [0, 1, 2]
    expect: empty
    rationale: "A changed file of {{ item }} points to tampering or a damaged installation."
    remediation: "Investigate the listed files and reinstall {{ item }} from a trusted repository."

  - id: PKG-003
    name: Package signatures are verified
    tags: [system, packages]
    severity: high
    run:
      rhel: |
        grep -hEi '^[[:space:]]*gpgcheck[[:space:]]*=' /etc/dnf/dnf.conf /etc/yum.conf 2>/dev/null | tail -1 | tr -d '[:space:]'
      # zypp checks signatures unless gpgcheck is set explicitly.
      suse: |
        v=$(grep -hEi '^[[:space:]]*gpgcheck[[:space:]]*=' /etc/zypp/zypp.conf | tail -1 | tr -d '[:space:]')
        echo "${v:-gpgcheck=on}"
    allow_rc: [0, 1]
    expect: "~ (?i)gpgcheck=(1|true|yes|on)"
    rationale: Without signature verification a tampered package from a mirror or the network installs unnoticed.
    remediation: Set gpgcheck=1 in /etc/dnf/dnf.conf, or gpgcheck = on in /etc/zypp/zypp.conf.
```
