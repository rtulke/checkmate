# OpenSSH server

Hardening of sshd based on its effective configuration (`sshd -T`), which already resolves Include files, defaults and the case-insensitive, first-value-wins semantics of sshd_config. `sshd -T` needs root.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/system/ssh.yml`](https://github.com/rtulke/checkmate/blob/main/examples/system/ssh.yml)
- :material-format-list-checks: **Checks**  
  17 from 10 definitions, 1 with loops
- :material-monitor: **Platforms**  
  debian, linux

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/system/ssh.yml

# Run the checks
checkmate run examples/system/ssh.yml

# Override a variable from the command line
checkmate run examples/system/ssh.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `SSH-CFG-ALLOWAGENTFORWARDING` | sshd: allowagentforwarding is no | <span class="sev sev-high">high</span> | system, ssh |
| `SSH-CFG-GSSAPIAUTHENTICATION` | sshd: gssapiauthentication is no | <span class="sev sev-high">high</span> | system, ssh |
| `SSH-CFG-HOSTBASEDAUTHENTICATION` | sshd: hostbasedauthentication is no | <span class="sev sev-high">high</span> | system, ssh |
| `SSH-CFG-IGNORERHOSTS` | sshd: ignorerhosts is yes | <span class="sev sev-high">high</span> | system, ssh |
| `SSH-CFG-PERMITEMPTYPASSWORDS` | sshd: permitemptypasswords is no | <span class="sev sev-high">high</span> | system, ssh |
| `SSH-CFG-PERMITROOTLOGIN` | sshd: permitrootlogin is no | <span class="sev sev-high">high</span> | system, ssh |
| `SSH-CFG-PERMITUSERENVIRONMENT` | sshd: permituserenvironment is no | <span class="sev sev-high">high</span> | system, ssh |
| `SSH-CFG-X11FORWARDING` | sshd: x11forwarding is no | <span class="sev sev-high">high</span> | system, ssh |
| `SSH-001` | sshd allows at most 4 authentication attempts | <span class="sev sev-medium">medium</span> | system, ssh |
| `SSH-002` | Login grace time is at most 60 seconds | <span class="sev sev-low">low</span> | system, ssh |
| `SSH-003` | No weak ciphers | <span class="sev sev-high">high</span> | system, ssh, crypto |
| `SSH-004` | No weak MACs | <span class="sev sev-high">high</span> | system, ssh, crypto |
| `SSH-005` | No weak key exchange algorithms | <span class="sev sev-high">high</span> | system, ssh, crypto |
| `SSH-006` | sshd logs at INFO or VERBOSE | <span class="sev sev-low">low</span> | system, ssh, logging |
| `SSH-007` | Private host keys are not readable by others | <span class="sev sev-high">high</span> | system, ssh, files |
| `SSH-008` | The SSH service is running | <span class="sev sev-medium">medium</span> | system, ssh, services |
| `SSH-009` | root has only approved SSH keys | <span class="sev sev-critical">critical</span> | system, ssh, users |

## Policy

```yaml title="examples/system/ssh.yml" linenums="1"
name: OpenSSH server
version: 1.0.0
description: >
  Hardening of sshd based on its effective configuration (`sshd -T`), which
  already resolves Include files, defaults and the case-insensitive,
  first-value-wins semantics of sshd_config. `sshd -T` needs root.

vars:
  # Expected values of sshd -T (keys are lowercase there).
  sshd_settings:
    permitrootlogin: "no"
    permitemptypasswords: "no"
    hostbasedauthentication: "no"
    ignorerhosts: "yes"
    permituserenvironment: "no"
    x11forwarding: "no"
    allowagentforwarding: "no"
    gssapiauthentication: "no"
  max_auth_tries: 4
  max_login_grace_seconds: 60
  trusted_root_keys:
    - "SHA256:REPLACE_WITH_YOUR_KEY_FINGERPRINT"

checks:
  - id: "SSH-CFG-{{ item.key | upper }}"
    name: "sshd: {{ item.key }} is {{ item.value }}"
    tags: [system, ssh]
    severity: high
    when: facts.is_root
    only_if: command -v sshd
    loop: "{{ sshd_settings }}"
    run: |
      sshd -T 2>/dev/null | awk -v key={{ item.key }} '$1 == key {print $2}'
    expect: "== {{ item.value }}"
    rationale: "Any other value of {{ item.key }} opens a login or forwarding path that a hardened server does not offer."
    remediation: "Set {{ item.key }} to {{ item.value }} in /etc/ssh/sshd_config and reload sshd."

  - id: SSH-001
    name: "sshd allows at most {{ max_auth_tries }} authentication attempts"
    tags: [system, ssh]
    when: facts.is_root
    only_if: command -v sshd
    run: |
      sshd -T 2>/dev/null | awk '$1 == "maxauthtries" {print $2}'
    expect: "<= {{ max_auth_tries }}"
    rationale: Many attempts per connection speed up password guessing.
    remediation: "Set MaxAuthTries {{ max_auth_tries }} in /etc/ssh/sshd_config and reload sshd."

  - id: SSH-002
    name: "Login grace time is at most {{ max_login_grace_seconds }} seconds"
    tags: [system, ssh]
    severity: low
    when: facts.is_root
    only_if: command -v sshd
    run: |
      sshd -T 2>/dev/null | awk '$1 == "logingracetime" {print $2}'
    expect: ["> 0", "<= {{ max_login_grace_seconds }}"]
    rationale: Connections that stay unauthenticated for a long time occupy connection slots and can block legitimate logins.
    remediation: "Set LoginGraceTime {{ max_login_grace_seconds }} in /etc/ssh/sshd_config and reload sshd."

  - id: SSH-003
    name: No weak ciphers
    tags: [system, ssh, crypto]
    severity: high
    when: facts.is_root
    only_if: command -v sshd
    run: |
      sshd -T 2>/dev/null | awk '$1 == "ciphers" {print $2}'
    expect: ["!empty", "!~ (cbc|arcfour|3des|blowfish)"]
    rationale: CBC mode, arcfour, 3DES and Blowfish ciphers have known cryptographic weaknesses.
    remediation: Restrict Ciphers in /etc/ssh/sshd_config to AES-GCM, AES-CTR and ChaCha20-Poly1305 and reload sshd.

  - id: SSH-004
    name: No weak MACs
    tags: [system, ssh, crypto]
    severity: high
    when: facts.is_root
    only_if: command -v sshd
    run: |
      sshd -T 2>/dev/null | awk '$1 == "macs" {print $2}'
    expect: ["!empty", "!~ (md5|-96|umac-64[@-])"]
    rationale: MACs based on MD5, truncated to 96 bits or with 64-bit tags give weak integrity protection.
    remediation: Restrict MACs in /etc/ssh/sshd_config to SHA-2 based algorithms and reload sshd.

  - id: SSH-005
    name: No weak key exchange algorithms
    tags: [system, ssh, crypto]
    severity: high
    when: facts.is_root
    only_if: command -v sshd
    run: |
      sshd -T 2>/dev/null | awk '$1 == "kexalgorithms" {print $2}'
    expect: ["!empty", "!~ (group1-|group14-sha1|group-exchange-sha1)"]
    rationale: Key exchanges that use SHA-1 or the 1024-bit Diffie-Hellman group 1 no longer give adequate security.
    remediation: Remove the group1, group14-sha1 and group-exchange-sha1 methods from KexAlgorithms in /etc/ssh/sshd_config and reload sshd.

  - id: SSH-006
    name: sshd logs at INFO or VERBOSE
    tags: [system, ssh, logging]
    severity: low
    when: facts.is_root
    only_if: command -v sshd
    run: |
      sshd -T 2>/dev/null | awk '$1 == "loglevel" {print $2}'
    expect: "in [INFO, VERBOSE]"
    rationale: Lower levels omit login events, and the DEBUG levels write private user data to the log.
    remediation: Set LogLevel INFO or LogLevel VERBOSE in /etc/ssh/sshd_config and reload sshd.

  - id: SSH-007
    name: Private host keys are not readable by others
    tags: [system, ssh, files]
    severity: high
    run: |
      find /etc/ssh -name 'ssh_host_*_key' \( -perm /o+rwx -o -perm /g+w \) 2>/dev/null
    allow_rc: [0, 1]
    expect: empty
    rationale: Anyone who can read a private host key can impersonate the server.
    remediation: chmod o-rwx,g-w /etc/ssh/ssh_host_*_key

  - id: SSH-008
    name: The SSH service is running
    tags: [system, ssh, services]
    when: facts.os == "linux"
    run:
      debian: systemctl is-active ssh
      linux: systemctl is-active sshd
    expect: "== active"
    rationale: Without a running SSH service the host cannot be administered remotely.
    remediation: Start the service with `systemctl enable --now sshd` (`ssh` on Debian).

  # Fingerprints of root's authorized keys must all be on the allowlist.
  - id: SSH-009
    name: root has only approved SSH keys
    tags: [system, ssh, users]
    severity: critical
    when: facts.is_root
    only_if: test -s /root/.ssh/authorized_keys
    run: |
      ssh-keygen -lf /root/.ssh/authorized_keys | awk '{print $2}' |
        grep -vxF {% for key in trusted_root_keys %}-e '{{ key }}' {% endfor %}
    allow_rc: [0, 1]
    expect: empty
    rationale: Every key in root's authorized_keys gives full control of the host, and attackers add keys there to keep access.
    remediation: Remove unknown keys from /root/.ssh/authorized_keys or add their fingerprints to trusted_root_keys.
```
