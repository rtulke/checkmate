# Samba

Security of a Samba file server: valid configuration, SMB 2.1 or newer, NTLMv2 only, signing and encryption, no guest access and no shares writable by everyone. Values come from testparm, so defaults count.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/services/samba.yml`](https://github.com/rtulke/checkmate/blob/main/examples/services/samba.yml)
- :material-format-list-checks: **Checks**  
  10 from 5 definitions, 1 with loops
- :material-monitor: **Platforms**  
  any (POSIX shell)

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/services/samba.yml

# Run the checks
checkmate run examples/services/samba.yml
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `SAMBA-CONFIG` | The Samba configuration is valid | <span class="sev sev-high">high</span> | services, samba, smb |
| `SAMBA-SERVICE` | Samba is running | <span class="sev sev-medium">medium</span> | services, samba, smb |
| `SAMBA-SERVER-MIN-PROTOCOL` | SMB1 and SMB 2.0 are disabled | <span class="sev sev-high">high</span> | services, samba, smb |
| `SAMBA-NTLM-AUTH` | Only NTLMv2 or Kerberos is accepted | <span class="sev sev-high">high</span> | services, samba, smb |
| `SAMBA-SERVER-SIGNING` | SMB signing is required | <span class="sev sev-medium">medium</span> | services, samba, smb |
| `SAMBA-SERVER-SMB-ENCRYPT` | SMB encryption is offered or required | <span class="sev sev-low">low</span> | services, samba, smb |
| `SAMBA-MAP-TO-GUEST` | Failed logins are not mapped to the guest account | <span class="sev sev-medium">medium</span> | services, samba, smb |
| `SAMBA-RESTRICT-ANONYMOUS` | Anonymous users cannot list users and shares | <span class="sev sev-medium">medium</span> | services, samba, smb |
| `SAMBA-GUEST-SHARES` | No share allows guest access | <span class="sev sev-high">high</span> | services, samba, smb |
| `SAMBA-WORLD-WRITABLE-SHARES` | No share path is writable by every user | <span class="sev sev-high">high</span> | services, samba, smb, permissions |

## Policy

```yaml title="examples/services/samba.yml" linenums="1"
name: Samba
version: 1.0.0
description: >
  Security of a Samba file server: valid configuration, SMB 2.1 or newer,
  NTLMv2 only, signing and encryption, no guest access and no shares
  writable by everyone. Values come from testparm, so defaults count.

defaults:
  when:
    - facts.os == "linux"
    - facts.is_root

snippets:
  # Effective value of a global parameter.
  global: testparm -s -d0 --parameter-name="{{ arg }}" 2>/dev/null

checks:
  - id: SAMBA-CONFIG
    name: The Samba configuration is valid
    tags: [services, samba, smb]
    severity: high
    only_if: command -v testparm
    run: testparm -s -d0 >/dev/null 2>&1
    expect: true

  - id: SAMBA-SERVICE
    name: Samba is running
    tags: [services, samba, smb]
    severity: medium
    only_if: command -v testparm && command -v systemctl && test -d /run/systemd/system
    run: |
      for u in smb smbd; do
        if [ "$(systemctl show -p ActiveState "$u" 2>/dev/null | cut -d= -f2)" = active ]; then echo active; exit 0; fi
      done
      echo inactive
    expect: "== active"

  - id: "SAMBA-{{ item.key | upper | replace(' ', '-') }}"
    name: "{{ item.value.name }}"
    tags: [services, samba, smb]
    severity: "{{ item.value.severity }}"
    only_if: command -v testparm
    loop:
      server min protocol: { name: SMB1 and SMB 2.0 are disabled, expect: "in [SMB2_10, SMB2_22, SMB2_24, SMB3, SMB3_00, SMB3_02, SMB3_10, SMB3_11]", severity: high }
      ntlm auth: { name: Only NTLMv2 or Kerberos is accepted, expect: "in [ntlmv2-only, disabled, mschapv2-and-ntlmv2-only, No]", severity: high }
      server signing: { name: SMB signing is required, expect: "in [mandatory, required]", severity: medium }
      server smb encrypt: { name: SMB encryption is offered or required, expect: "in [desired, required, mandatory, if_required]", severity: low }
      map to guest: { name: Failed logins are not mapped to the guest account, expect: "== Never", severity: medium }
      restrict anonymous: { name: Anonymous users cannot list users and shares, expect: "== 2", severity: medium }
    run: { use: global, arg: "{{ item.key }}" }
    expect: "{{ item.value.expect }}"

  - id: SAMBA-GUEST-SHARES
    name: No share allows guest access
    tags: [services, samba, smb]
    severity: high
    only_if: command -v testparm
    run: |
      testparm -s -d0 2>/dev/null | awk '
        /^\[/ {share = $0}
        tolower($0) ~ /^[[:space:]]*(guest ok|public)[[:space:]]*=[[:space:]]*yes/ {print share}'
    expect: empty

  - id: SAMBA-WORLD-WRITABLE-SHARES
    name: No share path is writable by every user
    tags: [services, samba, smb, permissions]
    severity: high
    only_if: command -v testparm
    run: |
      testparm -s -d0 2>/dev/null | awk -F'= ' '/^[[:space:]]*path = / {print $2}' | while read -r p; do
        if [ -d "$p" ] && find "$p" -maxdepth 0 -perm -0002 ! -perm -1000 | grep . >/dev/null; then echo "$p is world-writable without sticky bit"; fi
      done
    expect: empty
```
