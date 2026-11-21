# NFS server

Exports of an NFS server: no export to everyone, no root access for clients (no_root_squash), no unprivileged client ports, Kerberos instead of trusting client UIDs, NFSv4 only, and the permissions of the export files. Reads /etc/exports and /etc/exports.d/*.exports.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/services/nfs.yml`](https://github.com/rtulke/checkmate/blob/main/examples/services/nfs.yml)
- :material-format-list-checks: **Checks**  
  7 from 6 definitions, 1 with loops
- :material-monitor: **Platforms**  
  any (POSIX shell)

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/services/nfs.yml

# Run the checks
checkmate run examples/services/nfs.yml
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `NFS-SERVICE` | The NFS server is running | <span class="sev sev-medium">medium</span> | services, nfs |
| `NFS-NO-WORLD-EXPORT` | No directory is exported to every host | <span class="sev sev-critical">critical</span> | services, nfs |
| `NFS-NO-NO-ROOT-SQUASH` | Clients cannot act as root on exports (no no_root_squash) | <span class="sev sev-high">high</span> | services, nfs |
| `NFS-NO-INSECURE` | Clients must use privileged ports (no insecure option) | <span class="sev sev-high">high</span> | services, nfs |
| `NFS-KERBEROS` | Exports use Kerberos instead of trusting client user IDs | <span class="sev sev-low">low</span> | services, nfs |
| `NFS-V4-ONLY` | Only NFS version 4 is served | <span class="sev sev-low">low</span> | services, nfs |
| `NFS-EXPORTS-PERMS` | Export files are owned by root and not writable by others | <span class="sev sev-high">high</span> | services, nfs, permissions |

## Policy

```yaml title="examples/services/nfs.yml" linenums="1"
name: NFS server
version: 1.0.0
description: >
  Exports of an NFS server: no export to everyone, no root access for
  clients (no_root_squash), no unprivileged client ports, Kerberos instead
  of trusting client UIDs, NFSv4 only, and the permissions of the export
  files. Reads /etc/exports and /etc/exports.d/*.exports.

defaults:
  when:
    - facts.os == "linux"
    - facts.is_root

checks:
  - id: NFS-SERVICE
    name: The NFS server is running
    tags: [services, nfs]
    severity: medium
    only_if: test -s /etc/exports && command -v systemctl && test -d /run/systemd/system
    run: |
      for u in nfs-server nfs-kernel-server; do
        s=$(systemctl show -p ActiveState "$u" 2>/dev/null | cut -d= -f2)
        if [ "$s" = active ]; then echo active; exit 0; fi
      done
      echo inactive
    expect: "== active"

  - id: NFS-NO-WORLD-EXPORT
    name: No directory is exported to every host
    description: A client of "*", 0.0.0.0/0 or no client at all allows any host to mount the export.
    tags: [services, nfs]
    severity: critical
    only_if: test -e /etc/exports
    run: |
      { cat /etc/exports /etc/exports.d/*.exports 2>/dev/null || true; } | sed -e 's/#.*//' -e '/^[[:space:]]*$/d' |
        awk '{ if (NF == 1) { print $1 ": no client given"; next }
               for (i = 2; i <= NF; i++) { c = $i; sub(/\(.*/, "", c); if (c == "*" || c == "" || c ~ /^(0\.0\.0\.0\/0|::\/0)$/) print $1 ": " $i } }'
    expect: empty

  - id: "NFS-NO-{{ item.key | upper | replace('_', '-') }}"
    name: "{{ item.value }}"
    tags: [services, nfs]
    severity: high
    only_if: test -e /etc/exports
    loop:
      no_root_squash: Clients cannot act as root on exports (no no_root_squash)
      insecure: Clients must use privileged ports (no insecure option)
    run: |
      { cat /etc/exports /etc/exports.d/*.exports 2>/dev/null || true; } | sed -e 's/#.*//' | grep -E '[(,]{{ item.key }}[,)]' || true
    expect: empty

  - id: NFS-KERBEROS
    name: Exports use Kerberos instead of trusting client user IDs
    description: With sec=sys the server trusts whatever UID a client sends; sec=krb5, krb5i or krb5p authenticates users.
    tags: [services, nfs]
    severity: low
    only_if: test -s /etc/exports
    run: |
      { cat /etc/exports /etc/exports.d/*.exports 2>/dev/null || true; } | sed -e 's/#.*//' -e '/^[[:space:]]*$/d' |
        awk '{ for (i = 2; i <= NF; i++) if ($i !~ /sec=krb5/) print $1 ": " $i }'
    expect: empty

  - id: NFS-V4-ONLY
    name: Only NFS version 4 is served
    description: NFSv3 needs rpcbind and mountd and trusts client UIDs without locking down the protocol.
    tags: [services, nfs]
    severity: low
    only_if: test -s /etc/exports && command -v nfsconf
    run: |
      for v in vers2 vers3; do
        [ "$(nfsconf --get nfsd "$v" 2>/dev/null)" = n ] || echo "$v is not disabled in nfs.conf"
      done
    expect: empty

  - id: NFS-EXPORTS-PERMS
    name: Export files are owned by root and not writable by others
    tags: [services, nfs, permissions]
    severity: high
    only_if: test -e /etc/exports
    run: find -H /etc/exports /etc/exports.d \( ! -user root -o -perm /022 \) -print 2>/dev/null || true
    expect: empty
```
