# Cloud instances

Security of cloud virtual machines from the inside: the instance metadata service (a common target for credential theft through SSRF), the cloud agents, and leftover credentials on disk. Every check first detects its cloud with `only_if`, so the policy runs unchanged on AWS, Azure, Google Cloud and on-premises machines.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/cloud/instance-metadata.yml`](https://github.com/rtulke/checkmate/blob/main/examples/cloud/instance-metadata.yml)
- :material-format-list-checks: **Checks**  
  9 from 9 definitions
- :material-monitor: **Platforms**  
  any (POSIX shell)

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/cloud/instance-metadata.yml

# Run the checks
checkmate run examples/cloud/instance-metadata.yml
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `CLOUD-AWS-IMDSV2` | AWS: the metadata service requires IMDSv2 session tokens | <span class="sev sev-high">high</span> | cloud, aws, metadata |
| `CLOUD-AWS-SSM` | AWS: the Systems Manager agent is running | <span class="sev sev-low">low</span> | cloud, aws, agents |
| `CLOUD-AZURE-AGENT` | Azure: the Linux guest agent is running | <span class="sev sev-medium">medium</span> | cloud, azure, agents |
| `CLOUD-AZURE-IMDS-USERS` | Azure: only root can reach the metadata service | <span class="sev sev-low">low</span> | cloud, azure, metadata |
| `CLOUD-GCP-AGENT` | Google Cloud: the guest agent is running | <span class="sev sev-medium">medium</span> | cloud, gcp, agents |
| `CLOUD-GCP-OSLOGIN` | Google Cloud: OS Login manages SSH access | <span class="sev sev-medium">medium</span> | cloud, gcp, ssh |
| `CLOUD-CREDENTIAL-FILES` | No cloud credential files in home directories | <span class="sev sev-critical">critical</span> | cloud, credentials |
| `CLOUD-INIT-USERDATA` | cloud-init user data contains no secrets | <span class="sev sev-high">high</span> | cloud, credentials |
| `CLOUD-INIT-LOGS` | cloud-init logs are not readable by everyone | <span class="sev sev-medium">medium</span> | cloud, credentials, permissions |

## Policy

```yaml title="examples/cloud/instance-metadata.yml" linenums="1"
name: Cloud instances
version: 1.0.0
description: >
  Security of cloud virtual machines from the inside: the instance metadata
  service (a common target for credential theft through SSRF), the cloud
  agents, and leftover credentials on disk. Every check first detects its
  cloud with `only_if`, so the policy runs unchanged on AWS, Azure, Google
  Cloud and on-premises machines.

defaults:
  when: facts.os == "linux"

snippets:
  # Exit code 0 if the instance runs on the given cloud (DMI vendor data).
  on_cloud: grep -qiE '{{ arg }}' /sys/class/dmi/id/sys_vendor /sys/class/dmi/id/product_name /sys/class/dmi/id/bios_vendor /sys/class/dmi/id/chassis_asset_tag 2>/dev/null

checks:
  # --- AWS ---------------------------------------------------------------------
  - id: CLOUD-AWS-IMDSV2
    name: "AWS: the metadata service requires IMDSv2 session tokens"
    tags: [cloud, aws, metadata]
    severity: high
    only_if: { use: on_cloud, arg: "amazon|ec2" }
    # Without a token, IMDSv2-only instances answer 401.
    run: curl -s -o /dev/null --max-time 3 -w '%{http_code}' http://169.254.169.254/latest/meta-data/
    allow_rc: [0, 7, 28]
    expect: "in [401, 000]"
    remediation: aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required

  - id: CLOUD-AWS-SSM
    name: "AWS: the Systems Manager agent is running"
    tags: [cloud, aws, agents]
    severity: low
    only_if: { use: on_cloud, arg: "amazon|ec2" }
    run: systemctl is-active amazon-ssm-agent snap.amazon-ssm-agent.amazon-ssm-agent.service 2>/dev/null
    allow_rc: [0, 3, 4]
    expect: { some: "== active" }

  # --- Azure -------------------------------------------------------------------
  - id: CLOUD-AZURE-AGENT
    name: "Azure: the Linux guest agent is running"
    tags: [cloud, azure, agents]
    only_if: { use: on_cloud, arg: "microsoft corporation|7783-7084-3265-9085-8269-3286-77" }
    run: systemctl is-active walinuxagent waagent 2>/dev/null
    allow_rc: [0, 3, 4]
    expect: { some: "== active" }

  - id: CLOUD-AZURE-IMDS-USERS
    name: "Azure: only root can reach the metadata service"
    tags: [cloud, azure, metadata]
    severity: low
    only_if: { use: on_cloud, arg: "microsoft corporation|7783-7084-3265-9085-8269-3286-77" }
    # A firewall rule that limits 169.254.169.254 to root is a common hardening step.
    run: |
      { iptables -S OUTPUT 2>/dev/null; nft list ruleset 2>/dev/null; } | grep -E '169\.254\.169\.254'
    allow_rc: [0, 1]
    expect: { lines: ">= 1" }

  # --- Google Cloud --------------------------------------------------------------
  - id: CLOUD-GCP-AGENT
    name: "Google Cloud: the guest agent is running"
    tags: [cloud, gcp, agents]
    only_if: { use: on_cloud, arg: "google" }
    run: systemctl is-active google-guest-agent 2>/dev/null
    allow_rc: [0, 3, 4]
    expect: "== active"

  - id: CLOUD-GCP-OSLOGIN
    name: "Google Cloud: OS Login manages SSH access"
    tags: [cloud, gcp, ssh]
    only_if: { use: on_cloud, arg: "google" }
    run: grep -c 'oslogin' /etc/nsswitch.conf
    allow_rc: [0, 1]
    expect: ">= 1"

  # --- Every cloud -------------------------------------------------------------------
  - id: CLOUD-CREDENTIAL-FILES
    name: No cloud credential files in home directories
    tags: [cloud, credentials]
    severity: critical
    run: |
      find /root /home -maxdepth 3 -type f \( -path '*/.aws/credentials' -o -path '*/.azure/accessTokens.json' \
        -o -path '*/.azure/msal_token_cache.json' -o -path '*/.config/gcloud/credentials.db' \
        -o -path '*/.config/gcloud/application_default_credentials.json' \) 2>/dev/null
    allow_rc: [0, 1]
    expect: empty
    remediation: Use instance roles / managed identities instead of stored credentials.

  - id: CLOUD-INIT-USERDATA
    name: cloud-init user data contains no secrets
    tags: [cloud, credentials]
    severity: high
    when: facts.is_root
    only_if: test -d /var/lib/cloud/instance
    run: |
      cat /var/lib/cloud/instance/user-data.txt /var/lib/cloud/instance/user-data.txt.i 2>/dev/null |
        grep -iE '(password|passwd|secret|token|aws_secret_access_key|private_key)[[:space:]]*[:=]'
    allow_rc: [0, 1]
    expect: empty

  - id: CLOUD-INIT-LOGS
    name: cloud-init logs are not readable by everyone
    tags: [cloud, credentials, permissions]
    only_if: test -e /var/log/cloud-init.log
    run: find /var/log/cloud-init.log /var/log/cloud-init-output.log -perm /o+r 2>/dev/null
    allow_rc: [0, 1]
    expect: empty
```
