# TLS certificates and endpoints

Certificate expiry for local files and remote endpoints, chain validation and protocol versions, all with the openssl command line.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/network/tls.yml`](https://github.com/rtulke/checkmate/blob/main/examples/network/tls.yml)
- :material-format-list-checks: **Checks**  
  5 from 4 definitions, 4 with loops
- :material-monitor: **Platforms**  
  any (POSIX shell)

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/network/tls.yml

# Run the checks
checkmate run examples/network/tls.yml

# Override a variable from the command line
checkmate run examples/network/tls.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `TLS-FILE-_etc_pki_tls_certs_localhost.crt` | /etc/pki/tls/certs/localhost.crt is valid for 30 more days | <span class="sev sev-high">high</span> | network, tls, certificates |
| `TLS-FILE-_etc_ssl_certs_ssl-cert-snakeoil.pem` | /etc/ssl/certs/ssl-cert-snakeoil.pem is valid for 30 more days | <span class="sev sev-high">high</span> | network, tls, certificates |
| `TLS-EXPIRY-example.com` | Certificate of example.com is valid for 30 more days | <span class="sev sev-high">high</span> | network, tls, certificates |
| `TLS-CHAIN-example.com` | Certificate chain of example.com verifies | <span class="sev sev-high">high</span> | network, tls, certificates |
| `TLS-OLD-example.com` | example.com rejects TLS 1.1 | <span class="sev sev-medium">medium</span> | network, tls |

## Policy

```yaml title="examples/network/tls.yml" linenums="1"
name: TLS certificates and endpoints
version: 1.0.0
description: >
  Certificate expiry for local files and remote endpoints, chain validation
  and protocol versions, all with the openssl command line.

vars:
  min_valid_days: 30
  certificate_files: [/etc/pki/tls/certs/localhost.crt, /etc/ssl/certs/ssl-cert-snakeoil.pem]
  tls_endpoints: [example.com]

checks:
  - id: "TLS-FILE-{{ item | replace('/', '_') }}"
    name: "{{ item }} is valid for {{ min_valid_days }} more days"
    tags: [network, tls, certificates]
    severity: high
    loop: "{{ certificate_files }}"
    only_if: test -f {{ item }}
    # -checkend exits 1 if the certificate expires within the given seconds.
    run: openssl x509 -in {{ item }} -noout -checkend {{ min_valid_days * 86400 }}
    expect: true

  - id: "TLS-EXPIRY-{{ item }}"
    name: "Certificate of {{ item }} is valid for {{ min_valid_days }} more days"
    tags: [network, tls, certificates]
    severity: high
    loop: "{{ tls_endpoints }}"
    timeout: 20s
    run: |
      echo | openssl s_client -connect {{ item }}:443 -servername {{ item }} 2>/dev/null |
        openssl x509 -noout -checkend {{ min_valid_days * 86400 }}
    expect: true

  - id: "TLS-CHAIN-{{ item }}"
    name: "Certificate chain of {{ item }} verifies"
    tags: [network, tls, certificates]
    severity: high
    loop: "{{ tls_endpoints }}"
    timeout: 20s
    run: |
      echo | openssl s_client -connect {{ item }}:443 -servername {{ item }} -verify_return_error 2>&1 |
        grep -E 'Verify return code'
    allow_rc: [0, 1]
    expect: "~ Verify return code: 0 \\(ok\\)"

  - id: "TLS-OLD-{{ item }}"
    name: "{{ item }} rejects TLS 1.1"
    tags: [network, tls]
    loop: "{{ tls_endpoints }}"
    timeout: 20s
    # No TLS 1.1 session may be negotiated. The exit code of s_client is not
    # reliable across OpenSSL versions, so the negotiated protocol is read.
    run: |
      echo | openssl s_client -connect {{ item }}:443 -servername {{ item }} -tls1_1 2>&1 |
        grep -E '^[[:space:]]*Protocol[[:space:]]*:[[:space:]]*TLSv1\.1'
    allow_rc: [0, 1]
    expect: empty
```
