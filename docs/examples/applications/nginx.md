# nginx in depth

A detailed nginx review covering the topics of the public nginx hardening benchmarks: modules, service account, file permissions, timeouts and request limits, information disclosure, logging, TLS and security headers. Every check reads the effective configuration from `nginx -T`, which includes all included files.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/applications/nginx.yml`](https://github.com/rtulke/checkmate/blob/main/examples/applications/nginx.yml)
- :material-format-list-checks: **Checks**  
  32 from 23 definitions, 2 with loops
- :material-monitor: **Platforms**  
  any (POSIX shell)

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/applications/nginx.yml

# Run the checks
checkmate run examples/applications/nginx.yml

# Override a variable from the command line
checkmate run examples/applications/nginx.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `NGX-CONFIG-VALID` | The configuration is valid | <span class="sev sev-high">high</span> | applications, nginx |
| `NGX-NO-DAV` | The WebDAV module is not compiled in | <span class="sev sev-medium">medium</span> | applications, nginx, modules |
| `NGX-NO-AUTOINDEX` | Directory listings are disabled | <span class="sev sev-medium">medium</span> | applications, nginx, modules |
| `NGX-USER` | Workers run as a dedicated unprivileged user | <span class="sev sev-high">high</span> | applications, nginx, accounts |
| `NGX-USER-LOCKED` | The nginx account is locked and has no login shell | <span class="sev sev-medium">medium</span> | applications, nginx, accounts |
| `NGX-CONF-OWNER` | Configuration files are owned by root and not writable by others | <span class="sev sev-high">high</span> | applications, nginx, permissions |
| `NGX-TLS-KEYS` | TLS private keys are only readable by root | <span class="sev sev-critical">critical</span> | applications, nginx, tls, permissions |
| `NGX-PIDFILE` | The PID file is owned by root and not writable by others | <span class="sev sev-low">low</span> | applications, nginx, permissions |
| `NGX-KEEPALIVE` | keepalive_timeout is set and at most 10 seconds | <span class="sev sev-low">low</span> | applications, nginx, limits |
| `NGX-SEND-TIMEOUT` | send_timeout is set and at most 10 seconds | <span class="sev sev-low">low</span> | applications, nginx, limits |
| `NGX-LIMIT-CLIENT-MAX-BODY-SIZE` | client_max_body_size is configured | <span class="sev sev-low">low</span> | applications, nginx, limits |
| `NGX-LIMIT-LARGE-CLIENT-HEADER-BUFFERS` | large_client_header_buffers is configured | <span class="sev sev-low">low</span> | applications, nginx, limits |
| `NGX-LIMIT-CLIENT-BODY-TIMEOUT` | client_body_timeout is configured | <span class="sev sev-low">low</span> | applications, nginx, limits |
| `NGX-LIMIT-CLIENT-HEADER-TIMEOUT` | client_header_timeout is configured | <span class="sev sev-low">low</span> | applications, nginx, limits |
| `NGX-LIMIT-LIMIT-CONN-ZONE` | limit_conn_zone is configured | <span class="sev sev-low">low</span> | applications, nginx, limits |
| `NGX-LIMIT-LIMIT-REQ-ZONE` | limit_req_zone is configured | <span class="sev sev-low">low</span> | applications, nginx, limits |
| `NGX-SERVER-TOKENS` | The version is not disclosed | <span class="sev sev-medium">medium</span> | applications, nginx |
| `NGX-HIDDEN-FILES` | Hidden files (.git, .env, .htpasswd) are not served | <span class="sev sev-high">high</span> | applications, nginx |
| `NGX-PROXY-HEADERS` | Proxied responses hide backend headers | <span class="sev sev-low">low</span> | applications, nginx |
| `NGX-ACCESS-LOG` | Access logging is not disabled | <span class="sev sev-medium">medium</span> | applications, nginx, logging |
| `NGX-ERROR-LOG` | The error log records at least warnings | <span class="sev sev-low">low</span> | applications, nginx, logging |
| `NGX-LOGROTATE` | nginx logs are rotated | <span class="sev sev-low">low</span> | applications, nginx, logging |
| `NGX-TLS-PROTOCOLS` | Only TLS 1.2 and 1.3 are offered | <span class="sev sev-high">high</span> | applications, nginx, tls |
| `NGX-TLS-CIPHERS` | No weak ciphers are configured | <span class="sev sev-high">high</span> | applications, nginx, tls |
| `NGX-TLS-TICKETS` | TLS session tickets are disabled (forward secrecy) | <span class="sev sev-low">low</span> | applications, nginx, tls |
| `NGX-OCSP` | OCSP stapling is enabled | <span class="sev sev-low">low</span> | applications, nginx, tls |
| `NGX-HTTPS-REDIRECT` | Plain HTTP redirects to HTTPS | <span class="sev sev-medium">medium</span> | applications, nginx, tls |
| `NGX-HEADER-Content-Security-Policy` | Header Content-Security-Policy is set | <span class="sev sev-low">low</span> | applications, nginx, headers |
| `NGX-HEADER-Referrer-Policy` | Header Referrer-Policy is set | <span class="sev sev-low">low</span> | applications, nginx, headers |
| `NGX-HEADER-Strict-Transport-Security` | Header Strict-Transport-Security is set | <span class="sev sev-low">low</span> | applications, nginx, headers |
| `NGX-HEADER-X-Content-Type-Options` | Header X-Content-Type-Options is set | <span class="sev sev-low">low</span> | applications, nginx, headers |
| `NGX-HEADER-X-Frame-Options` | Header X-Frame-Options is set | <span class="sev sev-low">low</span> | applications, nginx, headers |

## Policy

```yaml title="examples/applications/nginx.yml" linenums="1"
name: nginx in depth
version: 1.0.0
description: >
  A detailed nginx review covering the topics of the public nginx hardening
  benchmarks: modules, service account, file permissions, timeouts and
  request limits, information disclosure, logging, TLS and security
  headers. Every check reads the effective configuration from `nginx -T`,
  which includes all included files.

vars:
  max_keepalive_timeout: 10
  max_send_timeout: 10
  tls_key_dirs: [/etc/nginx, /etc/ssl/private, /etc/pki/tls/private]
  security_headers:
    X-Frame-Options: "~ (?i)(DENY|SAMEORIGIN)"
    X-Content-Type-Options: "~ (?i)nosniff"
    Content-Security-Policy: "!empty"
    Referrer-Policy: "~ (?i)(no-referrer|strict-origin|same-origin)"
    Strict-Transport-Security: "~ max-age=([3-9][0-9]{6}|[1-9][0-9]{7,})"

snippets:
  # The effective configuration without comments.
  ngx: nginx -T 2>/dev/null | grep -vE '^[[:space:]]*(#|$)'

defaults:
  # Every check needs nginx; on other hosts the policy is skipped.
  when: facts.os == "linux"

checks:
  # --- installation and modules -------------------------------------------------
  - id: NGX-CONFIG-VALID
    name: The configuration is valid
    tags: [applications, nginx]
    severity: high
    only_if: command -v nginx
    run: nginx -t 2>&1
    expect: "~ syntax is ok"

  - id: NGX-NO-DAV
    name: The WebDAV module is not compiled in
    tags: [applications, nginx, modules]
    only_if: command -v nginx
    run: nginx -V 2>&1
    expect: "!~ http_dav_module"

  - id: NGX-NO-AUTOINDEX
    name: Directory listings are disabled
    tags: [applications, nginx, modules]
    only_if: command -v nginx
    run: { use: ngx }
    allow_rc: [0, 1]
    expect: { none: "~ ^[[:space:]]*autoindex[[:space:]]+on" }

  # --- service account and permissions ------------------------------------------------
  - id: NGX-USER
    name: Workers run as a dedicated unprivileged user
    tags: [applications, nginx, accounts]
    severity: high
    only_if: command -v nginx
    run: { use: ngx }
    allow_rc: [0, 1]
    expect: { some: "~ ^[[:space:]]*user[[:space:]]+(nginx|www-data|www)[[:space:];]" }

  - id: NGX-USER-LOCKED
    name: The nginx account is locked and has no login shell
    tags: [applications, nginx, accounts]
    when: facts.is_root
    only_if: getent passwd nginx >/dev/null || getent passwd www-data >/dev/null
    run: |
      for u in nginx www-data; do
        getent passwd "$u" >/dev/null || continue
        shell=$(getent passwd "$u" | cut -d: -f7)
        pw=$(getent shadow "$u" | cut -d: -f2)
        case "$shell" in */nologin|*/false) ;; *) echo "$u has shell $shell" ;; esac
        case "$pw" in '!'*|'*'*) ;; *) echo "$u has a password" ;; esac
      done
    expect: empty

  - id: NGX-CONF-OWNER
    name: Configuration files are owned by root and not writable by others
    tags: [applications, nginx, permissions]
    severity: high
    only_if: test -d /etc/nginx
    # Symbolic links always have mode 777 and are skipped.
    run: find /etc/nginx ! -type l \( ! -user root -o -perm /022 \)
    expect: empty

  - id: NGX-TLS-KEYS
    name: TLS private keys are only readable by root
    tags: [applications, nginx, tls, permissions]
    severity: critical
    only_if: command -v nginx
    run: |
      { nginx -T 2>/dev/null | awk '$1 == "ssl_certificate_key" {gsub(/;/, "", $2); print $2}'; } | sort -u |
        while read -r key; do
          [ -f "$key" ] || continue
          find -H "$key" \( -perm /077 -o ! -user root \)
        done
    expect: empty

  - id: NGX-PIDFILE
    name: The PID file is owned by root and not writable by others
    tags: [applications, nginx, permissions]
    severity: low
    only_if: test -f /run/nginx.pid
    run: find /run/nginx.pid \( -perm /022 -o ! -user root \)
    expect: empty

  # --- timeouts and limits -----------------------------------------------------------
  - id: NGX-KEEPALIVE
    name: "keepalive_timeout is set and at most {{ max_keepalive_timeout }} seconds"
    tags: [applications, nginx, limits]
    severity: low
    only_if: command -v nginx
    run: |
      nginx -T 2>/dev/null | awk '$1 == "keepalive_timeout" {gsub(/[;s]/, "", $2); print $2}'
    expect: ["!empty", { each: ["> 0", "<= {{ max_keepalive_timeout }}"] }]

  - id: NGX-SEND-TIMEOUT
    name: "send_timeout is set and at most {{ max_send_timeout }} seconds"
    tags: [applications, nginx, limits]
    severity: low
    only_if: command -v nginx
    run: |
      nginx -T 2>/dev/null | awk '$1 == "send_timeout" {gsub(/[;s]/, "", $2); print $2}'
    expect: ["!empty", { each: ["> 0", "<= {{ max_send_timeout }}"] }]

  - id: "NGX-LIMIT-{{ item | upper | replace('_', '-') }}"
    name: "{{ item }} is configured"
    tags: [applications, nginx, limits]
    severity: low
    only_if: command -v nginx
    loop: [client_max_body_size, large_client_header_buffers, client_body_timeout, client_header_timeout, limit_conn_zone, limit_req_zone]
    run: { use: ngx }
    allow_rc: [0, 1]
    expect: { some: "~ ^[[:space:]]*{{ item }}[[:space:]]" }

  # --- information disclosure -----------------------------------------------------------
  - id: NGX-SERVER-TOKENS
    name: The version is not disclosed
    tags: [applications, nginx]
    only_if: command -v nginx
    run: { use: ngx }
    allow_rc: [0, 1]
    expect: { some: "~ ^[[:space:]]*server_tokens[[:space:]]+off" }

  - id: NGX-HIDDEN-FILES
    name: Hidden files (.git, .env, .htpasswd) are not served
    tags: [applications, nginx]
    severity: high
    only_if: command -v nginx
    run: { use: ngx }
    allow_rc: [0, 1]
    expect: { some: "~ location[[:space:]]+~[[:space:]]+/\\\\\\." }

  - id: NGX-PROXY-HEADERS
    name: Proxied responses hide backend headers
    tags: [applications, nginx]
    severity: low
    only_if: command -v nginx && nginx -T 2>/dev/null | grep proxy_pass >/dev/null
    run: { use: ngx }
    allow_rc: [0, 1]
    expect: [{ some: "~ proxy_hide_header[[:space:]]+X-Powered-By" }, { some: "~ proxy_hide_header[[:space:]]+Server" }]

  # --- logging ---------------------------------------------------------------------
  - id: NGX-ACCESS-LOG
    name: Access logging is not disabled
    tags: [applications, nginx, logging]
    only_if: command -v nginx
    run: { use: ngx }
    allow_rc: [0, 1]
    expect: { none: "~ ^[[:space:]]*access_log[[:space:]]+off" }

  - id: NGX-ERROR-LOG
    name: The error log records at least warnings
    tags: [applications, nginx, logging]
    severity: low
    only_if: command -v nginx
    run: |
      nginx -T 2>/dev/null | awk '$1 == "error_log" {gsub(/;/, ""); print ($3 == "" ? "error" : $3)}'
    expect: ["!empty", { each: "in [debug, info, notice, warn]" }]

  - id: NGX-LOGROTATE
    name: nginx logs are rotated
    tags: [applications, nginx, logging]
    severity: low
    only_if: command -v nginx
    run: test -f /etc/logrotate.d/nginx
    expect: true

  # --- TLS and headers -------------------------------------------------------------
  - id: NGX-TLS-PROTOCOLS
    name: Only TLS 1.2 and 1.3 are offered
    tags: [applications, nginx, tls]
    severity: high
    only_if: command -v nginx
    run: |
      nginx -T 2>/dev/null | awk '$1 == "ssl_protocols"'
    expect: { each: "!~ (SSLv[23]|TLSv1[ ;]|TLSv1\\.1)" }

  - id: NGX-TLS-CIPHERS
    name: No weak ciphers are configured
    tags: [applications, nginx, tls]
    severity: high
    only_if: command -v nginx
    run: |
      nginx -T 2>/dev/null | awk '$1 == "ssl_ciphers"'
    expect: { each: "!~ (?i)(RC4|DES|MD5|NULL|EXPORT|aNULL|eNULL|3DES)([:;!' ]|$)" }

  - id: NGX-TLS-TICKETS
    name: TLS session tickets are disabled (forward secrecy)
    tags: [applications, nginx, tls]
    severity: low
    only_if: command -v nginx && nginx -T 2>/dev/null | grep ssl_certificate >/dev/null
    run: { use: ngx }
    allow_rc: [0, 1]
    expect: { some: "~ ^[[:space:]]*ssl_session_tickets[[:space:]]+off" }

  - id: NGX-OCSP
    name: OCSP stapling is enabled
    tags: [applications, nginx, tls]
    severity: low
    only_if: command -v nginx && nginx -T 2>/dev/null | grep ssl_certificate >/dev/null
    run: { use: ngx }
    allow_rc: [0, 1]
    expect: { some: "~ ^[[:space:]]*ssl_stapling[[:space:]]+on" }

  - id: NGX-HTTPS-REDIRECT
    name: Plain HTTP redirects to HTTPS
    tags: [applications, nginx, tls]
    only_if: command -v nginx && nginx -T 2>/dev/null | grep ssl_certificate >/dev/null
    run: { use: ngx }
    allow_rc: [0, 1]
    expect: { some: "~ return[[:space:]]+30[178][[:space:]]+https://" }

  - id: "NGX-HEADER-{{ item.key }}"
    name: "Header {{ item.key }} is set"
    tags: [applications, nginx, headers]
    severity: low
    only_if: command -v nginx
    loop: "{{ security_headers }}"
    run: |
      nginx -T 2>/dev/null | grep -iE '^[[:space:]]*add_header[[:space:]]+{{ item.key }}[[:space:]]' | sed -E 's/^[[:space:]]*add_header[[:space:]]+[^[:space:]]+[[:space:]]+//'
    allow_rc: [0, 1]
    expect: ["!empty", { each: "{{ item.value }}" }]
```
