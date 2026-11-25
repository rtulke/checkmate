# Apache httpd in depth

A detailed Apache httpd review following the topics of the httpd rules in the SCAP Security Guide: loaded modules, information disclosure, directory options, request limits and timeouts, TLS, logging, the service account and file permissions. Module lists come from `httpd -M`, the configuration is read from all files below the server root.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/applications/apache.yml`](https://github.com/rtulke/checkmate/blob/main/examples/applications/apache.yml)
- :material-format-list-checks: **Checks**  
  30 from 13 definitions, 2 with loops
- :material-monitor: **Platforms**  
  debian, rhel, suse

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/applications/apache.yml

# Run the checks
checkmate run examples/applications/apache.yml

# Override a variable from the command line
checkmate run examples/applications/apache.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `HTTPD-CONFIG-VALID` | The configuration is valid | <span class="sev sev-high">high</span> | applications, apache |
| `HTTPD-MOD-autoindex_module` | Module autoindex_module is not loaded | <span class="sev sev-medium">medium</span> | applications, apache, modules |
| `HTTPD-MOD-status_module` | Module status_module is not loaded | <span class="sev sev-medium">medium</span> | applications, apache, modules |
| `HTTPD-MOD-info_module` | Module info_module is not loaded | <span class="sev sev-medium">medium</span> | applications, apache, modules |
| `HTTPD-MOD-userdir_module` | Module userdir_module is not loaded | <span class="sev sev-medium">medium</span> | applications, apache, modules |
| `HTTPD-MOD-dav_module` | Module dav_module is not loaded | <span class="sev sev-medium">medium</span> | applications, apache, modules |
| `HTTPD-MOD-dav_fs_module` | Module dav_fs_module is not loaded | <span class="sev sev-medium">medium</span> | applications, apache, modules |
| `HTTPD-MOD-cgi_module` | Module cgi_module is not loaded | <span class="sev sev-medium">medium</span> | applications, apache, modules |
| `HTTPD-MOD-proxy_ftp_module` | Module proxy_ftp_module is not loaded | <span class="sev sev-medium">medium</span> | applications, apache, modules |
| `HTTPD-DIRECTIVE-SERVERTOKENS` | ServerTokens == prod | <span class="sev sev-medium">medium</span> | applications, apache |
| `HTTPD-DIRECTIVE-SERVERSIGNATURE` | ServerSignature == off | <span class="sev sev-medium">medium</span> | applications, apache |
| `HTTPD-DIRECTIVE-TRACEENABLE` | TraceEnable == off | <span class="sev sev-medium">medium</span> | applications, apache |
| `HTTPD-DIRECTIVE-FILEETAG` | FileETag == none | <span class="sev sev-medium">medium</span> | applications, apache |
| `HTTPD-DIRECTIVE-KEEPALIVE` | KeepAlive == on | <span class="sev sev-medium">medium</span> | applications, apache |
| `HTTPD-DIRECTIVE-TIMEOUT` | Timeout <= 60 | <span class="sev sev-medium">medium</span> | applications, apache |
| `HTTPD-DIRECTIVE-KEEPALIVETIMEOUT` | KeepAliveTimeout <= 15 | <span class="sev sev-medium">medium</span> | applications, apache |
| `HTTPD-DIRECTIVE-MAXKEEPALIVEREQUESTS` | MaxKeepAliveRequests >= 100 | <span class="sev sev-medium">medium</span> | applications, apache |
| `HTTPD-DIRECTIVE-LIMITREQUESTLINE` | LimitRequestLine <= 8190 | <span class="sev sev-medium">medium</span> | applications, apache |
| `HTTPD-DIRECTIVE-LIMITREQUESTFIELDS` | LimitRequestFields <= 100 | <span class="sev sev-medium">medium</span> | applications, apache |
| `HTTPD-DIRECTIVE-LOGLEVEL` | LogLevel in [warn, notice, info] | <span class="sev sev-medium">medium</span> | applications, apache |
| `HTTPD-NO-INDEXES` | Directory listings are disabled | <span class="sev sev-medium">medium</span> | applications, apache |
| `HTTPD-NO-SSI-EXEC` | Server-side includes cannot execute programs | <span class="sev sev-medium">medium</span> | applications, apache |
| `HTTPD-ROOT-DENY` | Access to the file system root is denied | <span class="sev sev-high">high</span> | applications, apache |
| `HTTPD-HTACCESS` | .htaccess files are not served | <span class="sev sev-high">high</span> | applications, apache |
| `HTTPD-USER` | httpd runs as an unprivileged user | <span class="sev sev-high">high</span> | applications, apache, accounts |
| `HTTPD-CONF-OWNER` | Configuration files are owned by root and not writable by others | <span class="sev sev-high">high</span> | applications, apache, permissions |
| `HTTPD-LOGS-PERMS` | Log directories are not readable by others | <span class="sev sev-medium">medium</span> | applications, apache, logging, permissions |
| `HTTPD-TLS-PROTOCOL` | Only TLS 1.2 and newer are offered | <span class="sev sev-high">high</span> | applications, apache, tls |
| `HTTPD-TLS-CIPHERS` | No weak cipher suites | <span class="sev sev-high">high</span> | applications, apache, tls |
| `HTTPD-TLS-COMPRESSION` | TLS compression and insecure renegotiation are off | <span class="sev sev-low">low</span> | applications, apache, tls |

## Policy

```yaml title="examples/applications/apache.yml" linenums="1"
name: Apache httpd in depth
version: 1.0.0
description: >
  A detailed Apache httpd review following the topics of the httpd rules in
  the SCAP Security Guide: loaded modules, information disclosure,
  directory options, request limits and timeouts, TLS, logging, the service
  account and file permissions. Module lists come from `httpd -M`, the
  configuration is read from all files below the server root.

vars:
  # httpd itself; on RHEL 8 and later apachectl no longer passes options on,
  # on Debian and SUSE apache2ctl sets up the environment first.
  httpd: "$(command -v apache2ctl || command -v httpd)"
  unwanted_modules: [autoindex_module, status_module, info_module, userdir_module, dav_module, dav_fs_module, cgi_module, proxy_ftp_module]

snippets:
  # All configuration lines without comments.
  conf:
    rhel: cat /etc/httpd/conf/httpd.conf /etc/httpd/conf.d/*.conf /etc/httpd/conf.modules.d/*.conf 2>/dev/null | grep -vE '^[[:space:]]*(#|$)'
    suse: cat /etc/apache2/*.conf /etc/apache2/conf.d/*.conf /etc/apache2/vhosts.d/*.conf 2>/dev/null | grep -vE '^[[:space:]]*(#|$)'
    debian: cat /etc/apache2/apache2.conf /etc/apache2/conf-enabled/*.conf /etc/apache2/mods-enabled/*.conf /etc/apache2/sites-enabled/* 2>/dev/null | grep -vE '^[[:space:]]*(#|$)'

  # Last value of a directive, lower-cased.
  directive: >-
    { cat /etc/httpd/conf/httpd.conf /etc/httpd/conf.d/*.conf /etc/apache2/apache2.conf /etc/apache2/*.conf
    /etc/apache2/conf-enabled/*.conf /etc/apache2/conf.d/*.conf 2>/dev/null || true; }
    | awk 'tolower($1) == tolower("{{ arg }}") {v = $2} END {print tolower(v)}'

defaults:
  when: facts.os == "linux"

checks:
  - id: HTTPD-CONFIG-VALID
    name: The configuration is valid
    tags: [applications, apache]
    severity: high
    only_if: 'command -v apache2ctl || command -v httpd'
    run: '{{ httpd }} configtest'
    # An invalid configuration exits 1: that is a failure, not an error.
    allow_rc: [0, 1]
    expect: { stderr: "~ Syntax OK" }

  - id: "HTTPD-MOD-{{ item }}"
    name: "Module {{ item }} is not loaded"
    tags: [applications, apache, modules]
    loop: "{{ unwanted_modules }}"
    only_if: 'command -v apache2ctl || command -v httpd'
    run: '{{ httpd }} -M 2>/dev/null'
    allow_rc: [0, 1]
    expect: { none: "~ ^[[:space:]]*{{ item }}[[:space:]]" }

  - id: "HTTPD-DIRECTIVE-{{ item.key | upper }}"
    name: "{{ item.key }} {{ item.value }}"
    tags: [applications, apache]
    only_if: 'command -v apache2ctl || command -v httpd'
    loop:
      ServerTokens: "== prod"
      ServerSignature: "== off"
      TraceEnable: "== off"
      FileETag: "== none"
      KeepAlive: "== on"
      Timeout: "<= 60"
      KeepAliveTimeout: "<= 15"
      MaxKeepAliveRequests: ">= 100"
      LimitRequestLine: "<= 8190"
      LimitRequestFields: "<= 100"
      LogLevel: "in [warn, notice, info]"
    run: { use: directive, arg: "{{ item.key }}" }
    expect: ["!empty", "{{ item.value }}"]

  - id: HTTPD-NO-INDEXES
    name: Directory listings are disabled
    tags: [applications, apache]
    only_if: 'command -v apache2ctl || command -v httpd'
    run: { use: conf }
    allow_rc: [0, 1]
    expect: { none: "~ (?i)^[[:space:]]*Options[[:space:]].*([[:space:]]|\\+)Indexes" }

  - id: HTTPD-NO-SSI-EXEC
    name: Server-side includes cannot execute programs
    tags: [applications, apache]
    only_if: 'command -v apache2ctl || command -v httpd'
    run: { use: conf }
    allow_rc: [0, 1]
    expect: { none: "~ (?i)^[[:space:]]*Options[[:space:]].*([[:space:]]|\\+)(Includes|ExecCGI)([[:space:]]|$)" }

  - id: HTTPD-ROOT-DENY
    name: Access to the file system root is denied
    tags: [applications, apache]
    severity: high
    only_if: 'command -v apache2ctl || command -v httpd'
    run: { use: conf }
    allow_rc: [0, 1]
    expect: { some: "~ (?i)^[[:space:]]*Require[[:space:]]+all[[:space:]]+denied" }

  - id: HTTPD-HTACCESS
    name: .htaccess files are not served
    tags: [applications, apache]
    severity: high
    only_if: 'command -v apache2ctl || command -v httpd'
    run: { use: conf }
    allow_rc: [0, 1]
    expect: { some: "~ (?i)<Files(Match)?[[:space:]].*\\^?\\\\?\\.ht" }

  - id: HTTPD-USER
    name: httpd runs as an unprivileged user
    tags: [applications, apache, accounts]
    severity: high
    only_if: 'command -v apache2ctl || command -v httpd'
    run: { use: directive, arg: User }
    expect: ["!empty", "!in [root, '0']"]

  - id: HTTPD-CONF-OWNER
    name: Configuration files are owned by root and not writable by others
    tags: [applications, apache, permissions]
    severity: high
    # Symbolic links always have mode 777 and are skipped.
    run: find /etc/httpd /etc/apache2 ! -type l \( ! -user root -o -perm /022 \) 2>/dev/null
    allow_rc: [0, 1]
    expect: empty

  - id: HTTPD-LOGS-PERMS
    name: Log directories are not readable by others
    tags: [applications, apache, logging, permissions]
    run: find /var/log/httpd /var/log/apache2 -maxdepth 0 -perm /007 2>/dev/null
    allow_rc: [0, 1]
    expect: empty

  - id: HTTPD-TLS-PROTOCOL
    name: Only TLS 1.2 and newer are offered
    tags: [applications, apache, tls]
    severity: high
    only_if: 'command -v apache2ctl || command -v httpd && {{ httpd }} -M 2>/dev/null | grep ssl_module >/dev/null'
    run: { use: conf }
    allow_rc: [0, 1]
    expect:
      all:
        - { some: "~ (?i)^[[:space:]]*SSLProtocol[[:space:]]" }
        - { none: "~ (?i)^[[:space:]]*SSLProtocol[[:space:]].*([[:space:]]|\\+)(SSLv3|TLSv1|TLSv1\\.1)([[:space:]]|$)" }

  - id: HTTPD-TLS-CIPHERS
    name: No weak cipher suites
    tags: [applications, apache, tls]
    severity: high
    only_if: 'command -v apache2ctl || command -v httpd && {{ httpd }} -M 2>/dev/null | grep ssl_module >/dev/null'
    run: { use: conf }
    allow_rc: [0, 1]
    expect: { none: "~ (?i)^[[:space:]]*SSLCipherSuite[[:space:]].*(^|[:+ ])(RC4|DES|3DES|MD5|EXPORT|NULL)([: ]|$)" }

  - id: HTTPD-TLS-COMPRESSION
    name: TLS compression and insecure renegotiation are off
    tags: [applications, apache, tls]
    severity: low
    only_if: 'command -v apache2ctl || command -v httpd && {{ httpd }} -M 2>/dev/null | grep ssl_module >/dev/null'
    run: { use: conf }
    allow_rc: [0, 1]
    expect: { none: "~ (?i)^[[:space:]]*(SSLCompression|SSLInsecureRenegotiation)[[:space:]]+on" }
```
