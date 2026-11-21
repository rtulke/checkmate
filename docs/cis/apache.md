# CIS Apache HTTP Server 2.4

Checks for the automatable recommendations of the CIS Apache HTTP Server 2.4 benchmark on RHEL-like systems (httpd) and Debian/Ubuntu (apache2). Run as root. Directive values are server-wide: the last occurrence in the included files wins, as for directives outside of virtual hosts. Recommendations that need a human review (planning, multi-use systems, patch level) are not included. Select levels with `--tags cis-level-1` or `--tags cis-level-2`.

**Policy:** [`cis/apache.yml`](https://github.com/rtulke/checkmate/blob/main/cis/apache.yml) · **Benchmark version:** 1.0.0

Runs as root and reads the configuration the way httpd sees it (`httpd -t -D DUMP_INCLUDES`, `-S`, `-M`):

```bash
sudo checkmate run cis/apache.yml --tags cis-level-1
sudo checkmate run cis/apache.yml --tags cis-level-2 -v
```

| ID | Check | Profiles | Severity |
|---|---|---|---|
| `CIS-APACHE-0-config-valid` | The httpd configuration is valid |  | <span class="sev sev-high">high</span> |
| `CIS-APACHE-2.2-log-config-module` | The logging module is loaded | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-APACHE-2.3-webdav` | WebDAV modules are not loaded | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-APACHE-2.4-status` | The status module is not loaded | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-APACHE-2.5-autoindex` | The directory listing module is not loaded | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-APACHE-2.6-proxy` | Proxy modules are not loaded | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-APACHE-2.7-userdir` | The user directories module is not loaded | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-APACHE-2.8-info` | The server information module is not loaded | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-APACHE-2.9-basic-digest-auth` | Basic and digest authentication modules are not loaded | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-APACHE-3.1-non-root-user` | httpd runs as a dedicated non-root user | L1 | <span class="sev sev-high">high</span> |
| `CIS-APACHE-3.2-user-shell` | The httpd user has no login shell | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-APACHE-3.3-user-locked` | The httpd user account is locked | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-APACHE-3.4-server-root-owner` | Files below the server root are owned by root | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-APACHE-3.5-server-root-group` | Files below the server root belong to group root | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-APACHE-3.6-server-root-other-write` | Files below the server root are not writable by others | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-APACHE-3.11-server-root-group-write` | Files below the server root are not writable by the group | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-APACHE-3.12-document-root-group-write` | Files below the document root are not writable by the httpd group | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-APACHE-3.7-core-dump-directory` | A core dump directory is not inside the document root and not accessible by others | L1 | <span class="sev sev-low">low</span> |
| `CIS-APACHE-3.9-pid-file` | The PID file directory is owned by root and not writable by others | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-APACHE-4.1-root-directory-denied` | Access to the file system root is denied | L1 | <span class="sev sev-high">high</span> |
| `CIS-APACHE-4.3-root-directory-override` | .htaccess overrides are disabled for the file system root | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-APACHE-4.4-override-disabled` | .htaccess overrides are disabled everywhere | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-APACHE-5.1-root-directory-options` | No options are enabled for the file system root | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-APACHE-5.2-document-root-options` | The document root allows no options except MultiViews | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-APACHE-5.3-no-includes` | Server-side includes with command execution are not enabled | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-APACHE-5.4-default-content` | Default welcome pages and the manual are removed | L1 | <span class="sev sev-low">low</span> |
| `CIS-APACHE-5.5-printenv` | The printenv CGI example is removed | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-APACHE-5.6-test-cgi` | The test-cgi CGI example is removed | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-APACHE-5.7-limit-methods` | HTTP request methods are limited | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-APACHE-5.8-trace-disabled` | The TRACE method is disabled | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-APACHE-5.9-old-protocols` | Requests with old HTTP protocol versions are rejected | L1 | <span class="sev sev-low">low</span> |
| `CIS-APACHE-5.10-htaccess-files` | Access to .ht* files is denied | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-APACHE-5.11-file-extensions` | Only approved file extensions can be requested | L2 | <span class="sev sev-low">low</span> |
| `CIS-APACHE-5.12-ip-requests` | Requests for an IP address instead of the host name are rejected | L2 | <span class="sev sev-low">low</span> |
| `CIS-APACHE-5.13-listen-addresses` | httpd listens only on explicit IP addresses | L2 | <span class="sev sev-low">low</span> |
| `CIS-APACHE-5.14-framing` | Pages cannot be framed by other sites | L2 | <span class="sev sev-low">low</span> |
| `CIS-APACHE-6.1-error-log` | Errors are logged at notice level or more detailed | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-APACHE-6.3-access-log` | An access log is written | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-APACHE-6.4-log-rotation` | Logs are rotated and kept for at least 13 rotations | L1 | <span class="sev sev-low">low</span> |
| `CIS-APACHE-6.6-modsecurity` | ModSecurity is loaded | L2 | <span class="sev sev-low">low</span> |
| `CIS-APACHE-6.7-owasp-crs` | The OWASP Core Rule Set is included | L2 | <span class="sev sev-low">low</span> |
| `CIS-APACHE-7.1-mod-ssl` | The TLS module is loaded | L1 | <span class="sev sev-high">high</span> |
| `CIS-APACHE-7.2-certificates-valid` | Configured certificates are valid and trusted | L1 | <span class="sev sev-high">high</span> |
| `CIS-APACHE-7.3-private-keys` | Private keys are readable only by root | L1 | <span class="sev sev-high">high</span> |
| `CIS-APACHE-7.4-protocols` | Only TLS 1.2 and newer are enabled | L1 | <span class="sev sev-high">high</span> |
| `CIS-APACHE-7.5-weak-ciphers` | Weak cipher suites are disabled | L1 | <span class="sev sev-high">high</span> |
| `CIS-APACHE-7.6-insecure-renegotiation` | Insecure TLS renegotiation is disabled | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-APACHE-7.7-compression` | TLS compression is disabled | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-APACHE-7.9-https-redirect` | Plain HTTP virtual hosts redirect to HTTPS | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-APACHE-7.11-ocsp-stapling` | OCSP stapling is enabled | L2 | <span class="sev sev-low">low</span> |
| `CIS-APACHE-7.12-hsts` | HTTP Strict Transport Security is sent | L2 | <span class="sev sev-low">low</span> |
| `CIS-APACHE-7.13-forward-secrecy` | Only cipher suites with forward secrecy are enabled | L2 | <span class="sev sev-low">low</span> |
| `CIS-APACHE-8.1-server-tokens` | The Server header reveals only the product name | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-APACHE-8.2-server-signature` | Error pages carry no server signature | L1 | <span class="sev sev-medium">medium</span> |
| `CIS-APACHE-8.3-icons` | The default icons alias is removed | L2 | <span class="sev sev-low">low</span> |
| `CIS-APACHE-8.4-etag` | ETag headers do not contain inode numbers | L2 | <span class="sev sev-low">low</span> |
| `CIS-APACHE-9.1-timeout` | The request timeout is 10 seconds or less | L1 | <span class="sev sev-low">low</span> |
| `CIS-APACHE-9.2-keepalive` | Persistent connections are enabled | L1 | <span class="sev sev-low">low</span> |
| `CIS-APACHE-9.3-maxkeepaliverequests` | A persistent connection serves at least 100 requests | L1 | <span class="sev sev-low">low</span> |
| `CIS-APACHE-9.4-keepalivetimeout` | Idle persistent connections close within 15 seconds | L1 | <span class="sev sev-low">low</span> |
| `CIS-APACHE-10.1-limitrequestline` | The request line is limited to 512 bytes | L2 | <span class="sev sev-low">low</span> |
| `CIS-APACHE-10.2-limitrequestfields` | A request has at most 100 header fields | L2 | <span class="sev sev-low">low</span> |
| `CIS-APACHE-10.3-limitrequestfieldsize` | A header field is limited to 1024 bytes | L2 | <span class="sev sev-low">low</span> |
| `CIS-APACHE-10.4-limitrequestbody` | The request body is limited to 100 KB | L2 | <span class="sev sev-low">low</span> |
| `CIS-APACHE-9.5-request-read-timeout` | Slow requests are cut off by mod_reqtimeout | L1 | <span class="sev sev-low">low</span> |
| `CIS-APACHE-11.1-selinux-enforcing` | SELinux is enforcing | L2 | <span class="sev sev-low">low</span> |
| `CIS-APACHE-11.2-httpd-confined` | httpd processes run in the httpd_t domain | L2 | <span class="sev sev-low">low</span> |
| `CIS-APACHE-11.3-httpd-not-permissive` | The httpd_t domain is not permissive | L2 | <span class="sev sev-low">low</span> |
| `CIS-APACHE-12.1-apparmor-enabled` | AppArmor is enabled | L2 | <span class="sev sev-low">low</span> |
| `CIS-APACHE-12.3-apparmor-enforce` | An AppArmor profile for apache2 is in enforce mode | L2 | <span class="sev sev-low">low</span> |
