# PHP and web content

PHP runtime settings and a scan of web directories for signs of compromise: web shells, obfuscated eval code, unusual file names and modified .htaccess files. PHP values come from the PHP binary itself (`php -r ini_get(...)`), so every included ini file is taken into account.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/applications/php-web.yml`](https://github.com/rtulke/checkmate/blob/main/examples/applications/php-web.yml)
- :material-format-list-checks: **Checks**  
  16 from 8 definitions, 1 with loops
- :material-monitor: **Platforms**  
  any (POSIX shell)

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/applications/php-web.yml

# Run the checks
checkmate run examples/applications/php-web.yml

# Override a variable from the command line
checkmate run examples/applications/php-web.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `PHP-INI-EXPOSE_PHP` | PHP expose_php is off | <span class="sev sev-medium">medium</span> | applications, php |
| `PHP-INI-ALLOW_URL_FOPEN` | PHP allow_url_fopen is off | <span class="sev sev-medium">medium</span> | applications, php |
| `PHP-INI-ALLOW_URL_INCLUDE` | PHP allow_url_include is off | <span class="sev sev-medium">medium</span> | applications, php |
| `PHP-INI-DISPLAY_ERRORS` | PHP display_errors is off | <span class="sev sev-medium">medium</span> | applications, php |
| `PHP-INI-LOG_ERRORS` | PHP log_errors is on | <span class="sev sev-medium">medium</span> | applications, php |
| `PHP-INI-SESSION-COOKIE_HTTPONLY` | PHP session.cookie_httponly is on | <span class="sev sev-medium">medium</span> | applications, php |
| `PHP-INI-SESSION-COOKIE_SECURE` | PHP session.cookie_secure is on | <span class="sev sev-medium">medium</span> | applications, php |
| `PHP-INI-SESSION-USE_STRICT_MODE` | PHP session.use_strict_mode is on | <span class="sev sev-medium">medium</span> | applications, php |
| `PHP-INI-OPEN_BASEDIR` | PHP open_basedir is set | <span class="sev sev-medium">medium</span> | applications, php |
| `PHP-DISABLE-FUNCTIONS` | Dangerous PHP functions are disabled | <span class="sev sev-high">high</span> | applications, php |
| `PHP-VERSION` | PHP 8.1 or newer | <span class="sev sev-high">high</span> | applications, php, updates |
| `WEB-WEBSHELL-EVAL` | No obfuscated eval code in web directories | <span class="sev sev-critical">critical</span> | applications, web, malware |
| `WEB-SUSPICIOUS-NAMES` | No unusual file names in web directories | <span class="sev sev-high">high</span> | applications, web, malware |
| `WEB-HTACCESS-APPEND` | No .htaccess file injects code into every request | <span class="sev sev-critical">critical</span> | applications, web, malware |
| `WEB-EXECUTABLE-UPLOADS` | Upload directories contain no PHP files | <span class="sev sev-high">high</span> | applications, web, malware |
| `WEB-WRITABLE` | Web content is not writable by the web server user | <span class="sev sev-low">low</span> | applications, web, permissions |

## Policy

```yaml title="examples/applications/php-web.yml" linenums="1"
name: PHP and web content
version: 1.0.0
description: >
  PHP runtime settings and a scan of web directories for signs of
  compromise: web shells, obfuscated eval code, unusual file names and
  modified .htaccess files. PHP values come from the PHP binary itself
  (`php -r ini_get(...)`), so every included ini file is taken into account.

vars:
  web_roots: [/var/www, /srv/www, /usr/share/nginx/html]
  dangerous_functions: [exec, passthru, shell_exec, system, proc_open, popen, pcntl_exec]

snippets:
  # Prints the effective value of a php.ini setting.
  php_ini: php -r 'echo var_export(ini_get("{{ arg }}"), true), PHP_EOL;' | tr -d "'"

defaults:
  when: facts.os == "linux"

checks:
  - id: "PHP-INI-{{ item.key | upper | replace('.', '-') }}"
    name: "PHP {{ item.key }} is {{ item.label }}"
    tags: [applications, php]
    only_if: command -v php
    loop:
      - { key: expose_php, label: "off", expect: "in ['', '0', 'off', 'false']" }
      - { key: allow_url_fopen, label: "off", expect: "in ['', '0', 'off', 'false']" }
      - { key: allow_url_include, label: "off", expect: "in ['', '0', 'off', 'false']" }
      - { key: display_errors, label: "off", expect: "in ['', '0', 'off', 'false', 'stderr']" }
      - { key: log_errors, label: "on", expect: "in ['1', 'on', 'true']" }
      - { key: session.cookie_httponly, label: "on", expect: "in ['1', 'on', 'true']" }
      - { key: session.cookie_secure, label: "on", expect: "in ['1', 'on', 'true']" }
      - { key: session.use_strict_mode, label: "on", expect: "in ['1', 'on', 'true']" }
      - { key: open_basedir, label: "set", expect: "!empty" }
    run: { use: php_ini, arg: "{{ item.key }}" }
    as: string
    expect: "{{ item.expect }}"

  - id: PHP-DISABLE-FUNCTIONS
    name: Dangerous PHP functions are disabled
    tags: [applications, php]
    severity: high
    only_if: command -v php
    # Prints every dangerous function that is not in disable_functions.
    run: |
      disabled=$(php -r 'echo ini_get("disable_functions");' | tr -d ' ')
      for f in {{ dangerous_functions | join(' ') }}; do
        case ",$disabled," in *",$f,"*) ;; *) echo "$f" ;; esac
      done
    expect: empty

  - id: PHP-VERSION
    name: PHP 8.1 or newer
    tags: [applications, php, updates]
    severity: high
    only_if: command -v php
    run: php -r 'echo PHP_VERSION, PHP_EOL;'
    as: version
    expect: ">= 8.1"

  # --- web content -----------------------------------------------------------
  - id: WEB-WEBSHELL-EVAL
    name: No obfuscated eval code in web directories
    tags: [applications, web, malware]
    severity: critical
    timeout: 10m
    run: |
      for d in {{ web_roots | join(' ') }}; do
        if [ -d "$d" ]; then
          grep -rlE --include='*.php' --include='*.phtml' --include='*.inc' \
            'eval[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|str_rot13|gzuncompress|\$_(POST|GET|REQUEST|COOKIE))' "$d"
        fi
      done
    allow_rc: [0, 1]
    expect: empty
    remediation: Treat the host as compromised and investigate the listed files.

  - id: WEB-SUSPICIOUS-NAMES
    name: No unusual file names in web directories
    tags: [applications, web, malware]
    severity: high
    run: |
      for d in {{ web_roots | join(' ') }}; do
        if [ -d "$d" ]; then
          find "$d" \( -name '...' -o -name '.yop' -o -name '.shell' -o -name 'id' -o -name '.ssh' \
            -o -iname '*c99*.php' -o -iname '*r57*.php' -o -iname '*wso*.php' -o -name '*.php.suspected' \) 2>/dev/null
        fi
      done
    allow_rc: [0, 1]
    expect: empty

  - id: WEB-HTACCESS-APPEND
    name: No .htaccess file injects code into every request
    tags: [applications, web, malware]
    severity: critical
    run: |
      for d in {{ web_roots | join(' ') }}; do
        if [ -d "$d" ]; then
          find "$d" -name .htaccess -exec grep -liE 'php_value[[:space:]]+auto_(prepend|append)_file' {} + 2>/dev/null
        fi
      done
    allow_rc: [0, 1]
    expect: empty

  - id: WEB-EXECUTABLE-UPLOADS
    name: Upload directories contain no PHP files
    tags: [applications, web, malware]
    severity: high
    run: |
      for d in {{ web_roots | join(' ') }}; do
        if [ -d "$d" ]; then
          find "$d" -type d \( -name uploads -o -name upload -o -name files \) -exec find {} -type f -iname '*.php*' \; 2>/dev/null
        fi
      done
    allow_rc: [0, 1]
    expect: empty

  - id: WEB-WRITABLE
    name: Web content is not writable by the web server user
    tags: [applications, web, permissions]
    severity: low
    run: |
      for d in {{ web_roots | join(' ') }}; do
        if [ -d "$d" ]; then
          find "$d" -maxdepth 2 \( -user www-data -o -user nginx -o -user apache \) -perm -u+w ! -path '*/uploads*' 2>/dev/null
        fi
      done
    allow_rc: [0, 1]
    expect: empty
```
