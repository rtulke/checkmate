# Templating and variables

All string values of a check are [Jinja2](https://jinja.palletsprojects.com/en/stable/templates/) templates, as in Ansible. Templates are rendered on the host right before the check runs, so facts about the host are available.

```yaml
vars:
  min_free_mb: 1024

checks:
  - id: DISK-ROOT
    name: "/ has at least {{ min_free_mb }} MB free"
    run: df -Pm / | awk 'NR == 2 {print $4}'
    expect: ">= {{ min_free_mb }}"
```

## Available names

| Name | Content |
|---|---|
| any variable | Variables from `vars`, `vars_files` and `-e`, at top level |
| `vars` | All variables as one mapping |
| `facts` | Facts about the host, see [Platforms and facts](platforms.md) |
| `item` | The current loop item (with `loop_run` not in `run` and `only_if`) |
| `arg`, `args` | Snippet arguments (inside snippets) |
| a registered name | The outcome of an earlier check with `register` (only in `when`) |
| `policy_dir` | Directory of the policy file that defines the check |

Undefined variables are an **error**, so typos never render as an empty string.

## Loops

`loop` turns one definition into one check per item. The id must contain the item so every check stays unique.

=== "List"

    ```yaml
    - id: "SVC-{{ item }}"
      name: "{{ item }} is running"
      loop: [sshd, chronyd, auditd]
      run: systemctl is-active {{ item }}
      expect: "== active"
    ```

=== "Mapping"

    ```yaml
    # Items are {key, value} pairs in file order.
    - id: "SYSCTL-{{ item.key }}"
      loop:
        net.ipv4.ip_forward: 0
        kernel.randomize_va_space: 2
      run: sysctl -n {{ item.key }}
      expect: "== {{ item.value }}"
    ```

=== "List of mappings"

    ```yaml
    - id: "MNT-{{ item.path | replace('/', '_') }}-{{ item.option }}"
      loop:
        - { path: /tmp, option: nosuid }
        - { path: /tmp, option: nodev }
      run: findmnt -n -o OPTIONS {{ item.path }}
      expect: "~ (^|,){{ item.option }}(,|$)"
    ```

=== "Variable"

    ```yaml
    vars:
      required_packages: [sudo, openssh-server]
    checks:
      - id: "PKG-{{ item }}"
        loop: "{{ required_packages }}"
        run: rpm -q {{ item }}
        expect: true
    ```

=== "Expression"

    ```yaml
    # Any Jinja2 expression that yields a list or mapping
    - id: "CONTENT-{{ item.path | replace('/', '_') }}"
      loop: "{{ files | selectattr('contains', 'defined') | list }}"
      run: cat {{ item.path }}
      expect: { some: "~ {{ item.contains }}" }
    ```

Since the expectation is a template too, a loop value can carry the whole condition:

```yaml
vars:
  sysctl:
    kernel.kptr_restrict: ">= 1"
    kernel.randomize_va_space: "== 2"
checks:
  - id: "SYSCTL-{{ item.key }}"
    loop: "{{ sysctl }}"
    run: sysctl -n {{ item.key }}
    expect: "{{ item.value }}"
```

## Snippets

A snippet is a named command, optionally with platform variants. Checks call it with `use` and pass values as `arg` (a single value) or `args` (a mapping):

```yaml
snippets:
  pkg_installed:
    rhel,suse: rpm -q --quiet {{ arg }}
    debian: dpkg-query -W -f='${Status}' {{ arg }} 2>/dev/null | grep -q 'install ok installed'

  ios: >-
    ssh -o BatchMode=yes {{ ios_user }}@{{ arg }} '{{ args.cmd }}'

checks:
  - id: "PKG-{{ item }}"
    loop: [sudo, chrony]
    run: { use: pkg_installed, arg: "{{ item }}" }
    expect: true

  - id: IOS-NTP
    run: { use: ios, arg: sw-core-01, args: { cmd: show ntp status } }
    expect: "~ Clock is synchronized"
```

Snippet arguments can have defaults: `{{ args.format | default("json") }}`.

## Loops over command output

`loop` needs the items when the policy is written. `loop_run` asks the host instead: it runs a command and creates one check per line of its output. Use it for things that differ from host to host, such as accounts, mounted file systems, network interfaces or virtual hosts.

```yaml
checks:
  - id: "KEYS-{{ item }}"
    name: "authorized_keys of {{ item }} is writable only by its owner"
    loop_run: awk -F: '!/^#/ && NF >= 7 && $7 !~ /(nologin|false)$/ {print $1}' /etc/passwd
    run: |
      home=$(awk -F: -v user="$CHECKMATE_ITEM" '$1 == user {print $6}' /etc/passwd)
      if [ -f "$home/.ssh/authorized_keys" ]; then
        ls -ln "$home/.ssh/authorized_keys" | cut -c6,9
      else
        echo --
      fi
    expect: "--"
```

Every account gets its own result (`KEYS-root`, `KEYS-alice`, ...), with its own status, waiver and line in the report.

**The item is data from the host.** A file or account name can contain `$(...)`, quotes or a semicolon, and checkmate often runs as root. `run` and `only_if` therefore cannot use `{{ item }}`; the policy is rejected if they do. They read the item from the environment variable `CHECKMATE_ITEM`:

| Shell | Item |
|---|---|
| bash, sh, zsh | `"$CHECKMATE_ITEM"` (always in double quotes) |
| pwsh, powershell | `$env:CHECKMATE_ITEM` |
| cmd | not available, `%CHECKMATE_ITEM%` would be expanded as command text |

Everywhere else (`id`, `name`, `tags`, `when`, `expect`, `remediation`, ...) `{{ item }}` works as in a `loop`, including filters and `item.split(':')[0]`.

The rules:

- `loop_run` takes the same forms as `run`: a command, platform variants or a snippet. It uses the `shell`, `timeout` and working directory of the check.
- One item per line. Surrounding whitespace, empty lines and repeated lines are dropped. Whitespace inside an item becomes `_` in the id.
- No line of output: one result `N/A`. There was nothing to check.
- The command fails (non-zero exit code, timeout, more than 10,000 items): one result `ERROR`. A list that cannot be read must never look compliant.
- A `when` condition that does not mention `item` is evaluated first. If it is false, the command does not run and there is one result `SKIP`.
- That condition may ask for the outcome of an earlier check, see [Checks that depend on other checks](#checks-that-depend-on-other-checks).
- `validate`, `list` and `diff` do not run commands. They show the check once, with `{item}` in place of the item, e.g. `KEYS-{item}`. The same id appears in the results of the three cases above.
- `loop` and `loop_run` cannot be combined.

Each check still collects its own data: the item only says *what* to check, the check's own `run` looks at it.

## Checks that depend on other checks

`register` gives the outcome of a check a name. Checks further down can use it in `when`, so a group of checks only runs where it makes sense:

```yaml
checks:
  - id: NGINX-INSTALLED
    name: nginx is installed
    severity: info
    register: nginx
    run: command -v nginx
    expect: true

  - id: NGINX-TLS
    name: nginx offers TLS 1.2 or newer only
    when: nginx.passed
    run: nginx -T 2>/dev/null | awk '$1 == "ssl_protocols"'
    expect: "!~ TLSv1(\\.1)?[ ;]"
```

Without nginx, `NGINX-TLS` is `SKIP` with the reason `when: nginx.passed is false`.

| Value | Content |
|---|---|
| `name.passed` | The expectation held |
| `name.failed` | The expectation did not hold |
| `name.status` | `pass`, `fail`, `error`, `skip`, `na` or `waived` |
| `name.ran` | The command ran (false for `skip`, `na` and waivers with `skip: true`) |
| `name.rc` | Exit code of the command, `-1` if it did not run |

Only the outcome is available, never the output. A registered check decides *whether* other checks run; every check still collects its own data with its own `run`. That keeps a check understandable and repeatable on its own.

The rules:

- A check can only refer to checks defined before it. This rules out cycles; `validate` reports a reference to a later check.
- The status is what the check found: a failure of low severity that the report shows as `WARN` is still `failed`, and a failure accepted by a waiver is still `failed`.
- The registered check is an ordinary check and appears in the report. If its failure is not a finding (nginx is simply not installed), give it `severity: info`.
- Selecting a check with `--tags` or `--id` also selects the checks it refers to.
- The name must not be a variable or one of `facts`, `vars`, `item`. In a `loop` it needs the item: `register: "svc_{{ item }}"`.
- A `loop_run` check can refer to a registered name: its item command only runs once the conditions hold. It cannot register a name itself, since it stands for many checks.

```yaml
  - id: "NGINX-VHOST-{{ item }}"
    name: "{{ item }} redirects HTTP to HTTPS"
    when: nginx.passed
    loop_run: ls /etc/nginx/sites-enabled
    run: grep -c 'return 301 https://' "/etc/nginx/sites-enabled/$CHECKMATE_ITEM"
    allow_rc: [0, 1]
    expect: ">= 1"
```

## Building command lines from lists

Jinja2 `for` loops are handy for allowlists:

```yaml
run: |
  ss -Hlnt | awk '{print $4}' | sed -E 's/.*:([0-9]+)$/\1/' | sort -nu |
    grep -vxF {% for p in allowed_ports %}-e {{ p }} {% endfor %}
allow_rc: [0, 1]
expect: empty
```

## Braces from other tools

`docker --format`, `kubectl -o go-template` and Helm use Go templates with `{{ }}` as well. Wrap them in a raw block so they reach the tool unchanged:

```yaml
run: docker info --format '{% raw %}{{ .LiveRestoreEnabled }}{% endraw %}'
```

Shell syntax such as `${#array[@]}`, `${var:-default}`, `{ cmd; }` and curl's `%{http_code}` needs no escaping.

## Differences from Jinja2 and Ansible

- **Comments** are written `{## … ##}` instead of `{# … #}`, so shell code like `${#arr}` is not mistaken for a comment.
- **Undefined variables** are an error (strict mode).
- **Ansible-only filters** such as `regex_replace`, `to_json`, `ipaddr` or `b64encode` are not available. The standard Jinja2 filters work: `upper`, `lower`, `replace`, `join`, `default`, `int`, `float`, `length`, `first`, `last`, `sort`, `unique`, `trim`, `title`, and more. Use the shell for anything else.
- `{% include %}` and `{% import %}` are disabled.
