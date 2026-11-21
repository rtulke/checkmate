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
| `item` | The current loop item |
| `arg`, `args` | Snippet arguments (inside snippets) |
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
