# expect operators

`expect` decides whether a check passes. It can look at the exit code, the standard output or the standard error of the command. Output is trimmed of leading and trailing whitespace before it is compared.

## Exit code

```yaml
expect: true                   # exit code is 0
expect: false                  # exit code is not 0
expect: { rc: "in [0, 100]" }  # explicit comparison
```

## Comparing the output

| Operator | Meaning | Example |
|---|---|---|
| `==` | equal | `"== active"` |
| `!=` | not equal | `"!= disabled"` |
| `>` `>=` `<` `<=` | numeric (or version) comparison | `">= 500"` |
| `!>` | not greater, same as `<=` | `"!> 90"` |
| `!<` | not less, same as `>=` | `"!< 2"` |
| `~` | matches a regular expression | `"~ ^PermitRootLogin no$"` |
| `!~` | does not match | `"!~ (cbc\|arcfour)"` |
| `in` | is one of a list | `"in [xfs, ext4]"` |
| `!in` | is none of a list | `"!in [trusted]"` |
| `empty` | no output | `empty` |
| `!empty` | some output | `"!empty"` |

A value without an operator means equality: `expect: active` is the same as `expect: "== active"`.

!!! tip "Quote expectations"
    Write expectations as quoted strings. Unquoted `>= 5` is still valid YAML, but `!empty` starts a YAML tag and `"== Status: active"` contains `": "`, so quoting everything avoids surprises.

### Numbers, versions and strings

With the default `as: auto`, both sides are compared as numbers if both are numbers (`1.0 == 1`, `10 > 9`), and as strings otherwise. Ordering operators (`>`, `<`, …) on non-numbers are an **error**, never a silent string comparison.

```yaml
- run: sw_vers -productVersion
  as: version          # 14.10 > 14.9, 5.14.0-427.el9 > 5.14.0-70.el9
  expect: ">= 14.0"

- run: awk '$1 == "UMASK" {print $2}' /etc/login.defs
  as: string           # "027" must not become the number 27
  expect: "in ['027', '077']"
```

### Regular expressions

Regular expressions use [Go RE2 syntax](https://github.com/google/re2/wiki/Syntax) and run in multi-line mode, so `^` and `$` match at line boundaries. Inline flags work: `"~ (?i)enabled"`.

In double-quoted YAML strings a backslash must be doubled; single-quoted strings keep it as is:

```yaml
expect: "~ ^v[0-9]+\\.[0-9]+$"
expect: '~ ^v\d+\.\d+$'
```

### Lists

`in` and `!in` accept a YAML flow list or a comma-separated list. Values can contain spaces, and lists can come from variables:

```yaml
expect: "in [644 root root, 640 root shadow]"
expect: "in {{ allowed_values }}"
```

## Line count

```yaml
expect: { lines: "== 0" }   # number of non-empty lines of stdout
expect: { lines: ">= 2" }
```

## Standard error

```yaml
# apachectl prints "Syntax OK" on stderr
expect: { stderr: "~ Syntax OK" }
expect: { stdout: empty, stderr: "== done" }
```

## Combining conditions

A list means **all** conditions must hold, `any` means **at least one**:

```yaml
expect: ["!empty", "<= 5", "> 0"]
expect: { any: [empty, "~ => disabled"] }
expect: { all: ["~ ok", { rc: "== 0" }] }
```

## Negation

`not` inverts any expectation, including groups and conditionals:

```yaml
expect: { not: "~ (telnet|rsh)" }
expect: { not: { any: ["== disabled", "== masked"] } }
```

## Every line, some line, no line

`each`, `some` and `none` apply conditions to every non-empty line of stdout. This removes the need to squeeze a listing into a single value with awk:

```yaml
# Every filesystem below 90 % usage
run: df -P | awk 'NR > 1 {sub(/%/, "", $5); print $5}'
expect: { each: "< 90" }

# At least one selected time source (chrony marks it with ^*)
run: chronyc -n sources
expect: { some: "~ ^\\^\\*" }

# No line enables root login
run: sshd -T
expect: { none: "~ ^permitrootlogin yes" }

# Several conditions per line
expect: { each: ["~ ^/", "!~ /tmp"] }
```

| Key | Holds when | Empty output |
|---|---|---|
| `each` | every line satisfies all conditions | holds |
| `some` | at least one line satisfies all conditions | does not hold |
| `none` | no line satisfies all conditions | holds |

Combine `each` with `"!empty"` if there must be at least one line.

## Conditional expectations

`if` / `then` / `else` select an expectation based on another one. Each part can be any expectation, including other conditionals:

```yaml
# Ubuntu needs 24.04, everything else at least release 12
run: . /etc/os-release && echo "$ID $VERSION_ID"
expect:
  if: { stdout: "~ ^ubuntu" }
  then: { stdout: "~ 2[4-9]\\." }
  else: { stdout: "~ (1[2-9]|[2-9][0-9])" }

# If cups is installed, it must not be running
run: systemctl is-active cups
allow_rc: [0, 3, 4]        # 3 = inactive, 4 = no such unit
expect:
  if: { rc: "!= 4" }
  then: "!= active"
```

Without `else`, the expectation holds when the condition does not.

### Conditions on facts and variables

The condition of `if` looks at the command output. To choose an expectation by **facts or variables**, use Jinja2 directly in `expect`, or split the check with `when`:

```yaml
# Inline Jinja2 condition
expect: "{{ '>= 9' if facts.distro == 'rhel' else '>= 12' }}"

# Two checks with when
- id: KERNEL-RHEL
  when: facts.distro == "rhel"
  run: rpm -E %rhel
  expect: ">= 9"
- id: KERNEL-DEBIAN
  when: facts.distro == "debian"
  run: cut -d. -f1 /etc/debian_version
  expect: ">= 12"
```

## Building blocks at a glance

| Building block | Example |
|---|---|
| exit code | `true`, `false`, `{ rc: "in [0, 100]" }` |
| comparison | `"== x"`, `">= 5"`, `"!> 90"`, `"in [a, b]"`, `"~ regex"`, `empty` |
| other target | `{ stderr: … }`, `{ lines: … }` |
| all / any | `["!empty", "<= 5"]`, `{ any: [a, b] }` |
| negation | `{ not: … }` |
| per line | `{ each: … }`, `{ some: … }`, `{ none: … }` |
| conditional | `{ if: …, then: …, else: … }` |

All of them nest freely:

```yaml
expect:
  all:
    - { lines: ">= 1" }
    - { each: ["~ ^[a-z]", "!~ (?i)deprecated"] }
    - if: { some: "~ ^ssl" }
      then: { none: "~ ^ssl_protocols .*TLSv1(\\.1)?[ ;]" }
```

## Output checks and exit codes

When `expect` inspects the output, the command must exit with an exit code listed in `allow_rc` (default `[0]`); otherwise the check is an <span class="st st-error">ERROR</span>. Many tools signal "nothing found" with exit code 1, so allow it explicitly:

```yaml
run: grep -E '^[^#]*NOPASSWD' /etc/sudoers
allow_rc: [0, 1]
expect: empty
```
