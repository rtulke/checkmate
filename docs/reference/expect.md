# expect operators

`expect` decides whether a check passes. It can look at the exit code, the standard output or the standard error of the command. Output is trimmed of leading and trailing whitespace before it is compared.

## Exit code

```yaml
expect: true        # exit code is 0
expect: false       # exit code is not 0
expect: { rc: "in [0, 100]" }   # explicit comparison
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

## Output checks and exit codes

When `expect` inspects the output, the command must exit with an exit code listed in `allow_rc` (default `[0]`); otherwise the check is an <span class="st st-error">ERROR</span>. Many tools signal "nothing found" with exit code 1, so allow it explicitly:

```yaml
run: grep -E '^[^#]*NOPASSWD' /etc/sudoers
allow_rc: [0, 1]
expect: empty
```
