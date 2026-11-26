# Web endpoints

Black-box checks of websites and APIs with curl: status codes, HTTPS redirects, security headers, response time and version disclosure. curl's -w placeholders such as %{http_code} are not Jinja2 syntax and need no escaping.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/applications/web-endpoints.yml`](https://github.com/rtulke/checkmate/blob/main/examples/applications/web-endpoints.yml)
- :material-format-list-checks: **Checks**  
  7 from 5 definitions, 4 with loops
- :material-monitor: **Platforms**  
  any (POSIX shell)

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/applications/web-endpoints.yml

# Run the checks
checkmate run examples/applications/web-endpoints.yml

# Override a variable from the command line
checkmate run examples/applications/web-endpoints.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `WEB-STATUS-example.com` | https://example.com answers with HTTP 200 | <span class="sev sev-high">high</span> | applications, web |
| `WEB-REDIRECT-example.com` | http://example.com redirects to HTTPS | <span class="sev sev-medium">medium</span> | applications, web, tls |
| `WEB-TIME-example.com` | https://example.com responds within 2 seconds | <span class="sev sev-low">low</span> | applications, web, performance |
| `WEB-HEADER-strict-transport-security` | Security header strict-transport-security is set | <span class="sev sev-medium">medium</span> | applications, web |
| `WEB-HEADER-x-content-type-options` | Security header x-content-type-options is set | <span class="sev sev-medium">medium</span> | applications, web |
| `WEB-HEADER-content-security-policy` | Security header content-security-policy is set | <span class="sev sev-medium">medium</span> | applications, web |
| `WEB-SERVER-VERSION` | The Server header does not reveal a version | <span class="sev sev-low">low</span> | applications, web |

## Policy

```yaml title="examples/applications/web-endpoints.yml" linenums="1"
name: Web endpoints
version: 1.0.0
description: >
  Black-box checks of websites and APIs with curl: status codes, HTTPS
  redirects, security headers, response time and version disclosure.
  curl's -w placeholders such as %{http_code} are not Jinja2 syntax and
  need no escaping.

vars:
  urls: [https://example.com]
  http_hosts: [example.com]
  max_response_seconds: 2
  security_headers: [strict-transport-security, x-content-type-options, content-security-policy]

checks:
  - id: "WEB-STATUS-{{ item | replace('https://', '') | replace('/', '_') }}"
    name: "{{ item }} answers with HTTP 200"
    tags: [applications, web]
    severity: high
    loop: "{{ urls }}"
    timeout: 20s
    run: curl -s -o /dev/null --max-time 15 -w '%{http_code}' {{ item }}
    expect: "== 200"
    rationale: "Any other status means that users do not get the page at {{ item }}."
    remediation: "Check the web server and the application behind {{ item }} and their logs."

  - id: "WEB-REDIRECT-{{ item }}"
    name: "http://{{ item }} redirects to HTTPS"
    tags: [applications, web, tls]
    loop: "{{ http_hosts }}"
    timeout: 20s
    run: curl -s -o /dev/null --max-time 15 -w '%{http_code} %{redirect_url}' http://{{ item }}/
    expect: "~ ^30[178] https://"
    rationale: "Without the redirect visitors who type {{ item }} stay on unencrypted HTTP."
    remediation: "Make the web server for {{ item }} answer plain HTTP with a 301 redirect to the https URL."

  - id: "WEB-TIME-{{ item | replace('https://', '') | replace('/', '_') }}"
    name: "{{ item }} responds within {{ max_response_seconds }} seconds"
    tags: [applications, web, performance]
    severity: low
    loop: "{{ urls }}"
    timeout: 20s
    run: curl -s -o /dev/null --max-time 15 -w '%{time_total}' {{ item }}
    expect: "< {{ max_response_seconds }}"
    rationale: A slow answer points to an overloaded or failing component before users report an outage.
    remediation: "Look for the slow component in the web server and application logs of {{ item }}."

  - id: "WEB-HEADER-{{ item }}"
    name: "Security header {{ item }} is set"
    tags: [applications, web]
    loop: "{{ security_headers }}"
    timeout: 20s
    run: |
      curl -s -D - -o /dev/null --max-time 15 {{ urls[0] }} | tr -d '\r' | grep -i '^{{ item }}:'
    allow_rc: [0, 1]
    expect: "!empty"
    rationale: "Without {{ item }} browsers do not apply the protection that this header switches on."
    remediation: "Send the {{ item }} header from the web server or the application."

  - id: WEB-SERVER-VERSION
    name: The Server header does not reveal a version
    tags: [applications, web]
    severity: low
    timeout: 20s
    run: |
      curl -s -D - -o /dev/null --max-time 15 {{ urls[0] }} | tr -d '\r' | grep -i '^server:'
    allow_rc: [0, 1]
    expect: "!~ [0-9]+\\.[0-9]+"
    rationale: A version number in the Server header tells an attacker which known vulnerabilities to try.
    remediation: Switch off the version output, for example with `server_tokens off` in nginx or `ServerTokens Prod` in Apache.
```
