# Docker

Docker daemon configuration and running containers. `docker --format` uses Go templates ({{ ... }}), which collide with Jinja2; wrap them in {% raw %}...{% endraw %} so they reach docker unchanged.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/applications/docker.yml`](https://github.com/rtulke/checkmate/blob/main/examples/applications/docker.yml)
- :material-format-list-checks: **Checks**  
  8 from 8 definitions
- :material-monitor: **Platforms**  
  any (POSIX shell)

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/applications/docker.yml

# Run the checks
checkmate run examples/applications/docker.yml
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `DOCKER-001` | The Docker socket is only accessible by root and the docker group | <span class="sev sev-high">high</span> | applications, docker |
| `DOCKER-002` | No container runs privileged | <span class="sev sev-critical">critical</span> | applications, docker |
| `DOCKER-003` | No container uses the host network | <span class="sev sev-high">high</span> | applications, docker |
| `DOCKER-004` | No container mounts the Docker socket | <span class="sev sev-critical">critical</span> | applications, docker |
| `DOCKER-005` | Containers do not run as root | <span class="sev sev-medium">medium</span> | applications, docker |
| `DOCKER-006` | live-restore keeps containers running during daemon restarts | <span class="sev sev-low">low</span> | applications, docker |
| `DOCKER-007` | Container logs go to a central driver | <span class="sev sev-low">low</span> | applications, docker, logging |
| `DOCKER-008` | Every running container has a memory limit | <span class="sev sev-medium">medium</span> | applications, docker, resources |

## Policy

```yaml title="examples/applications/docker.yml" linenums="1"
name: Docker
version: 1.0.0
description: >
  Docker daemon configuration and running containers. `docker --format`
  uses Go templates ({{ ... }}), which collide with Jinja2; wrap them in
  {% raw %}...{% endraw %} so they reach docker unchanged.

checks:
  - id: DOCKER-001
    name: The Docker socket is only accessible by root and the docker group
    tags: [applications, docker]
    severity: high
    only_if: test -S /var/run/docker.sock
    run: stat -c '%a %U %G' /var/run/docker.sock
    expect: "== 660 root docker"

  - id: DOCKER-002
    name: No container runs privileged
    tags: [applications, docker]
    severity: critical
    only_if: docker info >/dev/null 2>&1
    run: |
      docker ps -q | xargs -r docker inspect --format '{% raw %}{{ .Name }} {{ .HostConfig.Privileged }}{% endraw %}' |
        awk '$2 == "true" {print $1}'
    expect: empty

  - id: DOCKER-003
    name: No container uses the host network
    tags: [applications, docker]
    severity: high
    only_if: docker info >/dev/null 2>&1
    run: |
      docker ps -q | xargs -r docker inspect --format '{% raw %}{{ .Name }} {{ .HostConfig.NetworkMode }}{% endraw %}' |
        awk '$2 == "host" {print $1}'
    expect: empty

  - id: DOCKER-004
    name: No container mounts the Docker socket
    tags: [applications, docker]
    severity: critical
    only_if: docker info >/dev/null 2>&1
    run: |
      docker ps -q | xargs -r docker inspect --format '{% raw %}{{ .Name }}{{ range .Mounts }} {{ .Source }}{{ end }}{% endraw %}' |
        grep 'docker\.sock' | awk '{print $1}'
    allow_rc: [0, 1]
    expect: empty

  - id: DOCKER-005
    name: Containers do not run as root
    tags: [applications, docker]
    only_if: docker info >/dev/null 2>&1
    run: |
      docker ps -q | xargs -r docker inspect --format '{% raw %}{{ .Name }} {{ if .Config.User }}{{ .Config.User }}{{ else }}root{{ end }}{% endraw %}' |
        awk '$2 == "root" || $2 == "0" || $2 ~ /^0:/ {print $1}'
    expect: empty

  - id: DOCKER-006
    name: live-restore keeps containers running during daemon restarts
    tags: [applications, docker]
    severity: low
    only_if: docker info >/dev/null 2>&1
    run: docker info --format '{% raw %}{{ .LiveRestoreEnabled }}{% endraw %}'
    expect: "== true"

  - id: DOCKER-007
    name: Container logs go to a central driver
    tags: [applications, docker, logging]
    severity: low
    only_if: docker info >/dev/null 2>&1
    run: docker info --format '{% raw %}{{ .LoggingDriver }}{% endraw %}'
    expect: "in [journald, syslog, fluentd, gelf, awslogs, splunk]"

  - id: DOCKER-008
    name: Every running container has a memory limit
    tags: [applications, docker, resources]
    only_if: docker info >/dev/null 2>&1
    run: |
      docker ps -q | xargs -r docker inspect --format '{% raw %}{{ .Name }} {{ .HostConfig.Memory }}{% endraw %}' |
        awk '$2 == 0 {print $1}'
    expect: empty
```
