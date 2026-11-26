#!/bin/sh
# Runs policies over a real SSH connection to this machine and compares the
# results with a local run: --host must find exactly what a local run
# finds. Also checks sudo, timeouts and an unreachable host.
#
# Made for a disposable CI runner: it starts sshd and authorizes a new key
# for the current user.
set -eu
export LC_ALL=C
cd "$(dirname "$0")/../.."

go build -o bin/checkmate ./cmd/checkmate
out=test/linux/out-ssh
rm -rf "$out"
mkdir -p "$out"

command -v sshd >/dev/null 2>&1 || sudo apt-get install -y -q openssh-server >/dev/null
sudo mkdir -p /run/sshd
sudo systemctl start ssh 2>/dev/null || sudo "$(command -v sshd)"
mkdir -p ~/.ssh
chmod 700 ~/.ssh
ssh-keygen -q -t ed25519 -N '' -f "$out/key"
cat "$out/key.pub" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
ssh-keyscan -T 10 localhost 2>/dev/null >> ~/.ssh/known_hosts
printf 'Host localhost\n  IdentityFile %s\n  IdentitiesOnly yes\n' "$PWD/$out/key" >> ~/.ssh/config

status=0
fail() {
    echo "FAILED: $*"
    status=1
}

# One line per result: id and status.
results() {
    jq -r '.results[] | .id + " " + .status' "$1" | sort
}

# Policies that do not read files next to the policy: over SSH a command
# starts in the home directory of the remote user.
policies="examples/getting-started.yml examples/platforms/linux.yml examples/platforms/debian.yml
    examples/system/users.yml examples/system/ssh.yml examples/system/kernel.yml
    examples/system/services.yml examples/system/pam.yml examples/files/permissions.yml
    examples/network/ports.yml"

for policy in $policies; do
    name=$(basename "$policy" .yml)
    for mode in user root; do
        if [ "$mode" = root ]; then
            sudo bin/checkmate run "$policy" --format json > "$out/$name-$mode-local.json" 2>/dev/null || true
            bin/checkmate run "$policy" --host localhost --become --format json > "$out/$name-$mode-ssh.json" 2>/dev/null || true
        else
            bin/checkmate run "$policy" --format json > "$out/$name-$mode-local.json" 2>/dev/null || true
            bin/checkmate run "$policy" --host localhost --format json > "$out/$name-$mode-ssh.json" 2>/dev/null || true
        fi
        results "$out/$name-$mode-local.json" > "$out/$name-$mode-local.txt"
        results "$out/$name-$mode-ssh.json" > "$out/$name-$mode-ssh.txt"
        if [ ! -s "$out/$name-$mode-ssh.txt" ]; then
            fail "$policy as $mode: no results over SSH"
        elif ! diff "$out/$name-$mode-local.txt" "$out/$name-$mode-ssh.txt" > "$out/$name-$mode.diff"; then
            fail "$policy as $mode: local (<) and SSH (>) results differ"
            cat "$out/$name-$mode.diff"
        else
            echo "ok      $policy as $mode: $(wc -l < "$out/$name-$mode-ssh.txt") results match"
        fi
    done
done

# The facts are those of the host, gathered over SSH.
local_facts=$(sudo bin/checkmate run examples/getting-started.yml --format json 2>/dev/null | jq -cS '.facts')
ssh_facts=$(bin/checkmate run examples/getting-started.yml --host localhost --become --format json 2>/dev/null | jq -cS '.facts')
if [ "$local_facts" = "$ssh_facts" ]; then
    echo "ok      facts match: $ssh_facts"
else
    fail "facts differ: local $local_facts, SSH $ssh_facts"
fi

# Quoting, items from the host, a timeout that ends the remote processes.
cat > "$out/probe.yml" <<'POLICY'
name: SSH probe
checks:
  - id: QUOTING
    run: printf '%s\n' "it's" 'say "hi"' '$(id)' | tr '\n' '|'
    expect: "it's|say \"hi\"|$(id)|"
  - id: PIPEFAIL
    run: false | true
    expect: false
  - id: NO-STDIN
    run: cat; echo done
    expect: done
  - id: "ITEM-{{ item }}"
    loop_run: printf 'plain\nwith space\n$(touch /tmp/checkmate-ssh-pwned)\n'
    run: printf %s "$CHECKMATE_ITEM"
    expect: "{{ item }}"
  - id: TIMEOUT
    timeout: 2s
    run: sleep 61 | sleep 61
    expect: true
  - id: NOT-FOUND
    run: no-such-command-on-this-host
    expect: true
POLICY
bin/checkmate run "$out/probe.yml" --host localhost --format json > "$out/probe.json" 2>/dev/null || true
results "$out/probe.json" > "$out/probe.txt"
cat > "$out/probe.want" <<'WANT'
ITEM-$(touch_/tmp/checkmate-ssh-pwned) PASS
ITEM-plain PASS
ITEM-with_space PASS
NO-STDIN PASS
NOT-FOUND ERROR
PIPEFAIL PASS
QUOTING PASS
TIMEOUT ERROR
WANT
if diff "$out/probe.want" "$out/probe.txt"; then
    echo "ok      quoting, items, stdin, timeout and missing command"
else
    fail "probe results differ (< expected, > got)"
    jq -r '.results[] | select(.status != "PASS") | .id + ": " + (.message // "")' "$out/probe.json"
fi
[ ! -e /tmp/checkmate-ssh-pwned ] || fail "an item was executed on the host"
jq -e '.results[] | select(.id == "TIMEOUT") | .message | test("timed out")' "$out/probe.json" >/dev/null ||
    fail "the timeout is not reported as one"
sleep 1
if pgrep -f 'sleep 61' >/dev/null; then
    fail "processes survived the timeout on the host: $(pgrep -af 'sleep 61' | tr '\n' ';')"
else
    echo "ok      no process left on the host after the timeout"
fi

# A host that does not answer ends the run before any check.
if bin/checkmate run "$out/probe.yml" --host localhost:1 > "$out/unreachable.txt" 2>&1; then
    fail "an unreachable host was accepted"
elif grep -q "not reachable" "$out/unreachable.txt"; then
    echo "ok      unreachable host: $(cat "$out/unreachable.txt")"
else
    fail "unreachable host: unexpected message: $(cat "$out/unreachable.txt")"
fi

# No connection may stay behind.
sleep 1
if pgrep -af 'ssh.*/cm-' >/dev/null; then
    fail "an SSH connection was left open: $(pgrep -af 'ssh.*/cm-' | tr '\n' ';')"
else
    echo "ok      connections are closed"
fi

exit $status
