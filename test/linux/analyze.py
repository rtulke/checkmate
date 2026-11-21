#!/usr/bin/env python3
"""Find results that point to broken check commands.

A check may legitimately FAIL or ERROR in a container (no systemd, no
kernel modules, missing tools). What must never happen is a syntax error
in the shell, awk, sed or grep, or an invalid regular expression. This
script reports those, plus every non-passing check of the escape test.
"""
import json
import os
import re
import sys

BROKEN = re.compile(
    r"syntax error|unexpected (token|EOF|end)|unterminated|bad substitution|"
    r"unmatched|invalid (regular expression|character class|preceding|range|"
    r"option|back reference|content of)|unrecognized option|unknown option|"
    r"illegal (option|primary|character)|parse error|runaway|"
    r"(^|\s)(m|g|busybox )?awk: |sed: -e|sed: (bad|unknown|unterminated)|"
    r"grep: (Unmatched|Invalid|brackets|trailing|warning)|"
    r"missing (operand|argument)|cannot compare|is not a number|template|"
    r"invalid check definition|expression",
    re.IGNORECASE,
)
# Environmental problems in containers that are not bugs in the examples.
BENIGN = re.compile(
    r"System has not been booted with systemd|Failed to connect to bus|"
    r"No such file or directory|command not found|Permission denied|"
    r"Operation not permitted|not found or not executable|"
    r"Could not open .*sys/kernel|Read-only file system|"
    # Findings reported by configuration test tools (apachectl, nginx -t).
    r"AH0[0-9]{4}:|nginx: \[emerg\]",
    re.IGNORECASE,
)


def main(out_dir):
    problems = 0
    totals = {}
    for name in sorted(os.listdir(out_dir)):
        if not name.endswith(".json"):
            continue
        m = re.match(r"(.+?)-((?:examples|internal|docs)_.*)$", name[:-5])
        image, policy = (m.group(1), m.group(2)) if m else name[:-5].split("-", 1)
        path = os.path.join(out_dir, name)
        try:
            with open(path) as fh:
                report = json.load(fh)
        except (json.JSONDecodeError, OSError):
            with open(path[:-5] + ".err") as fh:
                err = fh.read().strip()
            print(f"[{image}] {policy}: no report: {err}")
            problems += 1
            continue
        for r in report["results"]:
            totals.setdefault(image, {}).setdefault(r["status"], 0)
            totals[image][r["status"]] += 1
            text = "\n".join(filter(None, [r.get("message", ""), r.get("stderr", "")]))
            escape_test = policy.endswith("escapes")
            broken = BROKEN.search(text) and not BENIGN.search(text)
            if escape_test and r["status"] != "PASS":
                broken = True
            if broken:
                problems += 1
                print(f"[{image}] {policy} {r['id']} {r['status']}: {r.get('message', '')}")
                if r.get("command"):
                    print("    command: " + r["command"].strip().replace("\n", "\n             "))
                if r.get("stderr"):
                    print("    stderr:  " + r["stderr"].strip().replace("\n", "\n             "))
    print()
    for image, counts in sorted(totals.items()):
        summary = ", ".join(f"{k} {v}" for k, v in sorted(counts.items()))
        print(f"{image:10} {summary}")
    print(f"\n{problems} problem(s) found")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
