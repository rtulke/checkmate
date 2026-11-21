#!/usr/bin/env python3
"""Reports broken checks in a checkmate JSON report of a Windows run.

A check is broken if it ends in ERROR, or if it passes although the command
wrote to stderr. FAIL results are findings on the runner, not broken checks.
Exit code 1 if anything is broken.
"""
import collections
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8-sig"))
facts = report["facts"]
print(f"{facts.get('distro_name')} {facts.get('version')} elevated={facts.get('is_root')}")
print(dict(collections.Counter(r["status"] for r in report["results"])))

problems = 0
for r in report["results"]:
    stderr = (r.get("stderr") or "").strip()
    if r["status"] == "ERROR" or (r["status"] == "PASS" and stderr):
        problems += 1
        print(f"\n[{r['status']}] {r['id']}: {r.get('message', '')}")
        if stderr:
            print("  stderr: " + stderr.replace("\n", "\n          ")[:600])
print(f"\n{problems} problem(s) found")
sys.exit(1 if problems else 0)
