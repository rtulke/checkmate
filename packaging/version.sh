#!/bin/sh
# Prints the package version: 2.1.0 for the tag v2.1.0, otherwise
# 0.0.0~git<commits>.<sha>, which sorts below every release in dpkg and rpm.
# Only release tags count; the rolling "latest" tag can point to the same commit.
tag=$(git describe --tags --exact-match --match 'v[0-9]*' 2>/dev/null)
if [ -n "$tag" ]; then
  echo "${tag#v}"
else
  echo "0.0.0~git$(git rev-list --count HEAD 2>/dev/null || echo 0).$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
fi
