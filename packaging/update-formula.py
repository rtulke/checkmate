#!/usr/bin/env python3
"""Sets url and sha256 of the stable version in the Homebrew formula.

    update-formula.py Formula/checkmate.rb <url> <sha256>
"""
import re
import sys

path, url, sha = sys.argv[1:4]
text = open(path).read()
text = re.sub(r'^  url ".*"\n  sha256 ".*"\n', "", text, flags=re.M)
text = text.replace('  license "', f'  url "{url}"\n  sha256 "{sha}"\n  license "', 1)
open(path, "w").write(text)
