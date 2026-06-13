#!/usr/bin/env python3
"""Fail if objdump shows variable-latency division in veil7 secret-path symbols.

This is intentionally symbol-scoped. Full release binaries include std and
third-party dependency code where public-data division is normal; a global
`grep div` is too noisy and would hide useful regressions behind false positives.
"""

from __future__ import annotations

import re
import sys

DIV_RE = re.compile(r"\b(?:idiv|div|udiv|sdiv)\b")
SYMBOL_RE = re.compile(r"^[0-9a-fA-F]+ <(.+)>:")

SECRET_SYMBOL_HINTS = (
    "veil7::layers::l1_entropy",
    "veil7::layers::l2_keygen",
    "veil7::layers::l4_prove",
    "veil7::layers::l5_verify",
    "veil7::pq_backends::slh_dsa",
)

current = ""
violations: list[str] = []

for line in sys.stdin:
    match = SYMBOL_RE.match(line)
    if match:
        current = match.group(1)
        continue

    if not current or not any(hint in current for hint in SECRET_SYMBOL_HINTS):
        continue

    if DIV_RE.search(line):
        violations.append(f"{current}: {line.strip()}")

if violations:
    print("division-like instruction in veil7 secret-path symbol:")
    print("\n".join(violations))
    raise SystemExit(1)

print("no division-like instruction found in veil7 secret-path symbols")
