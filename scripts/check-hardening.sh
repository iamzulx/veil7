#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "== source hardening tests =="
cargo test --test hardening

echo "== unsafe confinement =="
python3 - <<'PY'
from pathlib import Path
root = Path('src')
violations = []
for path in sorted(root.rglob('*.rs')):
    rel = path.as_posix()
    if rel == 'src/layers/l0_memlock.rs':
        continue
    for idx, raw in enumerate(path.read_text().splitlines(), 1):
        code = raw.split('//', 1)[0]
        needles = (
            'unsafe {',
            'unsafe{',
            'unsafe fn',
            'unsafe impl',
            'unsafe trait',
            'unsafe extern',
            '#![allow(unsafe_code)]',
        )
        if any(n in code for n in needles):
            violations.append(f'{rel}:{idx}: {raw}')
if violations:
    print('\n'.join(violations))
    raise SystemExit(1)
PY

echo "== secret-path div/rem source scan =="
python3 - <<'PY'
from pathlib import Path
secret_paths = [
    Path('src/layers/l1_entropy.rs'),
    Path('src/layers/l2_keygen.rs'),
    Path('src/layers/l4_prove.rs'),
    Path('src/layers/l5_verify.rs'),
    Path('src/pq_backends/slh_dsa.rs'),
]
violations = []
for path in secret_paths:
    for idx, raw in enumerate(path.read_text().splitlines(), 1):
        code = raw.split('//', 1)[0]
        compact = ''.join(code.split())
        if '/' in compact or '%' in compact or '.div_' in compact or '.rem_' in compact:
            violations.append(f'{path}:{idx}: {raw}')
if violations:
    print('\n'.join(violations))
    raise SystemExit(1)
PY

echo "== symbolized objdump timing-instruction report =="
cargo build --profile hardening
BIN="target/hardening/veil7"
OBJDUMP="${OBJDUMP:-objdump}"
if command -v "$OBJDUMP" >/dev/null 2>&1; then
    "$OBJDUMP" -d -C "$BIN" | python3 scripts/scan-secret-div.py
else
    echo "objdump unavailable; skipping binary instruction scan"
fi
