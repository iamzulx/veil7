#!/usr/bin/env bash
# SBOM (Software Bill of Materials) generator for veil7.
#
# Generates a CycloneDX-compatible SBOM in JSON format using cargo-tree.
#
# Usage:
#   bash scripts/generate-sbom.sh              # outputs to sbom.json
#   bash scripts/generate-sbom.sh output.json  # custom output path

set -euo pipefail

OUTPUT="${1:-sbom.json}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "Generating SBOM for veil7..."

TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
CARGO_VER=$(cargo --version 2>/dev/null | awk '{print $2}' || echo "unknown")

# Get dependency lines:
# 1. cargo tree outputs lines like "├── getrandom v0.2.17 MIT OR Apache-2.0"
# 2. Strip all non-ASCII chars (tree drawing characters)
# 3. Remove "(proc-macro)" annotations
# 4. Parse: first word = name, second = version, rest = license
# 5. Skip the root crate (veil7) and deduplicate
DEP_DATA=$(HOME="$HOME" cargo tree --format '{p} {l}' 2>/dev/null \
    | LC_ALL=C tr -d '\200-\377' \
    | sed 's/(proc-macro)//g' \
    | sed 's/^[[:space:]]*//' \
    | awk 'NF >= 2 {
        name = $1;
        version = $2;
        license = "";
        for (i = 3; i <= NF; i++) license = license (i > 3 ? " " : "") $i;
        if (license == "") license = "unknown";
        print name "|" version "|" license
    }' \
    | sort -u -t'|' -k1,2 \
    | grep -v '^veil7|' || true)

DEP_COUNT=0
if [ -n "$DEP_DATA" ]; then
    DEP_COUNT=$(echo "$DEP_DATA" | wc -l | tr -d ' ')
fi

# Write JSON header
cat > "$OUTPUT" << EOF
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "timestamp": "$TIMESTAMP",
    "component": {
      "type": "library",
      "name": "veil7",
      "version": "0.1.0",
      "description": "Stateless 7-layer universal post-quantum verification engine",
      "purl": "pkg:cargo/veil7@0.1.0"
    },
    "tools": [{ "name": "cargo-tree", "version": "$CARGO_VER" }]
  },
  "components": [
EOF

# Write each component
FIRST=true
if [ -n "$DEP_DATA" ]; then
    while IFS='|' read -r name version license; do
        [ -z "$name" ] && continue
        if [ "$FIRST" = true ]; then
            FIRST=false
        else
            printf ',\n' >> "$OUTPUT"
        fi
        license_esc=$(printf '%s' "$license" | sed 's/\\/\\\\/g; s/"/\\"/g')
        printf '    { "type": "library", "name": "%s", "version": "%s", "licenses": [{"license": {"name": "%s"}}], "purl": "pkg:cargo/%s@%s" }' \
            "$name" "$version" "$license_esc" "$name" "$version" >> "$OUTPUT"
    done <<< "$DEP_DATA"
fi

# Close JSON
printf '\n  ]\n}\n' >> "$OUTPUT"

echo "SBOM generated: $OUTPUT ($DEP_COUNT dependencies)"
