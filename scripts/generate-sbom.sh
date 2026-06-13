#!/usr/bin/env bash
# SBOM (Software Bill of Materials) generator for veil7.
#
# Generates a CycloneDX-compatible SBOM in JSON format using cargo-tree.
# Can be used standalone or in CI for supply chain transparency.
#
# Usage:
#   bash scripts/generate-sbom.sh              # outputs to sbom.json
#   bash scripts/generate-sbom.sh output.json  # custom output path
#
# Requirements: cargo (Rust toolchain)

set -euo pipefail

OUTPUT="${1:-sbom.json}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "Generating SBOM for veil7..."

# Collect dependency info: name, version, license, source
DEPS=$(cargo tree --format '{"name":"{p}","license":"{l}"}' 2>/dev/null | sort -u)

# Count dependencies
DEP_COUNT=$(echo "$DEPS" | wc -l)

# Generate CycloneDX-like JSON
cat > "$OUTPUT" << HEADER
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "component": {
      "type": "library",
      "name": "veil7",
      "version": "0.1.0",
      "description": "Stateless 7-layer universal post-quantum verification engine",
      "purl": "pkg:cargo/veil7@0.1.0"
    },
    "tools": [
      {
        "name": "cargo-tree",
        "version": "$(cargo --version 2>/dev/null | awk '{print $2}')"
      }
    ]
  },
  "components": [
HEADER

# Add each dependency as a component
FIRST=true
cargo tree --format '{n}|{v}|{l}' 2>/dev/null | sort -u -t'|' -k1,2 | while IFS='|' read -r name version license; do
    # Skip the root crate itself
    [ "$name" = "veil7" ] && continue

    if [ "$FIRST" = true ]; then
        FIRST=false
    else
        echo ","
    fi

    # Escape license field for JSON
    license_json=$(echo "$license" | sed 's/"/\\"/g')

    cat << ENTRY
    {
      "type": "library",
      "name": "$name",
      "version": "$version",
      "licenses": [{"license": {"name": "$license_json"}}],
      "purl": "pkg:cargo/$name@$version"
    }
ENTRY
done >> "$OUTPUT"

# Close JSON
cat >> "$OUTPUT" << FOOTER

  ]
}
FOOTER

echo "✅ SBOM generated: $OUTPUT ($DEP_COUNT dependencies)"
