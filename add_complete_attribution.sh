#!/bin/bash

# Add complete author attribution to all Rust source files
USERNAME="Iamzulx"
YEAR="2026"
HEADER="// Author: $USERNAME
// Copyright (c) $YEAR
// License: MIT"

# Find all Rust files
find /data/data/com.termux/files/home/xxx/src -name '*.rs' -type f | while read file; do
    # Check if file already has the complete header
    if ! head -3 "$file" | grep -q "Author: $USERNAME"; then
        echo "WARNING: $file does not have author header"
    elif ! head -3 "$file" | grep -q "Copyright (c) $YEAR"; then
        # Has author but missing copyright/license
        echo "Updating: $file"
        
        # Create temp file with complete header
        temp_file=$(mktemp)
        echo "$HEADER" > "$temp_file"
        
        # Skip the old "// Author: Iamzulx" line and add rest of file
        tail -n +2 "$file" >> "$temp_file"
        mv "$temp_file" "$file"
        echo "  ✓ Added copyright and license"
    else
        echo "Already complete: $file"
    fi
done

echo "Done!"
