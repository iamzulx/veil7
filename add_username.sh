#!/bin/bash

# Add username comment to all Rust source files
USERNAME="Iamzulx"
HEADER="// Author: $USERNAME"

# Find all Rust files
find /data/data/com.termux/files/home/xxx/src -name '*.rs' -type f | while read file; do
    # Check if file already has the header
    if ! head -1 "$file" | grep -q "Author: $USERNAME"; then
        # Add header at the top
        temp_file=$(mktemp)
        echo "$HEADER" > "$temp_file"
        cat "$file" >> "$temp_file"
        mv "$temp_file" "$file"
        echo "Added header to: $file"
    else
        echo "Header already exists in: $file"
    fi
done

echo "Done!"
