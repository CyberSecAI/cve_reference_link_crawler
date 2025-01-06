#!/bin/bash

# Create directory for big files
mkdir -p tmp/big_files

# Find files >= 20MB and move them while preserving path information
find ./data_out -type f -size +10M -print0 | while IFS= read -r -d '' file; do
    # Get the original path for logging
    echo "Original location: $file"
    
    # Create path hash to avoid collisions
    path_hash=$(echo "$file" | md5sum | cut -d' ' -f1)
    
    # Move the file
    mv "$file" "tmp/big_files/${path_hash}_$(basename "$file")"
done