#!/bin/bash

# Create a directory to keep things organized
mkdir -p test_transfer
cd test_transfer || exit

echo "Generating test files..."

# 1. Create a simple text file
echo "This is a small text file for testing." > small_file.txt

# 2. Create a 1MB dummy file (useful for speed tests)
# 'if' is input file, 'of' is output file, 'bs' is block size, 'count' is number of blocks
dd if=/dev/zero of=medium_file.dat bs=1M count=1 status=none

# 3. Create a 10MB dummy file
dd if=/dev/zero of=large_file.bin bs=1M count=10 status=none

# 4. Create a file with specific permissions (to test if they persist)
echo "This file has restricted permissions." > restricted.txt
chmod 600 restricted.txt

# 5. Create a hidden file
echo "I am a hidden file." > .hidden_test

echo "Done! Files created in: $(pwd)"
ls -la