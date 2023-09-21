#!/bin/bash

# Check if the correct number of arguments are provided
if [ $# -ne 3 ]; then
  echo "Usage: $0 <pattern_to_match> <config_file> <new_line>"
  exit 1
fi

# Assign command-line arguments to variables
pattern_to_match="$1"
config_file="$2"
new_line="$3"

# Check if the config file exists
if [ ! -f "$config_file" ]; then
  echo "Config file not found: $config_file"
  exit 1
fi

# Escape special characters in the pattern
escaped_pattern=$(sed 's/[][\/.^$*]/\\&/g' <<< "$pattern_to_match")

# Get the indentation of the pattern line
indentation=$(sed -n "/$escaped_pattern/{s/^\([[:space:]]*\).*$/\1/;p;q}" "$config_file")

# Check if the new line already exists after the pattern line
if grep -qFx "${indentation}${new_line}" "$config_file"; then
  echo "The new line already exists after the pattern. No duplicate line added."
else
  # Use sed to insert the new line under the pattern with the same indentation
  sed -i "\%$escaped_pattern%a\\${indentation}${new_line}" "$config_file"
  echo "New line added under the pattern '$pattern_to_match' with correct indentation."
fi
