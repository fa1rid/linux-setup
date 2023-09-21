#!/bin/bash

# Check if the correct number of arguments is provided
if [ "$#" -ne 3 ]; then
  echo "Usage: $0 <search_pattern> <config_file> <comment/uncomment>"
  exit 1
fi

search_pattern="$1"
config_file="$2"
comment_uncomment="$3"

# Check if the config file exists
if [ ! -f "$config_file" ]; then
  echo "Error: Config file '$config_file' not found."
  exit 1
fi

# Define the AWK script
awk_script='
{
  # Count leading whitespace (tabs or spaces)
  whitespace_count = match($0, /^[ \t]*/)
  whitespace = substr($0, RSTART, RLENGTH)
  line = substr($0, RLENGTH + 1)

  # Check if the line matches the search pattern
  if ($0 ~ search_pattern) {
    if (comment_uncomment == "comment" && substr(line, 1, 1) != "#") {
      # Comment the line and add a space after the comment symbol if needed
      if (substr(line, 1, 1) != " ") {
        line = " " line
      }
      $0 = whitespace "#" line
    } else if (comment_uncomment == "uncomment") {
      # Uncomment the line and remove all preceding comment symbols and spaces
      sub(whitespace "[# ]*", whitespace, $0)
    }
  }

  # Print the modified line
  print
}
'

# Use AWK to process the config file and redirect the output to a temporary file
awk -v search_pattern="$search_pattern" -v comment_uncomment="$comment_uncomment" "$awk_script" "$config_file" > "$config_file.tmp"

# Replace the original config file with the temporary file
mv "$config_file.tmp" "$config_file"

echo "Done. Configuration file '$config_file' has been modified."
