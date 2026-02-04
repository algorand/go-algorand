#!/bin/bash
# Find error sentinel definitions in the codebase and their string values
# Output: JSON lines with file, line, varname, message

# Find var declarations with errors.New
grep -rn --include='*.go' -E '^var [A-Za-z_][A-Za-z0-9_]* = errors\.New\(' . | \
  grep -v '_test\.go' | \
  grep -v '/vendor/' | \
  grep -v '/test/' | \
  while IFS= read -r line; do
    file=$(echo "$line" | cut -d: -f1)
    lineno=$(echo "$line" | cut -d: -f2)
    content=$(echo "$line" | cut -d: -f3-)

    # Extract variable name
    varname=$(echo "$content" | sed -n 's/^var \([A-Za-z_][A-Za-z0-9_]*\) =.*/\1/p')

    # Extract message (handle both " and ` quotes)
    msg=$(echo "$content" | sed -n 's/.*errors\.New("\([^"]*\)".*/\1/p')
    if [ -z "$msg" ]; then
      msg=$(echo "$content" | sed -n "s/.*errors\.New(\`\([^\`]*\)\`.*/\1/p")
    fi

    if [ -n "$varname" ] && [ -n "$msg" ]; then
      msg_escaped=$(echo "$msg" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g')
      echo "{\"file\":\"$file\",\"line\":$lineno,\"var\":\"$varname\",\"msg\":\"$msg_escaped\"}"
    fi
  done

# Find var declarations with fmt.Errorf (static messages only - no %v etc)
grep -rn --include='*.go' -E '^var [A-Za-z_][A-Za-z0-9_]* = fmt\.Errorf\(' . | \
  grep -v '_test\.go' | \
  grep -v '/vendor/' | \
  grep -v '/test/' | \
  grep -v '%[svdwqxXfFeEgGtTpbc]' | \
  while IFS= read -r line; do
    file=$(echo "$line" | cut -d: -f1)
    lineno=$(echo "$line" | cut -d: -f2)
    content=$(echo "$line" | cut -d: -f3-)

    varname=$(echo "$content" | sed -n 's/^var \([A-Za-z_][A-Za-z0-9_]*\) =.*/\1/p')
    msg=$(echo "$content" | sed -n 's/.*fmt\.Errorf("\([^"]*\)".*/\1/p')

    if [ -n "$varname" ] && [ -n "$msg" ]; then
      msg_escaped=$(echo "$msg" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g')
      echo "{\"file\":\"$file\",\"line\":$lineno,\"var\":\"$varname\",\"msg\":\"$msg_escaped\"}"
    fi
  done

# Find indented assignments in var blocks (no "var" keyword, starts with tab/spaces)
grep -rn --include='*.go' -E '^	[A-Za-z][A-Za-z0-9_]* = errors\.New\(' . | \
  grep -v '_test\.go' | \
  grep -v '/vendor/' | \
  grep -v '/test/' | \
  while IFS= read -r line; do
    file=$(echo "$line" | cut -d: -f1)
    lineno=$(echo "$line" | cut -d: -f2)
    content=$(echo "$line" | cut -d: -f3-)

    # Skip common local var names
    if echo "$content" | grep -qE '^\s*(err|e) = '; then
      continue
    fi

    varname=$(echo "$content" | sed -n 's/^	\([A-Za-z][A-Za-z0-9_]*\) =.*/\1/p')
    msg=$(echo "$content" | sed -n 's/.*errors\.New("\([^"]*\)".*/\1/p')
    if [ -z "$msg" ]; then
      msg=$(echo "$content" | sed -n "s/.*errors\.New(\`\([^\`]*\)\`.*/\1/p")
    fi

    if [ -n "$varname" ] && [ -n "$msg" ]; then
      msg_escaped=$(echo "$msg" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g')
      echo "{\"file\":\"$file\",\"line\":$lineno,\"var\":\"$varname\",\"msg\":\"$msg_escaped\"}"
    fi
  done
