#!/bin/bash
# Called at SessionStart - outputs state for Claude to read
set -e

STATE_FILE="$CLAUDE_PROJECT_DIR/.claude/state.local.log"

if [ -f "$STATE_FILE" ]; then
  echo "=== CHIEF OF STAFF STATE (from previous session) ==="
  cat "$STATE_FILE"
  echo "=== END STATE ==="

  # Check if Chief of Staff mode was active
  if grep -q "Mode: Chief of Staff" "$STATE_FILE" 2>/dev/null; then
    echo ""
    echo "=== CHIEF OF STAFF REMINDER ==="
    echo "The previous session was using Chief of Staff mode."
    echo "To resume that mode, invoke the chief-of-staff skill"
    echo "=== END REMINDER ==="
  fi
fi

exit 0
