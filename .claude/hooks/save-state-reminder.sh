#!/bin/bash
# Called before compaction - reminds Claude to save state
set -e

echo "=== PRE-COMPACTION REMINDER ==="
echo "IMPORTANT: Update .claude/state.local.md with current state before compaction."
echo "Include: active task IDs, assumptions, decisions, blockers, next steps."
echo "=== END REMINDER ==="

exit 0
