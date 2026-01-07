# Chief of Staff - First-Time Setup

Run these steps only if `.claude/hooks/load-state.sh` does not exist.

## 1. Create hooks directory
```bash
mkdir -p .claude/hooks
```

## 2. Copy the hook script
Copy `hook-example/load-state.sh` from this skill directory to `.claude/hooks/load-state.sh`

## 3. Make it executable
```bash
chmod +x .claude/hooks/load-state.sh
```

## 4. Ensure .gitignore excludes state files
Add to `.claude/.gitignore` if not present:
```
*.local.log
```

## 5. Verify setup
After setup, the skill is ready. On future sessions, the SessionStart hook will automatically load state.
