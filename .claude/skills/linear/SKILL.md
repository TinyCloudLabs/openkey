---
name: linear-project-management
description: Plan and execute projects using Linear. Use when creating issues, tracking progress, posting updates, or managing milestones.

# Configuration - Edit these values when deploying to a new project
config:
  workspace: tinycloudlabs
  project: OpenKey

  teams:
    primary:
      name: TinyCloud Dev
      id: db0530d0-5eb4-4bea-b6d9-29f9d04d5de7
      prefix: TC
      description: Main development team for all parent issues
    secondary:
      name: AI
      id: b89ab94c-8ad6-4eda-97e2-c0f71c489181
      prefix: AI
      description: AI-related sub-issues and implementation work

  statuses:
    backlog: Backlog
    todo: Todo
    ready: Ready to Start
    in_progress: In Progress
    in_review: In Review
    done: Done
    canceled: Canceled
    duplicate: Duplicate

  labels:
    - Feature
    - Bug
    - Improvement
---

# Linear Project Management

This skill guides Linear project management. All configurable values (workspace, teams, prefixes) are defined in the YAML frontmatter above.

## Workspace & Teams

Reference the `config` section above for:
- **Workspace**: `config.workspace`
- **Primary Team**: `config.teams.primary.name` (issues get `{prefix}-xxx` IDs)
- **Secondary Team**: `config.teams.secondary.name` (for sub-issues)

## Issue Statuses

| Status | Type | Use When |
|--------|------|----------|
| Backlog | backlog | Ideas/future work not yet prioritized |
| Todo | unstarted | Scoped but not yet started |
| Ready to Start | unstarted | Fully scoped, ready for implementation |
| In Progress | started | Actively being worked on |
| In Review | started | Code complete, awaiting review |
| Done | completed | Work complete and verified |
| Canceled | canceled | Work no longer needed |
| Duplicate | canceled | Duplicate of another issue |

## Labels

| Label | Use For |
|-------|---------|
| Feature | New functionality |
| Bug | Defects and errors |
| Improvement | Enhancements to existing features |

## Creating Issues

### Title Format
Use clear, imperative titles: "Add user authentication flow" not "Auth stuff"

### Description Template
```markdown
## Summary
[1-2 sentences: what and why]

## Acceptance Criteria
- [ ] Criterion 1
- [ ] Criterion 2

## Technical Notes
[Optional: Implementation hints, affected files]
```

### Required Fields
- **team**: Primary team from `config.teams.primary.name`
- **project**: Associate with a project under the primary team
- **labels**: At least one (Feature, Bug, Improvement)
- **state**: Typically "Ready to Start"

### Creating Projects
Projects **must** be created under the primary team:
```
create_project: { name: "Project Name", team: "<config.teams.primary.name>" }
```

## Branch Naming Convention

**Format**: `[label]/<prefix>-[id]-[short-description]`

Use the prefix from `config.teams.primary.prefix` or `config.teams.secondary.prefix`.

**Examples**:
- `feature/<primary-prefix>-42-add-dark-mode`
- `bug/<primary-prefix>-15-fix-websocket-leak`
- `feature/<secondary-prefix>-10-implement-feature` (for secondary team sub-issues)

**Elite teams maintain 81%+ issue-branch linkage.**

## Commit Messages

Include issue ID: `<PREFIX>-42: Add dark mode toggle component`

## Project Updates

### Health Indicators
- **On track** - Progress as expected, no blockers
- **At risk** - Potential issues that may cause delays
- **Off track** - Significant blockers or delays

### Update Frequency
Active projects: Weekly updates minimum

### Template
```markdown
## Status: [On track | At risk | Off track]

### Progress This Week
- Completed: [list]
- In Progress: [list]

### Blockers
[Any blockers or risks]

### Next Steps
[Plans for next week]
```

## Workflow: Starting a Feature

1. **Create or select a project** under the primary team:
   ```
   create_project: { name: "Project Name", team: "<config.teams.primary.name>" }
   ```

2. **Create parent issue** on primary team:
   - title: "Epic: [Feature Name]"
   - team: `config.teams.primary.name`
   - project: "[Project Name]"
   - labels: ["Feature"]

3. **Create sub-issues** on secondary team for specialized work:
   - team: `config.teams.secondary.name`
   - parentId: [parent issue ID]
   - Note: Sub-issues are tracked separately but linked to parent

4. **Create branch**: `git checkout -b feature/<prefix>-[id]-[name]`

5. **Update status** as work progresses

## Workflow: Completing Work

1. Ensure acceptance criteria met
2. Update issue to "Done"
3. Link PR with `<PREFIX>-xxx` in title/description
4. Post completion comment if noteworthy

## Quick Reference

| Task | Tool | Key Parameters |
|------|------|----------------|
| Create project | `create_project` | name, team: `<primary.name>` |
| Create parent issue | `create_issue` | title, team: `<primary.name>`, project |
| Create sub-issue | `create_issue` | title, team: `<secondary.name>`, parentId |
| Update status | `update_issue` | id, state |
| Add comment | `create_comment` | issueId, body |
| List my work | `list_issues` | assignee: "me", team: `<primary.name>` |
| Get project | `get_project` | query: "[project name]" |

## LinearB Best Practices

1. **Issue-Branch Linkage** - Always name branches with issue ID
2. **Small PRs** - Break work into 1-2 day issues
3. **Regular Updates** - Weekly project updates, daily status changes
4. **Early Risk Flagging** - Use "At risk" status proactively
