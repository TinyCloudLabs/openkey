---
name: linear-project-management
description: Plan and execute projects using Linear for OpenKey. Use when creating issues, tracking progress, posting updates, or managing milestones.
---

This skill guides Linear project management for the OpenKey repository. It ensures consistent issue structure, proper project linkage, and adherence to Linear best practices.

## Workspace Configuration

- **Workspace:** tinycloudlabs
- **Primary Team:** TinyCloud Dev (issues get TC-xxx IDs)
- **Primary Team ID:** db0530d0-5eb4-4bea-b6d9-29f9d04d5de7
- **AI Team:** AI (for AI-related sub-issues, get AI-xxx IDs)
- **AI Team ID:** b89ab94c-8ad6-4eda-97e2-c0f71c489181

## Issue Statuses (TinyCloud Dev Team)

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
```
## Summary
[1-2 sentences: what and why]

## Acceptance Criteria
- [ ] Criterion 1
- [ ] Criterion 2

## Technical Notes
[Optional: Implementation hints, affected files]
```

### Required Fields
- **team:** "TinyCloud Dev" (primary team for all parent issues)
- **project:** Associate with a TinyCloud Dev project (must be same team as issue)
- **labels:** At least one (Feature, Bug, Improvement)
- **state:** Typically "Ready to Start"

### Creating Projects
Projects **must** be created under the TinyCloud Dev team to be associated with issues:
```
create_project: { name: "Project Name", team: "TinyCloud Dev" }
```

## Branch Naming Convention

**Format:** `[label]/tc-[id]-[short-description]`

**Examples:**
- `feature/tc-42-add-dark-mode`
- `bug/tc-15-fix-websocket-leak`
- `feature/ai-10-implement-llm-integration` (for AI team sub-issues)

**Elite teams maintain 81%+ issue-branch linkage.**

## Commit Messages

Include issue ID: `TC-42: Add dark mode toggle component`

## Project Updates

### Health Indicators
- **On track** - Progress as expected, no blockers
- **At risk** - Potential issues that may cause delays
- **Off track** - Significant blockers or delays

### Update Frequency
Active projects: Weekly updates minimum

### Template
```
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

1. **Create or select a project under TinyCloud Dev:**
   ```
   create_project: { name: "Project Name", team: "TinyCloud Dev" }
   ```

2. **Create parent issue on TinyCloud Dev team:**
   - title: "Epic: [Feature Name]"
   - team: "TinyCloud Dev"
   - project: "[Project Name]" (must be TinyCloud Dev project)
   - labels: ["Feature"]

3. **Create AI team sub-issues** for AI-related implementation work:
   - team: "AI"
   - parentId: [parent TC issue ID]
   - Note: Sub-issues on AI team are tracked separately but linked to parent

4. **Create branch:** `git checkout -b feature/tc-[id]-[name]`

5. **Update status** as work progresses

## Workflow: Completing Work

1. Ensure acceptance criteria met
2. Update issue to "Done"
3. Link PR with TC-xxx or AI-xxx in title/description
4. Post completion comment if noteworthy

## Quick Reference

| Task | Tool | Key Parameters |
|------|------|----------------|
| Create project | `create_project` | name, team: "TinyCloud Dev" |
| Create parent issue | `create_issue` | title, team: "TinyCloud Dev", project: "[name]" |
| Create AI sub-issue | `create_issue` | title, team: "AI", parentId: [TC issue ID] |
| Update status | `update_issue` | id, state |
| Add comment | `create_comment` | issueId, body |
| List my work | `list_issues` | assignee: "me", team: "TinyCloud Dev" |
| Get project | `get_project` | query: "[project name]" |

## LinearB Best Practices

1. **Issue-Branch Linkage** - Always name branches with issue ID
2. **Small PRs** - Break work into 1-2 day issues
3. **Regular Updates** - Weekly project updates, daily status changes
4. **Early Risk Flagging** - Use "At risk" status proactively
