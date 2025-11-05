# Git Workflow for AI-Generated Projects

## 🎯 Overview

This document describes how to manage git repositories when using AI to generate software projects. The key insight: **treat AI-generated code like any other code** - review it, version it, and deploy it using standard practices.

## 📦 Repository Structure

### Option 1: Separate Repositories (Recommended)

```
github.com/yourorg/
├── ai-orchestrator/          # Reusable AI pipeline system
├── openkey/                  # Generated OpenKey project
└── openkey-deployments/      # Deployment configurations (optional)
```

### Option 2: Monorepo with Subtree

```
github.com/yourorg/openkey-mono/
├── orchestrator/             # Git subtree (can be pulled from separate repo)
├── project/                  # Main application code
└── deployments/              # Deployment configs
```

## 🔄 Workflow Scenarios

### 1. Initial Project Generation

```bash
# Start with the orchestrator
cd openkey
claude-code

# Generate the project
> implement orchestrator/specs/openkey.spec.yaml

# AI creates project/ directory with all code

# Initialize project repository
cd project
git init
git add .
git commit -m "feat: Initial AI-generated implementation

- WebAuthn authentication system
- Ethereum key management  
- Express backend with TypeScript
- Next.js frontend
- Docker compose setup
- Comprehensive test suite

Generated from openkey.spec.yaml by AI orchestrator v1.0"

# Push to remote
git remote add origin git@github.com:yourorg/openkey.git
git branch -M main
git push -u origin main
```

### 2. AI-Driven Improvements

```bash
# Run AI evaluation
> evaluate

# If improvements needed, refine
> refine

# AI regenerates code with improvements
# Review the changes
cd project
git diff

# Stage and commit improvements
git add -A
git commit -m "perf: AI optimization - reduce auth latency

- Optimized WebAuthn credential lookup
- Added Redis caching for sessions
- Improved database query performance
- Authentication now <100ms (was 145ms)

AI Pipeline Iteration: 2"

git push
```

### 3. Manual Modifications

```bash
# Make manual changes to AI-generated code
cd project/backend
vim src/services/auth.service.ts

# Commit manual changes
git add -A
git commit -m "fix: Add rate limiting to auth endpoints

- Prevent brute force attacks
- Add configurable rate limits
- Include bypass for trusted IPs"

git push
```

### 4. Feature Development with AI Assistance

```bash
# Create feature branch
cd project
git checkout -b feat/social-recovery

# Update spec with new feature
cd ../orchestrator/specs
vim openkey.spec.yaml  # Add social recovery requirements

# Have AI implement the feature
> implement openkey.spec.yaml --feature social-recovery

# Review and commit AI's implementation
cd ../project
git add -A
git commit -m "feat: Add social recovery mechanism

- Allow users to set recovery contacts
- Implement threshold signatures
- Add recovery UI flow
- Include e2e tests

Implemented by AI from updated spec"

# Push feature branch
git push -u origin feat/social-recovery

# Create PR for review
gh pr create --title "Add social recovery feature" \
  --body "AI-implemented social recovery based on updated spec"
```

## 📋 Commit Message Convention

### For AI-Generated Code

```
<type>: <description>

<detailed changes>

AI Pipeline: <iteration number>
Spec Version: <spec version>
[Performance metrics if applicable]
```

### Types
- `feat`: New feature implementation
- `fix`: Bug fixes
- `perf`: Performance improvements  
- `refactor`: Code refactoring
- `test`: Test additions/modifications
- `docs`: Documentation updates
- `chore`: Build/deploy configurations

### Examples

```bash
# Initial generation
git commit -m "feat: Initial OpenKey implementation

- Complete WebAuthn authentication system
- Ethereum key management with AES-256 encryption
- Express backend, Next.js frontend
- 87% test coverage

AI Pipeline: 1
Spec Version: 1.0.0"

# AI improvement
git commit -m "perf: Optimize authentication performance

- Implement connection pooling
- Add query result caching
- Optimize WebAuthn credential lookup

Performance: Auth reduced from 145ms to 85ms
AI Pipeline: 2"

# Manual fix
git commit -m "fix: Correct CORS configuration for WebAuthn

- Add proper origin validation
- Fix OPTIONS preflight handling"
```

## 🌿 Branching Strategy

### Main Branches
- `main` - Production-ready code
- `develop` - Integration branch
- `ai/working` - AI's working branch (optional)

### Feature Branches
- `feat/*` - New features
- `fix/*` - Bug fixes
- `ai/iteration-*` - AI improvement iterations

### Example Flow

```bash
# AI works on improvement
git checkout -b ai/iteration-3
# AI makes changes...
git add -A
git commit -m "perf: AI iteration 3 improvements"

# Review AI's work
git diff develop...ai/iteration-3

# If good, merge
git checkout develop
git merge ai/iteration-3
git push

# Deploy to staging for testing
npm run deploy:staging
```

## 🔍 Code Review Process

### AI-Generated Code Reviews

1. **Treat like any PR**:
   ```bash
   # AI creates feature branch
   git checkout -b ai/auth-improvements
   
   # AI commits changes
   git add -A
   git commit -m "perf: Improve auth performance"
   git push -u origin ai/auth-improvements
   
   # Create PR
   gh pr create --title "AI: Auth performance improvements"
   ```

2. **Review Checklist**:
   - [ ] Code follows project standards
   - [ ] Tests pass and coverage adequate  
   - [ ] No security vulnerabilities
   - [ ] Performance metrics improved
   - [ ] Documentation updated

3. **Merge Process**:
   ```bash
   # After approval
   git checkout develop
   git merge --no-ff ai/auth-improvements
   git push
   ```

## 🏷️ Version Tagging

### Semantic Versioning with AI Metadata

```bash
# Tag AI-generated releases
git tag -a v1.0.0 -m "Initial AI-generated release

OpenKey v1.0.0
- Full WebAuthn implementation
- Ethereum key management
- Production ready

Generated by AI Pipeline v1.0
From spec: openkey.spec.yaml v1.0.0
Iterations: 3
Final metrics: All criteria met"

git push origin v1.0.0
```

### Tag Format
```
v<major>.<minor>.<patch>-ai.<iteration>

Examples:
v1.0.0-ai.1   # First AI generation
v1.0.1-ai.2   # AI-generated patch
v1.1.0         # Manual feature addition
v1.1.1-ai.3   # AI improvements to manual features
```

## 🔐 Security Considerations

### Secrets Management

```bash
# Never commit secrets, even in AI-generated code
# Add to .gitignore
echo ".env" >> .gitignore
echo "*.key" >> .gitignore
echo "*.pem" >> .gitignore

# Use git-secret or similar for encrypted secrets
git secret init
git secret add .env.production
git secret hide
```

### Pre-commit Hooks

```bash
# Install pre-commit hooks to catch issues
cd project
npm install --save-dev husky

# Add security checks
npx husky add .husky/pre-commit "npm run lint"
npx husky add .husky/pre-commit "npm run test:security"
```

## 📊 Tracking AI Performance

### Git Notes for AI Metadata

```bash
# Add notes about AI performance
git notes add -m "AI Metrics:
- Generation time: 45 minutes
- Iterations: 3  
- Test coverage: 87%
- Performance: All criteria met
- Security: Passed audit"

# View AI metrics
git log --show-notes
```

### Metrics Branch

```bash
# Keep AI metrics in separate branch
git checkout -b metrics/ai-performance

# Save iteration data
mkdir -p metrics/iterations
echo '{"iteration": 3, "duration": 2700, "criteria_met": 15}' \
  > metrics/iterations/iteration-3.json

git add metrics/
git commit -m "metrics: AI iteration 3 performance data"
```

## 🚀 Deployment Tracking

### Deployment Tags

```bash
# Tag deployments with AI metadata
git tag -a deploy/staging/2024-01-15 -m "Deploy to staging

Version: v1.0.0-ai.3
Environment: Staging
AI-generated: Yes
Tests passed: 142/142"

git tag -a deploy/prod/2024-01-16 -m "Deploy to production

Version: v1.0.0-ai.3  
Environment: Production
AI-generated: Yes
Post-deploy metrics: Normal"
```

## 📝 Best Practices

1. **Always Review AI Output**: Never auto-deploy without review
2. **Maintain Clear History**: Use descriptive commits
3. **Track AI Iterations**: Include metadata in commits
4. **Test Everything**: AI code needs same quality bar
5. **Document Decisions**: Why AI made certain choices
6. **Version Specs**: Track specification changes
7. **Monitor Production**: AI-generated ≠ bug-free

## 🔄 Continuous Improvement

```bash
# Create improvement tracking
git checkout -b improve/ai-pipeline

# Document learnings
echo "## Iteration 3 Learnings
- Need better error handling templates
- Performance criteria too strict initially  
- Add more integration test scenarios" > AI_LEARNINGS.md

git add AI_LEARNINGS.md
git commit -m "docs: AI pipeline learnings from OpenKey project"

# Feed back to orchestrator
cd ../orchestrator
git checkout -b improve/openkey-learnings
# Update templates based on learnings...
```

This workflow ensures AI-generated code is properly versioned, reviewed, and deployed using industry-standard practices!