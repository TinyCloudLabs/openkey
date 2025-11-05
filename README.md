# OpenKey - AI-Driven Development with Pipeline Orchestration

OpenKey is an open-source authentication service that combines WebAuthn passkeys with Ethereum key management, built using a self-improving AI development pipeline.

## 📚 Documentation

- **[Architecture Overview](README-ARCHITECTURE.md)** - Understand the three-layer architecture
- **[Git Workflow Guide](GIT-WORKFLOW.md)** - Managing AI-generated code with git
- **[Orchestrator Example](orchestrator-example.md)** - See the AI in action

## Architecture

This project demonstrates a novel approach to AI-driven development with three key components:

### 1. Generic Pipeline Orchestrator (`orchestrator/.claude/agent.md`)
A Claude Code subagent that can implement any software project from a specification file. The orchestrator:
- Reads project specifications from YAML files
- Generates dynamic pipelines using Mastra.ai
- Manages build iterations and checkpoints
- Evaluates outputs against success criteria
- Refines the pipeline based on results

### 2. Project Specification (`orchestrator/specs/openkey.spec.yaml`)
A declarative specification defining:
- Project goals and requirements
- Component architecture
- Security constraints
- Testing requirements
- Success criteria
- Business constraints

### 3. Dynamic Pipeline (`orchestrator/pipeline/openkey-pipeline-starter.ts`)
A self-modifying Mastra workflow that:
- Generates specialized AI agents based on project needs
- Executes parallel build processes
- Runs comprehensive testing
- Evaluates quality and security
- Improves itself through iterations

## OpenKey Features

- **WebAuthn Authentication**: Passwordless login using passkeys
- **Ethereum Key Management**: Secure key generation and signing
- **Recovery Mechanisms**: Email-based account recovery
- **Demo Application**: Complete integration example
- **GPL Licensing**: Open source with domain binding
- **Self-Hosted**: No dependency on external auth services

## Usage

### Start the Orchestrator

```bash
# Start Claude Code with the orchestrator
claude-code

# In the chat, implement the OpenKey specification
> implement orchestrator/specs/openkey.spec.yaml
```

### The orchestrator will:

1. **Initialize** - Parse the spec and generate pipeline
2. **Build** - Create backend, frontend, and demo in parallel
3. **Test** - Run unit, integration, and security tests
4. **Evaluate** - Check against spec success criteria
5. **Refine** - Improve pipeline if quality insufficient
6. **Deploy** - Create deployable project in `project/` directory

### Monitor Progress

```bash
# Check current status
> status

# Resume from checkpoint
> resume

# Trigger manual evaluation
> evaluate

# Force pipeline refinement
> refine
```

## Project Structure

```
openkey/
├── orchestrator/                   # AI Pipeline System (reusable)
│   ├── .claude/
│   │   └── agent.md               # Generic orchestrator agent
│   ├── pipeline/
│   │   ├── types.ts               # TypeScript definitions
│   │   ├── templates/             # Code generation templates
│   │   └── openkey-pipeline-starter.ts # Pipeline implementation
│   ├── specs/
│   │   └── openkey.spec.yaml      # Project specification
│   └── state/                     # Pipeline execution state
├── project/                        # Generated OpenKey code (deployable)
│   ├── backend/                   # Express API
│   ├── frontend/                  # Next.js app
│   ├── tests/                     # Test suites
│   ├── docker-compose.yml         # Local development
│   └── package.json               # Project dependencies
└── deployments/                    # Deployment configurations
    ├── local/                     # Local dev scripts
    ├── staging/                   # Staging deployment
    └── production/                # Production deployment
```

## Key Innovation: Self-Improving Pipeline

The pipeline is the primary artifact that evolves. When builds fail to meet specifications:

1. **Evaluation Agent** identifies specific issues
2. **Refiner Agent** analyzes failures and suggests improvements
3. **Orchestrator** modifies agent prompts, workflow steps, and tools
4. **Pipeline** restarts with improvements applied

This creates a feedback loop where the development process itself gets better at building the software.

## Testing Strategy

### Automated Testing with Playwright MCP

The system uses Playwright's Model Context Protocol for browser automation:

```typescript
// Natural language testing
await playwrightMCP.test("User can register with passkey", async () => {
  await navigate("https://xxx.ngrok.io");
  await click("Sign up with passkey");
  await completePasskeyRegistration();
  await expectText("Welcome to OpenKey");
});
```

### ngrok Integration

- HTTPS tunnels for WebAuthn testing
- Real-world browser compatibility testing
- Cross-device passkey testing

## Success Criteria

The pipeline will iterate until all criteria are met:

### Functional
- All API endpoints work correctly
- WebAuthn works on major browsers
- Ethereum signatures are cryptographically valid
- Recovery mechanisms function properly

### Performance
- Authentication completes in < 100ms
- Key generation takes < 500ms
- System maintains 99.9% uptime

### Security
- No private key exposure
- Passes OWASP security audit
- Rate limiting prevents abuse
- Keys encrypted with AES-256

### Quality
- Clean, documented code
- 80% test coverage
- Mobile-responsive UI
- Clear error messages

## Deployment

Once the AI has generated the project, deploy it like any standard application:

### Local Development
```bash
cd project
docker-compose up
# Access at http://localhost:3000
```

### Staging/Production
```bash
# Deploy to staging
npm run deploy:staging

# Deploy to production  
npm run deploy:production

# Emergency rollback
cd deployments/production
./rollback-production.sh <previous-version>
```

## Future Enhancements

- **TEE Integration**: Trusted Execution Environment for key isolation
- **Hardware Security Modules**: HSM support for enterprise deployments
- **Multi-chain Support**: Beyond Ethereum key management
- **Social Recovery**: Decentralized recovery mechanisms

## License

GPL-3.0 with domain binding for open source compliance. Commercial licenses available.

## Contributing

The pipeline orchestrator can be extended to build other projects by:

1. Creating new specification files (`.spec.yaml`)
2. Adding project-specific agent templates
3. Extending the pipeline generator logic
4. Adding new evaluation criteria

The orchestrator is designed to be project-agnostic and reusable across different software development contexts.