# Pipeline Orchestrator Usage Example

This document shows how to use the OpenKey Pipeline Orchestrator in practice.

## Getting Started

### 1. Start Claude Code with the Orchestrator

```bash
# In your terminal
cd openkey
claude-code
```

Claude Code will automatically load the `.claude/agent.md` orchestrator.

### 2. Implement the OpenKey Project

In the Claude Code chat:

```
implement openkey.spec.yaml
```

## Example Orchestration Session

```
🤖 Pipeline Orchestrator: Loading openkey.spec.yaml...

📋 Project: OpenKey v1.0.0
🎯 Goal: Build a self-hosted alternative to Privy with lower costs
🔧 Components: backend (api), frontend (webapp), demo (example)
✅ Spec validation passed

🚀 Generating pipeline from specification...
   - Created 6 specialized agents based on project requirements
   - Generated workflow with 8 phases
   - Configured parallel build processes

🏗️ Starting OpenKey Pipeline - Iteration 1

[INIT] Initializing pipeline state...
[ARCHITECTURE] Designing system architecture...
   🏛️ Architect Agent: Creating technical design for Express + Next.js stack
   📄 Saved: pipeline/artifacts/openkey/architecture.md

[BUILD] Starting parallel build phase...
   🔧 Backend Builder: Setting up Express TypeScript project...
      ✅ Initialized project with WebAuthn and Ethereum dependencies
      ✅ Implemented /auth endpoints with @simplewebauthn/server
      ✅ Added Ethereum key management with ethers.js
      ✅ Created recovery system with email tokens
   
   🎨 Frontend Builder: Creating Next.js application...
      ✅ Set up Next.js 14 with App Router
      ✅ Built authentication UI with passkey support
      ✅ Created user dashboard with Ethereum integration
      ✅ Implemented settings and recovery pages
   
   🎭 Demo Builder: Creating demonstration app...
      ✅ Built integration example with login flow
      ✅ Added message signing demonstration
      ✅ Created transaction signing demo
   
   🧪 Test Setup: Configuring testing environment...
      ✅ Set up Jest and Vitest for unit tests
      ✅ Configured Playwright MCP for browser automation
      ✅ Created ngrok configuration for HTTPS testing

[INTEGRATION] Connecting all components...
   🔗 Integrator Agent: Setting up development environment...
      ✅ Connected frontend to backend API
      ✅ Configured PostgreSQL with Docker Compose
      ✅ Set up ngrok tunnels: https://abc123.ngrok.io
      ✅ All services starting correctly

💾 Checkpoint saved: integration-complete

[TESTING] Running comprehensive test suite...
   🧪 Test Agent: Executing all test scenarios...
      ✅ Unit tests: 87% coverage (target: 80%)
      ✅ Integration tests via Playwright MCP:
         - User registration with passkey: ✅ PASS
         - Login flow: ✅ PASS  
         - Ethereum signing: ✅ PASS
         - Device management: ✅ PASS
         - Recovery process: ✅ PASS
      ⚠️ Security tests:
         - OWASP compliance: ✅ PASS
         - Key exposure detection: ❌ FAIL (found exposed key in logs)
         - Rate limiting: ✅ PASS
      ⚠️ Performance tests:
         - Authentication: 145ms (target: <100ms)
         - Key generation: 320ms ✅ PASS

📄 Saved: pipeline/artifacts/openkey/test-results.json

[EVALUATION] Checking against success criteria...
   📊 Evaluator Agent: Analyzing build quality...
   
   Functional Requirements: ✅ 4/4 PASS
   ✅ All endpoints return correct responses
   ✅ WebAuthn works on Chrome, Safari, Firefox  
   ✅ Ethereum signatures are valid
   ✅ Recovery mechanism functions
   
   Performance Requirements: ⚠️ 3/4 PARTIAL
   ❌ Authentication: 145ms (target: <100ms)
   ✅ Key generation: 320ms (target: <500ms)
   ✅ 99.9% uptime achieved in testing
   
   Security Requirements: ⚠️ 2/3 PARTIAL  
   ❌ Key exposure detected in backend logs
   ✅ Security audit passed (other areas)
   ✅ Rate limiting prevents abuse
   
   Quality Requirements: ✅ 4/4 PASS
   ✅ Clean, documented code
   ✅ 87% test coverage (target: 80%)
   ✅ Mobile responsive UI  
   ✅ Clear error messages
   
   📊 Overall: 13/15 criteria met (87%)
   🔄 DECISION: Needs improvement before deployment

[REFINE] Improving pipeline based on results...
   🔧 Refiner Agent: Analyzing failures and suggesting improvements...
   
   Issues identified:
   1. Backend logging exposes private keys
   2. Authentication performance needs optimization
   
   Pipeline improvements:
   ✅ Updated Backend Builder prompt to emphasize log sanitization
   ✅ Added performance optimization step to backend workflow  
   ✅ Enhanced Evaluator criteria for security scanning
   ✅ Modified Test Agent to specifically check for key exposure

💾 Pipeline improvements applied
🔄 Starting Iteration 2 with enhanced agents...

[INIT] Restarting with improved pipeline...
[ARCHITECTURE] Using existing architecture (cached)...
[BUILD] Re-running backend build with enhanced security focus...
   🔧 Backend Builder: Applying security improvements...
      ✅ Sanitized all logging to prevent key exposure
      ✅ Optimized authentication endpoints for performance
      ✅ Added request caching for faster responses

[TESTING] Re-running focused test suite...
   🧪 Test Agent: Verifying improvements...
      ✅ Security tests: All passed (no key exposure detected)
      ✅ Performance tests: Authentication now 85ms ✅ PASS

[EVALUATION] Re-evaluating with stricter criteria...
   📊 Evaluator Agent: Final quality assessment...
   
   📊 Overall: 15/15 criteria met (100%)
   ✅ DECISION: Ready for deployment

[DEPLOY] Creating demo deployment...
   🚀 Deployer: Setting up demo environment...
      ✅ Backend started: http://localhost:3001
      ✅ Frontend started: http://localhost:3000  
      ✅ Database migrations completed
      ✅ Demo accessible at: https://abc123.ngrok.io
      
🎉 SUCCESS! OpenKey completed after 2 iterations

📋 FINAL SUMMARY:
   - Project: OpenKey v1.0.0
   - Iterations: 2
   - Total time: 45 minutes
   - Success criteria: 15/15 met
   - Demo URL: https://abc123.ngrok.io
   - Code location: pipeline/artifacts/openkey/

🔗 Next steps:
   1. Test the demo at https://abc123.ngrok.io
   2. Review generated code in pipeline/artifacts/openkey/
   3. Run production deployment when ready
   4. Set up monitoring and maintenance

✨ The pipeline has successfully built OpenKey and learned to build it better!
```

## Commands Available During Execution

### Status Check
```
status
```
Response:
```
📊 Pipeline Status:
   - Project: OpenKey
   - Phase: Testing  
   - Iteration: 2
   - Started: 2024-11-04T10:30:00Z
   - Last checkpoint: integration-complete
   - Criteria met: 13/15 (87%)
   - Next action: Performance optimization
```

### Resume from Checkpoint
```
resume
```
Response:
```
🔄 Resuming from checkpoint: integration-complete
📋 Continuing iteration 2 from testing phase...
```

### Manual Evaluation
```
evaluate
```
Response:
```
📊 Running manual evaluation against spec criteria...
[Detailed evaluation results]
```

### Force Refinement
```
refine
```
Response:
```
🔧 Triggering pipeline refinement...
🤔 Analyzing current issues and improvement opportunities...
```

## File Structure After Completion

```
openkey/
├── .claude/
│   └── agent.md                           # Orchestrator agent
├── pipeline/
│   ├── state/openkey/
│   │   ├── current-state.json            # Latest pipeline state
│   │   ├── checkpoints/                  # Saved checkpoints
│   │   │   ├── architecture-2024...json
│   │   │   ├── integration-2024...json
│   │   │   └── testing-2024...json
│   │   └── evaluations/                  # Evaluation history
│   │       ├── evaluation-1-2024...json
│   │       └── evaluation-2-2024...json
│   └── artifacts/openkey/                # Generated code and docs
│       ├── architecture.md               # System architecture
│       ├── backend/                      # Express API code
│       ├── frontend/                     # Next.js application
│       ├── demo/                         # Demo application
│       ├── tests/                        # Test suites
│       ├── test-results.json            # Latest test results
│       └── deployment-guide.md          # Deployment instructions
├── openkey.spec.yaml                     # Project specification
└── README.md                             # Project documentation
```

## Key Features Demonstrated

1. **Self-Improving Pipeline**: The system identifies issues and improves its own development process
2. **Parallel Development**: Multiple components built simultaneously
3. **Comprehensive Testing**: Unit, integration, security, and performance tests
4. **Quality Gates**: Strict evaluation against specification criteria
5. **Checkpoint System**: Resume capability for long-running builds
6. **Artifact Management**: Organized storage of all generated code and documentation

This orchestration approach creates a true "AI engineer" that can build complex software systems with minimal human intervention while maintaining high quality standards.