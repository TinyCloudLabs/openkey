// Pipeline Generator Template
// This file helps the orchestrator create pipelines from project specifications

import { ProjectSpec, AgentConfigMap } from '../types';

export class PipelineGenerator {
  
  static generateAgentConfigs(spec: ProjectSpec): AgentConfigMap {
    const configs: AgentConfigMap = {
      architect: {
        model: 'opus',
        systemPrompt: `You are a software architect designing ${spec.metadata.name}.
        
Project Goal: ${spec.goals.primary}

Components to design:
${Object.entries(spec.components).map(([name, comp]) => `- ${name}: ${comp.type} using ${comp.framework || comp.language}`).join('\n')}

Security Requirements:
${spec.security.encryption.concat(spec.security.authentication).join('\n')}

Create a detailed technical architecture that satisfies all requirements.
Focus on security, scalability, and simplicity.`,
        tools: ['Read', 'WebSearch', 'Write']
      },

      builder: {
        model: 'sonnet',
        systemPrompt: `You are an expert developer building ${spec.metadata.name}.

Tech Stack: ${Object.values(spec.components).map(c => c.framework || c.language).join(', ')}

Key Requirements:
${spec.constraints.technical.join('\n')}

Build clean, secure, well-documented code following best practices.
Never expose private keys or secrets.
Use TypeScript for type safety.`,
        tools: ['Read', 'Write', 'Edit', 'MultiEdit', 'Bash', 'WebSearch']
      },

      tester: {
        model: 'sonnet',
        systemPrompt: `You are a QA engineer testing ${spec.metadata.name}.

Testing Requirements:
- Unit tests: ${spec.testing.unit.backend} and ${spec.testing.unit.frontend}
- Integration: ${spec.testing.integration.tool} with ${spec.testing.integration.environment}
- Coverage target: ${spec.testing.unit.coverage}

Test Scenarios:
${spec.testing.integration.scenarios.join('\n')}

Use Playwright MCP for browser automation and ngrok for HTTPS testing.
Write comprehensive tests covering all user flows and security aspects.`,
        tools: ['Read', 'Write', 'Bash', 'Grep']
      },

      integrator: {
        model: 'sonnet',
        systemPrompt: `You integrate components for ${spec.metadata.name}.

Development Environment:
${Object.entries(spec.deployment.development).map(([k, v]) => `${k}: ${v}`).join('\n')}

Ensure all components work together seamlessly.
Set up development environment and dependencies.
Configure services and databases.`,
        tools: ['Read', 'Write', 'Edit', 'Bash']
      },

      evaluator: {
        model: 'opus',
        systemPrompt: `You evaluate ${spec.metadata.name} against specification criteria.

Success Criteria:
Functional: ${spec.success_criteria.functional.join(', ')}
Performance: ${spec.success_criteria.performance.join(', ')}
Security: ${spec.success_criteria.security.join(', ')}
Quality: ${spec.success_criteria.quality.join(', ')}

Be thorough and critical. Provide specific feedback for improvements.`,
        tools: ['Read', 'Grep', 'Bash']
      },

      refiner: {
        model: 'opus',
        systemPrompt: `You improve AI pipelines based on evaluation results.

When builds fail to meet specifications, analyze:
1. What specific criteria were not met
2. Which agent's work caused the issue  
3. How to modify agent prompts/tools/workflow
4. Whether the pipeline needs additional steps

Suggest concrete improvements to make the next iteration better.`,
        tools: ['Read', 'Write', 'Edit']
      }
    };

    return configs;
  }

  static generateWorkflowSteps(spec: ProjectSpec): string {
    const componentTypes = Object.values(spec.components).map(c => c.type);
    const hasAPI = componentTypes.includes('api');
    const hasWebapp = componentTypes.includes('webapp');
    const hasDemo = componentTypes.includes('example');

    return `
// Generated workflow for ${spec.metadata.name}
export const ${spec.metadata.name}Pipeline = workflow<PipelineState>('${spec.metadata.name}-pipeline')
  
  .step('init', async (ctx) => {
    console.log('Starting ${spec.metadata.name} Pipeline - Iteration:', ctx.state.iteration);
    return { spec: spec, startTime: new Date() };
  })
  
  .step('architecture', async (ctx) => {
    const architect = createAgent('architect', ctx.state.agentConfigs.architect);
    const design = await architect.query('Design the system architecture');
    await saveArtifact('architecture.md', design);
    return { architecture: design };
  })
  
  .step('build', parallel([
    ${hasAPI ? this.generateAPIBuildStep() : ''}
    ${hasWebapp ? this.generateWebappBuildStep() : ''}
    ${hasDemo ? this.generateDemoBuildStep() : ''}
    workflow('testing-setup').step('setup', async (ctx) => {
      const tester = createAgent('tester', ctx.state.agentConfigs.tester);
      return await tester.query('Set up testing environment');
    })
  ]))
  
  .step('integration', async (ctx) => {
    const integrator = createAgent('integrator', ctx.state.agentConfigs.integrator);
    return await integrator.query('Integrate all components');
  })
  
  .step('testing', async (ctx) => {
    const tester = createAgent('tester', ctx.state.agentConfigs.tester);
    return await tester.query('Run comprehensive test suite');
  })
  
  .step('evaluation', async (ctx) => {
    const evaluator = createAgent('evaluator', ctx.state.agentConfigs.evaluator);
    return await evaluator.query('Evaluate against success criteria');
  })
  
  .branch('quality-gate', {
    'success': workflow.step('deploy', deploySuccessStep),
    'needs-improvement': workflow.step('refine', refinePipelineStep)
  });
`;
  }

  private static generateAPIBuildStep(): string {
    return `
    workflow('api-build')
      .step('setup', async (ctx) => {
        const builder = createAgent('builder', ctx.state.agentConfigs.builder);
        return await builder.query('Set up API project structure');
      })
      .step('implement', async (ctx) => {
        const builder = createAgent('builder', ctx.state.agentConfigs.builder);
        return await builder.query('Implement API endpoints and services');
      }),`;
  }

  private static generateWebappBuildStep(): string {
    return `
    workflow('webapp-build')
      .step('setup', async (ctx) => {
        const builder = createAgent('builder', ctx.state.agentConfigs.builder);
        return await builder.query('Set up webapp project structure');
      })
      .step('implement', async (ctx) => {
        const builder = createAgent('builder', ctx.state.agentConfigs.builder);
        return await builder.query('Implement UI components and pages');
      }),`;
  }

  private static generateDemoBuildStep(): string {
    return `
    workflow('demo-build')
      .step('create', async (ctx) => {
        const builder = createAgent('builder', ctx.state.agentConfigs.builder);
        return await builder.query('Create demonstration application');
      }),`;
  }
}