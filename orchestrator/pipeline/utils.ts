// Pipeline Utilities
// Helper functions for the Pipeline Orchestrator

import { ProjectSpec, PipelineState, EvaluationResult } from './types';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as yaml from 'js-yaml';

export class PipelineUtils {
  
  static async loadSpec(specPath: string): Promise<ProjectSpec> {
    try {
      const content = await fs.readFile(specPath, 'utf8');
      return yaml.load(content) as ProjectSpec;
    } catch (error) {
      throw new Error(`Failed to load spec file ${specPath}: ${error.message}`);
    }
  }

  static async saveState(projectName: string, state: PipelineState): Promise<void> {
    const statePath = path.join('pipeline', 'state', projectName, 'current-state.json');
    await this.ensureDir(path.dirname(statePath));
    await fs.writeFile(statePath, JSON.stringify(state, null, 2));
  }

  static async loadState(projectName: string): Promise<PipelineState | null> {
    const statePath = path.join('pipeline', 'state', projectName, 'current-state.json');
    try {
      const content = await fs.readFile(statePath, 'utf8');
      return JSON.parse(content);
    } catch (error) {
      return null; // No existing state
    }
  }

  static async saveCheckpoint(projectName: string, state: PipelineState): Promise<void> {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const checkpointPath = path.join(
      'pipeline', 
      'state', 
      projectName, 
      'checkpoints', 
      `${state.currentPhase}-${timestamp}.json`
    );
    
    await this.ensureDir(path.dirname(checkpointPath));
    await fs.writeFile(checkpointPath, JSON.stringify(state, null, 2));
    
    // Also update current state
    await this.saveState(projectName, state);
  }

  static async saveArtifact(
    projectName: string, 
    artifactName: string, 
    content: any
  ): Promise<void> {
    const artifactPath = path.join('pipeline', 'artifacts', projectName, artifactName);
    await this.ensureDir(path.dirname(artifactPath));
    
    const contentStr = typeof content === 'string' 
      ? content 
      : JSON.stringify(content, null, 2);
    
    await fs.writeFile(artifactPath, contentStr);
  }

  static async saveEvaluation(
    projectName: string, 
    evaluation: EvaluationResult
  ): Promise<void> {
    const timestamp = evaluation.timestamp.toISOString().replace(/[:.]/g, '-');
    const evalPath = path.join(
      'pipeline', 
      'state', 
      projectName, 
      'evaluations', 
      `evaluation-${evaluation.iteration}-${timestamp}.json`
    );
    
    await this.ensureDir(path.dirname(evalPath));
    await fs.writeFile(evalPath, JSON.stringify(evaluation, null, 2));
  }

  static async getLatestCheckpoint(projectName: string): Promise<PipelineState | null> {
    const checkpointsDir = path.join('pipeline', 'state', projectName, 'checkpoints');
    
    try {
      const files = await fs.readdir(checkpointsDir);
      if (files.length === 0) return null;
      
      // Sort by modification time, newest first
      const stats = await Promise.all(
        files.map(async file => ({
          file,
          mtime: (await fs.stat(path.join(checkpointsDir, file))).mtime
        }))
      );
      
      stats.sort((a, b) => b.mtime.getTime() - a.mtime.getTime());
      const latestFile = stats[0].file;
      
      const content = await fs.readFile(
        path.join(checkpointsDir, latestFile), 
        'utf8'
      );
      return JSON.parse(content);
      
    } catch (error) {
      return null;
    }
  }

  static async getEvaluationHistory(projectName: string): Promise<EvaluationResult[]> {
    const evaluationsDir = path.join('pipeline', 'state', projectName, 'evaluations');
    
    try {
      const files = await fs.readdir(evaluationsDir);
      const evaluations = await Promise.all(
        files.map(async file => {
          const content = await fs.readFile(
            path.join(evaluationsDir, file), 
            'utf8'
          );
          return JSON.parse(content) as EvaluationResult;
        })
      );
      
      // Sort by iteration number
      return evaluations.sort((a, b) => a.iteration - b.iteration);
      
    } catch (error) {
      return [];
    }
  }

  static async initializeProject(projectName: string): Promise<PipelineState> {
    const initialState: PipelineState = {
      iteration: 1,
      lastCheckpoint: 'init',
      evaluationHistory: [],
      agentConfigs: {},
      startTime: new Date(),
      currentPhase: 'initialization'
    };

    await this.saveState(projectName, initialState);
    return initialState;
  }

  static async ensureDir(dirPath: string): Promise<void> {
    try {
      await fs.mkdir(dirPath, { recursive: true });
    } catch (error) {
      if (error.code !== 'EEXIST') {
        throw error;
      }
    }
  }

  static generateProjectSummary(spec: ProjectSpec, state: PipelineState): string {
    const componentCount = Object.keys(spec.components).length;
    const criteriaCount = Object.values(spec.success_criteria).flat().length;
    
    return `
# ${spec.metadata.name} Project Summary

**Version**: ${spec.metadata.version}  
**License**: ${spec.metadata.license}  
**Current Iteration**: ${state.iteration}  
**Current Phase**: ${state.currentPhase}  

## Project Goals
${spec.goals.primary}

## Components (${componentCount})
${Object.entries(spec.components).map(([name, comp]) => 
  `- **${name}**: ${comp.type} (${comp.framework || comp.language})`
).join('\n')}

## Success Criteria (${criteriaCount})
- Functional: ${spec.success_criteria.functional.length} requirements
- Performance: ${spec.success_criteria.performance.length} requirements  
- Security: ${spec.success_criteria.security.length} requirements
- Quality: ${spec.success_criteria.quality.length} requirements

## Progress
- Started: ${state.startTime.toISOString()}
- Evaluations: ${state.evaluationHistory.length}
- Last Checkpoint: ${state.lastCheckpoint}

## Recent Evaluations
${state.evaluationHistory.slice(-3).map(eval => 
  `- Iteration ${eval.iteration}: ${eval.meetsSpec ? '✅ PASS' : '❌ FAIL'} (${eval.timestamp.toISOString()})`
).join('\n')}
`;
  }

  static validateSpec(spec: ProjectSpec): string[] {
    const errors: string[] = [];

    if (!spec.metadata?.name) {
      errors.push('Missing metadata.name');
    }

    if (!spec.goals?.primary) {
      errors.push('Missing goals.primary');
    }

    if (!spec.components || Object.keys(spec.components).length === 0) {
      errors.push('Missing or empty components');
    }

    if (!spec.success_criteria) {
      errors.push('Missing success_criteria');
    }

    // Validate each component
    Object.entries(spec.components || {}).forEach(([name, comp]) => {
      if (!comp.type) {
        errors.push(`Component ${name} missing type`);
      }
      if (!comp.language) {
        errors.push(`Component ${name} missing language`);
      }
    });

    return errors;
  }
}

export default PipelineUtils;