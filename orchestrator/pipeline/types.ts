// Types for the Pipeline Orchestrator System

export interface ProjectSpec {
  metadata: {
    name: string;
    version: string;
    description: string;
    license: string;
    authors: string[];
  };
  goals: {
    primary: string;
    secondary: string[];
  };
  components: Record<string, ComponentSpec>;
  security: SecuritySpec;
  testing: TestingSpec;
  deployment: DeploymentSpec;
  success_criteria: SuccessCriteria;
  constraints: ConstraintsSpec;
  documentation: string[];
}

export interface ComponentSpec {
  type: string;
  framework?: string;
  language: string;
  features: string[];
  pages?: string[];
  endpoints?: string[];
  dependencies?: string[];
  database?: DatabaseSpec;
}

export interface DatabaseSpec {
  type: string;
  orm?: string;
  schema: string[];
}

export interface SecuritySpec {
  encryption: string[];
  authentication: string[];
  future: string[];
}

export interface TestingSpec {
  unit: {
    backend: string;
    frontend: string;
    coverage: string;
  };
  integration: {
    tool: string;
    environment: string;
    scenarios: string[];
  };
  security: string[];
}

export interface DeploymentSpec {
  development: Record<string, string>;
  testing: Record<string, string>;
  production: Record<string, string>;
}

export interface SuccessCriteria {
  functional: string[];
  performance: string[];
  security: string[];
  quality: string[];
}

export interface ConstraintsSpec {
  technical: string[];
  business: string[];
}

export interface PipelineState {
  iteration: number;
  lastCheckpoint: string;
  evaluationHistory: EvaluationResult[];
  agentConfigs: AgentConfigMap;
  startTime: Date;
  currentPhase: string;
}

export interface EvaluationResult {
  iteration: number;
  timestamp: Date;
  meetsSpec: boolean;
  functional: boolean;
  performance: boolean;
  security: boolean;
  quality: boolean;
  feedback: string;
  suggestions: string[];
}

export interface AgentConfig {
  model: string;
  systemPrompt: string;
  tools: string[];
}

export interface AgentConfigMap {
  [role: string]: AgentConfig;
}

export interface PipelineOutput {
  phase: string;
  status: 'success' | 'failure' | 'in_progress';
  artifacts: string[];
  errors?: string[];
  metrics?: Record<string, any>;
}