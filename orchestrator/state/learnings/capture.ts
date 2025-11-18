#!/usr/bin/env bun

/**
 * Learning Capture System
 * 
 * This script captures new learnings during pipeline execution
 * and updates the learnings manifest for future improvements.
 */

import { readFileSync, writeFileSync } from 'fs';
import { join } from 'path';
import * as yaml from 'js-yaml';

interface Learning {
  type: 'pattern' | 'error_resolution' | 'architectural_pattern' | 'security_practice' | 'tooling_preference';
  data: any;
  learned_from: string;
  confidence?: 'low' | 'medium' | 'high';
  timestamp: string;
}

interface LearningsManifest {
  learnings_manifest: {
    version: string;
    last_updated: string;
  };
  pipeline_improvements: {
    implementation_patterns: Array<any>;
    error_resolutions: Array<any>;
    architectural_patterns: Array<any>;
    security_practices: Array<any>;
    tooling_preferences: Array<any>;
  };
  [key: string]: any;
}

class LearningCapture {
  private manifestPath: string;
  private manifest: LearningsManifest;

  constructor() {
    this.manifestPath = join(__dirname, 'manifest.yaml');
    this.loadManifest();
  }

  private loadManifest(): void {
    try {
      const content = readFileSync(this.manifestPath, 'utf8');
      this.manifest = yaml.load(content) as LearningsManifest;
    } catch (error) {
      console.error('Failed to load learnings manifest:', error);
      process.exit(1);
    }
  }

  private saveManifest(): void {
    try {
      this.manifest.learnings_manifest.last_updated = new Date().toISOString().split('T')[0];
      const content = yaml.dump(this.manifest, { 
        indent: 2,
        lineWidth: -1,
        noRefs: true 
      });
      writeFileSync(this.manifestPath, content, 'utf8');
      console.log('✅ Learning captured and manifest updated');
    } catch (error) {
      console.error('Failed to save learnings manifest:', error);
      process.exit(1);
    }
  }

  public capturePattern(pattern: string, description: string, learned_from: string, confidence: string = 'medium', applies_to: string[] = []): void {
    const newPattern = {
      pattern,
      description,
      learned_from,
      confidence,
      applies_to,
      timestamp: new Date().toISOString()
    };

    // Check if pattern already exists
    const existingIndex = this.manifest.pipeline_improvements.implementation_patterns
      .findIndex(p => p.pattern === pattern);

    if (existingIndex >= 0) {
      this.manifest.pipeline_improvements.implementation_patterns[existingIndex] = newPattern;
      console.log(`🔄 Updated existing pattern: ${pattern}`);
    } else {
      this.manifest.pipeline_improvements.implementation_patterns.push(newPattern);
      console.log(`➕ Added new pattern: ${pattern}`);
    }

    this.saveManifest();
  }

  public captureErrorResolution(error: string, solution: string, context: string, learned_from: string): void {
    const newResolution = {
      error,
      solution,
      context,
      learned_from,
      timestamp: new Date().toISOString()
    };

    // Check if error resolution already exists
    const existingIndex = this.manifest.pipeline_improvements.error_resolutions
      .findIndex(r => r.error === error);

    if (existingIndex >= 0) {
      this.manifest.pipeline_improvements.error_resolutions[existingIndex] = newResolution;
      console.log(`🔄 Updated existing error resolution: ${error}`);
    } else {
      this.manifest.pipeline_improvements.error_resolutions.push(newResolution);
      console.log(`➕ Added new error resolution: ${error}`);
    }

    this.saveManifest();
  }

  public captureArchitecturalPattern(pattern: string, description: string, benefits: string[], learned_from: string, confidence: string = 'medium'): void {
    const newPattern = {
      pattern,
      description,
      benefits,
      learned_from,
      confidence,
      timestamp: new Date().toISOString()
    };

    // Check if architectural pattern already exists
    const existingIndex = this.manifest.pipeline_improvements.architectural_patterns
      .findIndex(p => p.pattern === pattern);

    if (existingIndex >= 0) {
      this.manifest.pipeline_improvements.architectural_patterns[existingIndex] = newPattern;
      console.log(`🔄 Updated existing architectural pattern: ${pattern}`);
    } else {
      this.manifest.pipeline_improvements.architectural_patterns.push(newPattern);
      console.log(`➕ Added new architectural pattern: ${pattern}`);
    }

    this.saveManifest();
  }

  public captureSecurityPractice(practice: string, description: string, importance: string, learned_from: string): void {
    const newPractice = {
      practice,
      description,
      importance,
      learned_from,
      timestamp: new Date().toISOString()
    };

    // Check if security practice already exists
    const existingIndex = this.manifest.pipeline_improvements.security_practices
      .findIndex(p => p.practice === practice);

    if (existingIndex >= 0) {
      this.manifest.pipeline_improvements.security_practices[existingIndex] = newPractice;
      console.log(`🔄 Updated existing security practice: ${practice}`);
    } else {
      this.manifest.pipeline_improvements.security_practices.push(newPractice);
      console.log(`➕ Added new security practice: ${practice}`);
    }

    this.saveManifest();
  }

  public captureToolingPreference(tool: string, reason: string, learned_from: string): void {
    const newPreference = {
      tool,
      reason,
      learned_from,
      timestamp: new Date().toISOString()
    };

    // Check if tooling preference already exists
    const existingIndex = this.manifest.pipeline_improvements.tooling_preferences
      .findIndex(t => t.tool === tool);

    if (existingIndex >= 0) {
      this.manifest.pipeline_improvements.tooling_preferences[existingIndex] = newPreference;
      console.log(`🔄 Updated existing tooling preference: ${tool}`);
    } else {
      this.manifest.pipeline_improvements.tooling_preferences.push(newPreference);
      console.log(`➕ Added new tooling preference: ${tool}`);
    }

    this.saveManifest();
  }

  public listLearnings(): void {
    console.log('\n📚 Current Learnings:');
    console.log(`\n🔧 Implementation Patterns (${this.manifest.pipeline_improvements.implementation_patterns.length}):`);
    this.manifest.pipeline_improvements.implementation_patterns.forEach(p => {
      console.log(`  • ${p.pattern}: ${p.description}`);
    });

    console.log(`\n🐛 Error Resolutions (${this.manifest.pipeline_improvements.error_resolutions.length}):`);
    this.manifest.pipeline_improvements.error_resolutions.forEach(r => {
      console.log(`  • ${r.error}: ${r.solution}`);
    });

    console.log(`\n🏗️ Architectural Patterns (${this.manifest.pipeline_improvements.architectural_patterns.length}):`);
    this.manifest.pipeline_improvements.architectural_patterns.forEach(p => {
      console.log(`  • ${p.pattern}: ${p.description}`);
    });

    console.log(`\n🔒 Security Practices (${this.manifest.pipeline_improvements.security_practices.length}):`);
    this.manifest.pipeline_improvements.security_practices.forEach(p => {
      console.log(`  • ${p.practice}: ${p.description}`);
    });

    console.log(`\n🛠️ Tooling Preferences (${this.manifest.pipeline_improvements.tooling_preferences.length}):`);
    this.manifest.pipeline_improvements.tooling_preferences.forEach(t => {
      console.log(`  • ${t.tool}: ${t.reason}`);
    });
  }
}

// CLI interface
function main() {
  const args = process.argv.slice(2);
  const capture = new LearningCapture();

  if (args.length === 0) {
    console.log(`
📚 Learning Capture System

Usage:
  bun capture.ts pattern <pattern> <description> <learned_from> [confidence] [applies_to...]
  bun capture.ts error <error> <solution> <context> <learned_from>
  bun capture.ts architecture <pattern> <description> <learned_from> [confidence] [benefits...]
  bun capture.ts security <practice> <description> <importance> <learned_from>
  bun capture.ts tooling <tool> <reason> <learned_from>
  bun capture.ts list

Examples:
  bun capture.ts pattern "bun_over_npm" "Use Bun instead of npm" "openkey_implementation" "high" "typescript" "javascript"
  bun capture.ts error "docker_build_fail" "Use bun install instead of npm ci" "Missing lockfile" "openkey_implementation"
  bun capture.ts list
    `);
    return;
  }

  const command = args[0];

  switch (command) {
    case 'pattern':
      if (args.length < 4) {
        console.error('❌ Missing arguments for pattern command');
        return;
      }
      capture.capturePattern(args[1], args[2], args[3], args[4] || 'medium', args.slice(5));
      break;

    case 'error':
      if (args.length < 5) {
        console.error('❌ Missing arguments for error command');
        return;
      }
      capture.captureErrorResolution(args[1], args[2], args[3], args[4]);
      break;

    case 'architecture':
      if (args.length < 4) {
        console.error('❌ Missing arguments for architecture command');
        return;
      }
      capture.captureArchitecturalPattern(args[1], args[2], args.slice(5), args[3], args[4] || 'medium');
      break;

    case 'security':
      if (args.length < 5) {
        console.error('❌ Missing arguments for security command');
        return;
      }
      capture.captureSecurityPractice(args[1], args[2], args[3], args[4]);
      break;

    case 'tooling':
      if (args.length < 4) {
        console.error('❌ Missing arguments for tooling command');
        return;
      }
      capture.captureToolingPreference(args[1], args[2], args[3]);
      break;

    case 'list':
      capture.listLearnings();
      break;

    default:
      console.error(`❌ Unknown command: ${command}`);
  }
}

if (import.meta.main) {
  main();
}

export { LearningCapture };