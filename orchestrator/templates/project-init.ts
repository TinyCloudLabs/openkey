// Project Initialization Template
// Used by the orchestrator to create a deployable project structure

import { ProjectSpec } from '../pipeline/types';
import * as fs from 'fs/promises';
import * as path from 'path';

export class ProjectInitializer {
  
  static async initializeProject(spec: ProjectSpec, projectPath: string = 'project') {
    console.log(`📁 Initializing ${spec.metadata.name} project structure...`);
    
    // Create base directory structure
    const directories = [
      'backend/src',
      'backend/tests',
      'frontend/src',
      'frontend/public',
      'frontend/tests',
      'shared/types',
      'shared/utils',
      'tests/integration',
      'tests/e2e',
      'docs/api',
      'docs/guides',
      '.github/workflows',
      'scripts',
      'infrastructure/terraform',
      'infrastructure/kubernetes'
    ];
    
    for (const dir of directories) {
      await fs.mkdir(path.join(projectPath, dir), { recursive: true });
    }
    
    // Create root package.json
    await this.createRootPackageJson(spec, projectPath);
    
    // Create Docker Compose for local development
    await this.createDockerCompose(spec, projectPath);
    
    // Create .gitignore
    await this.createGitignore(projectPath);
    
    // Create README
    await this.createProjectReadme(spec, projectPath);
    
    // Create CI/CD workflow
    await this.createGitHubWorkflow(spec, projectPath);
    
    // Create environment example
    await this.createEnvExample(spec, projectPath);
    
    console.log('✅ Project structure initialized');
  }
  
  private static async createRootPackageJson(spec: ProjectSpec, projectPath: string) {
    const packageJson = {
      name: spec.metadata.name,
      version: spec.metadata.version,
      description: spec.metadata.description,
      private: true,
      workspaces: ["backend", "frontend", "shared"],
      scripts: {
        "dev": "docker-compose up",
        "build": "npm run build:shared && npm run build:backend && npm run build:frontend",
        "build:shared": "cd shared && npm run build",
        "build:backend": "cd backend && npm run build",
        "build:frontend": "cd frontend && npm run build",
        "test": "npm run test:unit && npm run test:integration",
        "test:unit": "npm run test:backend && npm run test:frontend",
        "test:backend": "cd backend && npm test",
        "test:frontend": "cd frontend && npm test",
        "test:integration": "cd tests && npm run integration",
        "test:e2e": "cd tests && npm run e2e",
        "lint": "npm run lint:backend && npm run lint:frontend",
        "lint:backend": "cd backend && npm run lint",
        "lint:frontend": "cd frontend && npm run lint",
        "deploy:local": "cd ../deployments/local && ./deploy-local.sh",
        "deploy:staging": "cd ../deployments/staging && ./deploy-staging.sh",
        "deploy:production": "cd ../deployments/production && ./deploy-production.sh"
      },
      devDependencies: {
        "@types/node": "^20.0.0",
        "typescript": "^5.0.0",
        "prettier": "^3.0.0",
        "eslint": "^8.0.0",
        "husky": "^9.0.0",
        "lint-staged": "^15.0.0"
      },
      engines: {
        "node": ">=18.0.0",
        "npm": ">=9.0.0"
      }
    };
    
    await fs.writeFile(
      path.join(projectPath, 'package.json'),
      JSON.stringify(packageJson, null, 2)
    );
  }
  
  private static async createDockerCompose(spec: ProjectSpec, projectPath: string) {
    const dockerCompose = `version: '3.8'

services:
  # PostgreSQL Database
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: openkey
      POSTGRES_PASSWORD: localdev
      POSTGRES_DB: openkey
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U openkey"]
      interval: 5s
      timeout: 5s
      retries: 5

  # Redis for sessions
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 5s
      retries: 5

  # Backend API
  backend:
    build:
      context: .
      dockerfile: backend/Dockerfile.dev
    ports:
      - "3001:3001"
    environment:
      NODE_ENV: development
      DATABASE_URL: postgresql://openkey:localdev@postgres:5432/openkey
      REDIS_URL: redis://redis:6379
      JWT_SECRET: local-dev-secret
      ENCRYPTION_KEY: local-dev-encryption-key
    volumes:
      - ./backend:/app/backend
      - ./shared:/app/shared
      - /app/backend/node_modules
      - /app/shared/node_modules
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    command: npm run dev

  # Frontend
  frontend:
    build:
      context: .
      dockerfile: frontend/Dockerfile.dev
    ports:
      - "3000:3000"
    environment:
      NEXT_PUBLIC_API_URL: http://localhost:3001
    volumes:
      - ./frontend:/app/frontend
      - ./shared:/app/shared
      - /app/frontend/node_modules
      - /app/shared/node_modules
    depends_on:
      - backend
    command: npm run dev

  # ngrok for HTTPS testing (WebAuthn requires HTTPS)
  ngrok:
    image: ngrok/ngrok:alpine
    environment:
      NGROK_AUTHTOKEN: \${NGROK_AUTHTOKEN:-}
    command: http frontend:3000
    ports:
      - "4040:4040" # ngrok web interface
    depends_on:
      - frontend

volumes:
  postgres_data:
  redis_data:
`;
    
    await fs.writeFile(
      path.join(projectPath, 'docker-compose.yml'),
      dockerCompose
    );
  }
  
  private static async createGitignore(projectPath: string) {
    const gitignore = `# Dependencies
node_modules/
.pnp
.pnp.js

# Testing
coverage/
.nyc_output

# Production
build/
dist/
out/

# Misc
.DS_Store
*.pem
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Environment variables
.env
.env.local
.env.development.local
.env.test.local
.env.production.local

# IDE
.idea/
.vscode/
*.swp
*.swo

# Next.js
.next/
out/

# TypeScript
*.tsbuildinfo

# Docker
docker-compose.override.yml

# Logs
logs/
*.log

# OS files
Thumbs.db

# Temporary files
tmp/
temp/
`;
    
    await fs.writeFile(
      path.join(projectPath, '.gitignore'),
      gitignore
    );
  }
  
  private static async createProjectReadme(spec: ProjectSpec, projectPath: string) {
    const readme = `# ${spec.metadata.name}

${spec.metadata.description}

## 🚀 Quick Start

### Prerequisites
- Node.js 18+
- Docker & Docker Compose
- ngrok account (for WebAuthn testing)

### Local Development

1. Clone the repository:
\`\`\`bash
git clone https://github.com/your-org/${spec.metadata.name}.git
cd ${spec.metadata.name}
\`\`\`

2. Install dependencies:
\`\`\`bash
npm install
\`\`\`

3. Set up environment variables:
\`\`\`bash
cp .env.example .env
# Edit .env with your values
\`\`\`

4. Start the development environment:
\`\`\`bash
npm run dev
\`\`\`

5. Access the application:
- Frontend: http://localhost:3000
- Backend API: http://localhost:3001
- ngrok tunnel: Check http://localhost:4040

## 🏗️ Architecture

### Components
${Object.entries(spec.components).map(([name, comp]) => 
  `- **${name}**: ${comp.type} built with ${comp.framework || comp.language}`
).join('\n')}

### Tech Stack
- Backend: ${spec.components.backend?.framework} with ${spec.components.backend?.language}
- Frontend: ${spec.components.frontend?.framework} with ${spec.components.frontend?.language}
- Database: ${spec.components.backend?.database?.type}
- Authentication: WebAuthn (Passkeys)
- Blockchain: Ethereum key management

## 🧪 Testing

Run all tests:
\`\`\`bash
npm test
\`\`\`

Run specific test suites:
\`\`\`bash
npm run test:unit       # Unit tests
npm run test:integration # Integration tests
npm run test:e2e        # End-to-end tests
\`\`\`

## 📦 Deployment

### Local Deployment
\`\`\`bash
npm run deploy:local
\`\`\`

### Staging Deployment
\`\`\`bash
npm run deploy:staging
\`\`\`

### Production Deployment
\`\`\`bash
npm run deploy:production
\`\`\`

## 🔒 Security

${spec.security.encryption.map(e => `- ${e}`).join('\n')}
${spec.security.authentication.map(a => `- ${a}`).join('\n')}

## 📄 License

${spec.metadata.license}

## 👥 Authors

${spec.metadata.authors.map(a => `- ${a}`).join('\n')}
`;
    
    await fs.writeFile(
      path.join(projectPath, 'README.md'),
      readme
    );
  }
  
  private static async createGitHubWorkflow(spec: ProjectSpec, projectPath: string) {
    const workflow = `name: CI/CD Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:16
        env:
          POSTGRES_USER: openkey
          POSTGRES_PASSWORD: testpass
          POSTGRES_DB: openkey_test
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432
          
      redis:
        image: redis:7
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 6379:6379

    steps:
    - uses: actions/checkout@v4
    
    - name: Setup Node.js
      uses: actions/setup-node@v4
      with:
        node-version: '20'
        cache: 'npm'
    
    - name: Install dependencies
      run: npm ci
    
    - name: Run linters
      run: npm run lint
    
    - name: Run unit tests
      run: npm run test:unit
      env:
        DATABASE_URL: postgresql://openkey:testpass@localhost:5432/openkey_test
        REDIS_URL: redis://localhost:6379
    
    - name: Run integration tests
      run: npm run test:integration
      env:
        DATABASE_URL: postgresql://openkey:testpass@localhost:5432/openkey_test
        REDIS_URL: redis://localhost:6379
    
    - name: Build application
      run: npm run build
    
    - name: Upload coverage
      uses: codecov/codecov-action@v3
      
  deploy-staging:
    needs: test
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/develop'
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Deploy to staging
      run: |
        cd deployments/staging
        ./deploy-staging.sh
      env:
        STAGING_HOST: \${{ secrets.STAGING_HOST }}
        STAGING_USER: \${{ secrets.STAGING_USER }}
        STAGING_KEY: \${{ secrets.STAGING_KEY }}
        
  deploy-production:
    needs: test
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Deploy to production
      run: |
        cd deployments/production
        ./deploy-production.sh
      env:
        PROD_HOST: \${{ secrets.PROD_HOST }}
        PROD_USER: \${{ secrets.PROD_USER }}
        PROD_KEY: \${{ secrets.PROD_KEY }}
`;
    
    await fs.writeFile(
      path.join(projectPath, '.github/workflows/ci-cd.yml'),
      workflow
    );
  }
  
  private static async createEnvExample(spec: ProjectSpec, projectPath: string) {
    const envExample = `# OpenKey Environment Variables

# Node Environment
NODE_ENV=development

# Database
DATABASE_URL=postgresql://openkey:localdev@localhost:5432/openkey

# Redis
REDIS_URL=redis://localhost:6379

# API
PORT=3001
API_URL=http://localhost:3001

# Frontend
FRONTEND_URL=http://localhost:3000

# Security
JWT_SECRET=your-jwt-secret-here-min-32-chars
JWT_EXPIRES_IN=7d
ENCRYPTION_KEY=your-encryption-key-here-32-chars

# WebAuthn
WEBAUTHN_RP_NAME=${spec.metadata.name}
WEBAUTHN_RP_ID=localhost
WEBAUTHN_ORIGIN=http://localhost:3000
WEBAUTHN_CHALLENGE_TIMEOUT=60000

# Email (for recovery)
SMTP_HOST=smtp.mailtrap.io
SMTP_PORT=2525
SMTP_USER=your-smtp-user
SMTP_PASSWORD=your-smtp-password
EMAIL_FROM=noreply@openkey.local

# ngrok (for HTTPS testing)
NGROK_AUTHTOKEN=your-ngrok-token

# Feature Flags
ENABLE_EMAIL_RECOVERY=true
ENABLE_MULTI_DEVICE=true
ENABLE_TEE_INTEGRATION=false

# Rate Limiting
ENABLE_RATE_LIMITING=true
RATE_LIMIT_WINDOW=60000
RATE_LIMIT_MAX_REQUESTS=100

# Logging
LOG_LEVEL=debug
LOG_FORMAT=json

# Monitoring (optional)
SENTRY_DSN=
DATADOG_API_KEY=
`;
    
    await fs.writeFile(
      path.join(projectPath, '.env.example'),
      envExample
    );
  }
}

export default ProjectInitializer;