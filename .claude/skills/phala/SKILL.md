---
name: phala-cloud-cli
description: Deploy and manage applications on Phala Cloud's TEE (Trusted Execution Environment) infrastructure using the Phala CLI. Use this skill when working with Phala Cloud deployments, CVMs (Confidential Virtual Machines), TEE applications, or when pushing Docker containers to Phala's confidential computing platform. Triggers include mentions of Phala, TEE deployment, CVM management, confidential computing deployment, or dstack.
---

# Phala Cloud CLI

Deploy confidential applications to Phala Cloud's managed TEE infrastructure.

## Prerequisites

- Node.js with npm (or Bun)
- Docker installed and running
- Phala Cloud account with API key

## Installation

```bash
npm install -g phala
```

Or use without installing: `npx phala <command>` or `bunx phala <command>`

## Authentication

1. Get API key from https://cloud.phala.com → User Avatar → API Tokens
2. Authenticate:

```bash
phala auth login <your-api-key>
phala auth status  # verify authentication
```

## Complete Deployment Workflow

### Local Development

```bash
# Start TEE simulator for local testing
phala simulator start --port 8090

# Build Docker image
phala docker build --image my-app --tag v1.0.0

# Create env file
echo "API_KEY=test" > .env

# Generate and run locally
phala docker generate --image my-app --tag v1.0.0 -e .env
```

### Deploy to Phala Cloud

```bash
# Login to Docker Hub
phala docker login --username <dockerhub-username>

# Build and push image
phala docker build --image my-app --tag v1.0.0
phala docker push --image <username>/my-app:v1.0.0

# Deploy CVM
phala cvms create --name my-app --compose ./docker-compose.yml --env-file ./.env
```

### Interactive Deployment

Run `phala cvms create` without options for guided setup:
- Select from example templates or custom compose file
- Configure vCPUs, memory, disk size
- Select TEEPod (prod5, prod2, etc.)
- Select dstack image version

## CVM Management Commands

```bash
phala cvms ls                    # List all CVMs
phala cvms get <app-id>          # Get CVM details
phala cvms status <app-id>       # Check status
phala cvms start <app-id>        # Start stopped CVM
phala cvms stop <app-id>         # Stop running CVM
phala cvms restart <app-id>      # Restart CVM
phala cvms resize <app-id>       # Resize resources
phala cvms delete <app-id>       # Delete CVM
phala cvms attestation <app-id>  # Get TEE attestation
```

## Updating Deployed Applications

**Important:** Increment Docker tags for each deployment—Phala may not pull latest if tag unchanged.

```bash
# Build new version with incremented tag
phala docker build --image my-app --tag v1.0.1
phala docker push --image <username>/my-app:v1.0.1

# Upgrade running CVM
phala cvms upgrade <app-id> --compose ./docker-compose.yml --env-file ./.env
```

Environment variables are **completely replaced** on update—include all required vars.

## App URL Format

Access deployed apps at:
```
https://<app-id>-<port>.dstack-<teepod>.phala.network
```

Example: `https://e15c1a29a9dfb522da528464a8d5ce40ac28039f-7681.dstack-prod5.phala.network`

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Docker build fails | Verify Docker daemon running, check Dockerfile path |
| Simulator issues | Check port 8090 available, verify Docker permissions |
| Deployment fails | Validate API key, confirm image on Docker Hub, check env vars |
| Image not updating | Increment Docker tag version |

Get help: `phala --help` or `phala <command> --help`

## Searching Phala Documentation

If information is missing or outdated, search https://docs.phala.com. Key documentation sections:

- **CLI Reference**: `/phala-cloud/references/phala-cloud-cli/phala/`
- **CVM Deployment**: `/phala-cloud/phala-cloud-cli/start-from-cloud-cli`
- **Code Updates**: `/phala-cloud/update/upgrade-application`
- **Attestation**: `/phala-cloud/attestation/`
- **Networking**: `/phala-cloud/networking/`
- **Key Management (KMS)**: `/phala-cloud/key-management/`
- **GPU TEE**: `/phala-cloud/confidential-ai/`
- **Troubleshooting**: `/phala-cloud/troubleshooting/`
- **FAQs**: `/phala-cloud/faqs`

Use web_fetch on `https://docs.phala.com/phala-cloud/<section>` to get current documentation.
