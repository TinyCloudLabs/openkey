#!/usr/bin/env bash
set -e

# This script creates proper .npmrc files with authentication
# It should be called before publishing packages

# Check for NPM_TOKEN
if [ -z "$NPM_TOKEN" ]; then
  echo "ERROR: NPM_TOKEN environment variable is not set"
  exit 1
fi

# Create ~/.npmrc with proper format
echo "Creating ~/.npmrc file..."
echo "registry=https://registry.npmjs.org/" > ~/.npmrc
echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" >> ~/.npmrc
echo "always-auth=true" >> ~/.npmrc

# Create root .npmrc as well
echo "Creating project root .npmrc file..."
echo "registry=https://registry.npmjs.org/" > .npmrc
echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" >> .npmrc
echo "always-auth=true" >> .npmrc

# Also create .npmrc in each package directory
echo "Creating package-specific .npmrc files..."
mkdir -p packages/sdk
echo "registry=https://registry.npmjs.org/" > packages/sdk/.npmrc
echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" >> packages/sdk/.npmrc
echo "always-auth=true" >> packages/sdk/.npmrc

mkdir -p packages/types
echo "registry=https://registry.npmjs.org/" > packages/types/.npmrc
echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" >> packages/types/.npmrc
echo "always-auth=true" >> packages/types/.npmrc

mkdir -p packages/db
echo "registry=https://registry.npmjs.org/" > packages/db/.npmrc
echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" >> packages/db/.npmrc
echo "always-auth=true" >> packages/db/.npmrc

mkdir -p packages/tee
echo "registry=https://registry.npmjs.org/" > packages/tee/.npmrc
echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" >> packages/tee/.npmrc
echo "always-auth=true" >> packages/tee/.npmrc

# Verify npm auth works
if command -v npm &> /dev/null; then
  echo "Verifying npm authentication..."
  npm whoami || echo "Warning: npm authentication failed, but continuing anyway"
fi

echo "NPM authentication setup complete"
