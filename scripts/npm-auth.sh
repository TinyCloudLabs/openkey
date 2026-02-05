#!/bin/bash

# Configure npm authentication for publishing
# Requires NPM_TOKEN environment variable

if [ -z "$NPM_TOKEN" ]; then
  echo "Error: NPM_TOKEN environment variable is not set"
  exit 1
fi

# Create .npmrc in home directory
cat > ~/.npmrc << NPMRC
registry=https://registry.npmjs.org/
//registry.npmjs.org/:_authToken=${NPM_TOKEN}
always-auth=true
NPMRC

# Create .npmrc in project root
cat > .npmrc << NPMRC
registry=https://registry.npmjs.org/
//registry.npmjs.org/:_authToken=${NPM_TOKEN}
always-auth=true
NPMRC

# Create .npmrc in publishable packages
for pkg in packages/sdk packages/types; do
  if [ -d "$pkg" ]; then
    cat > "$pkg/.npmrc" << NPMRC
registry=https://registry.npmjs.org/
//registry.npmjs.org/:_authToken=${NPM_TOKEN}
always-auth=true
NPMRC
  fi
done

echo "npm authentication configured"
