#!/bin/bash
set -e

# Publish packages to npm
# This script is called by the changesets action

echo "=== Publishing OpenKey packages ==="

# Configure npm authentication
./scripts/npm-auth.sh

# Publish with changesets
bun changeset publish --access public

echo "=== Publishing complete ==="
