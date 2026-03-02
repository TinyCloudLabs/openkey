#!/bin/bash
set -e

# Publish packages to npm
# This script is called by the changesets action

echo "=== Publishing OpenKey packages ==="

# Configure npm authentication
./scripts/npm-auth.sh

# Rewrite workspace:* references to concrete versions before publishing.
# bun changeset publish does not do this automatically, so published packages
# end up with "workspace:*" in their dependencies which breaks consumers.
./scripts/resolve-workspace-deps.sh

# Publish with changesets
bun changeset publish --access public

echo "=== Publishing complete ==="
