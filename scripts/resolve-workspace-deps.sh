#!/usr/bin/env bash
set -e

# Resolve workspace:* dependencies to concrete versions in publishable packages.
#
# Problem: bun changeset publish does not rewrite "workspace:*" references to
# real version numbers. When packages are published to npm with "workspace:*",
# consumers cannot install them because npm/bun can't resolve the protocol.
#
# Solution: Before publishing, read each workspace package's version and replace
# any "workspace:*" reference with "^{version}" in all publishable package.json files.

echo "Resolving workspace:* dependencies to concrete versions..."

# Publishable packages
PUBLISHABLE=(
  packages/sdk/package.json
  packages/core/package.json
  packages/types/package.json
  packages/cli/package.json
  packages/sdk-react-native/package.json
)

# For each publishable package, find workspace:* refs and resolve them
for pkg_json in "${PUBLISHABLE[@]}"; do
  if [ ! -f "$pkg_json" ]; then
    continue
  fi

  # Find all workspace:* dependencies in this package
  workspace_deps=$(jq -r '
    [.dependencies, .devDependencies, .peerDependencies]
    | map(select(. != null))
    | map(to_entries[] | select(.value | startswith("workspace:")))
    | .[]
    | .key
  ' "$pkg_json" 2>/dev/null || true)

  if [ -z "$workspace_deps" ]; then
    continue
  fi

  for dep_name in $workspace_deps; do
    # Find the dep's package.json to get its version
    # Strip @openkey/ scope to get dir name
    dep_dir=$(echo "$dep_name" | sed 's|@openkey/||')
    dep_pkg="packages/$dep_dir/package.json"

    if [ ! -f "$dep_pkg" ]; then
      echo "  Warning: $dep_pkg not found for $dep_name, skipping"
      continue
    fi

    version=$(jq -r '.version' "$dep_pkg")
    if [ -z "$version" ] || [ "$version" = "null" ]; then
      echo "  Warning: no version found in $dep_pkg, skipping"
      continue
    fi

    echo "  $pkg_json: $dep_name workspace:* -> ^$version"

    # Replace in dependencies, devDependencies, peerDependencies
    tmp=$(mktemp)
    jq --arg name "$dep_name" --arg ver "^$version" '
      if .dependencies[$name] and (.dependencies[$name] | startswith("workspace:"))
        then .dependencies[$name] = $ver else . end
      | if .devDependencies[$name] and (.devDependencies[$name] | startswith("workspace:"))
        then .devDependencies[$name] = $ver else . end
      | if .peerDependencies[$name] and (.peerDependencies[$name] | startswith("workspace:"))
        then .peerDependencies[$name] = $ver else . end
    ' "$pkg_json" > "$tmp"
    mv "$tmp" "$pkg_json"
  done
done

echo "Workspace dependency resolution complete."
