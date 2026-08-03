/** Return the verb portion of a fully-qualified capability ability. */
export function abilityVerb(ability: string): string {
  const slash = ability.indexOf("/");
  return slash === -1 ? ability : ability.slice(slash + 1);
}

/**
 * True only for a non-empty set of list/metadata operations. These actions
 * can reveal secret names and metadata, but they do not read secret values.
 * Byte-exact service allowlists remain responsible for rejecting unknown
 * capability shapes before friendly copy is shown.
 */
export function isMetadataOnlyAccess(
  abilities: readonly string[],
): boolean {
  return (
    abilities.length > 0 &&
    abilities.every((ability) => {
      const verb = abilityVerb(ability);
      return verb === "list" || verb === "metadata";
    })
  );
}
