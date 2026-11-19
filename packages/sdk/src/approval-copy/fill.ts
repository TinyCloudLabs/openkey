/** The `{name}` placeholders in a template type. */
type Names<T extends string> = T extends `${string}{${infer Name}}${infer Rest}` ? Name | Names<Rest> : never;

/** Values for the placeholders of a literal template; any named values for a template only known as `string`. */
export type FillValues<T extends string> = string extends T
  ? Record<string, string | number>
  : { [Name in Names<T>]: string | number };

/**
 * Puts values into a template's `{name}` placeholders. A placeholder without a value is left as written, so a
 * missing value shows up in the page and in a test instead of throwing in the middle of an approval.
 */
export function fill<const T extends string>(template: T, values: NoInfer<FillValues<T>>): string {
  const named: Record<string, string | number> = values;
  return template.replace(/\{([A-Za-z][A-Za-z0-9]*)\}/g, (placeholder, name: string) =>
    Object.prototype.hasOwnProperty.call(named, name) ? String(named[name]) : placeholder,
  );
}
