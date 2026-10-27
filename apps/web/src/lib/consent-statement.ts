import { renderLiteral, type StatementEntry } from '@openkey/capability-review';

/** Keep pre-escaped fallback rows intact; escape only raw, unmapped copy. */
export function displayConsentStatement(statement: Pick<StatementEntry, 'primaryText' | 'literalEscaped'>): string {
  const text = statement.primaryText;
  if (statement.literalEscaped) return text;
  return text.startsWith('Perform ') || text.startsWith('Access ')
    ? renderLiteral(text, 280)
    : text;
}
