import { getValidTokens } from '../api';

export async function tokenCommand(options: { host: string; clientId: string }) {
  const tokens = await getValidTokens(options.host, options.clientId);
  // Write to stdout without newline for piping
  process.stdout.write(tokens.accessToken);
}
