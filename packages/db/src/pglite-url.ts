import { homedir } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';

export const DEFAULT_PGLITE_DATABASE_URL = 'pglite:';
export const DEFAULT_PGLITE_DATA_DIR = join(homedir(), '.local', 'share', 'openkey', 'dev.pglite');

export function isPgliteConnectionString(connectionString: string) {
  return connectionString.startsWith('pglite:');
}

export function resolvePgliteDataDir(connectionString: string) {
  if (!isPgliteConnectionString(connectionString)) {
    throw new Error(`Expected a pglite: connection string, received: ${connectionString}`);
  }

  const rawPath = connectionString.replace(/^pglite:(?:\/\/)?/, '');
  if (!rawPath || rawPath === '/') {
    return DEFAULT_PGLITE_DATA_DIR;
  }

  if (rawPath === '~') {
    return homedir();
  }

  if (rawPath.startsWith('~/')) {
    return join(homedir(), rawPath.slice(2));
  }

  if (rawPath.startsWith('memory://')) {
    return rawPath;
  }

  return isAbsolute(rawPath) ? rawPath : resolve(process.cwd(), rawPath);
}
