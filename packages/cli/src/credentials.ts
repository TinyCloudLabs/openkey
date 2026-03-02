import { readFileSync, writeFileSync, mkdirSync, existsSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import type { AuthTokens } from '@openkey/core';

export interface StoredCredentials {
  host: string;
  clientId: string;
  tokens: AuthTokens;
  storedAt: string; // ISO timestamp
}

type CredentialsStore = Record<string, StoredCredentials>;

const OPENKEY_DIR = join(homedir(), '.openkey');
const CREDENTIALS_FILE = join(OPENKEY_DIR, 'credentials.json');

function ensureDir(): void {
  if (!existsSync(OPENKEY_DIR)) {
    mkdirSync(OPENKEY_DIR, { recursive: true, mode: 0o700 });
  }
}

function readStore(): CredentialsStore {
  try {
    const data = readFileSync(CREDENTIALS_FILE, 'utf-8');
    return JSON.parse(data);
  } catch {
    return {};
  }
}

function writeStore(store: CredentialsStore): void {
  ensureDir();
  writeFileSync(CREDENTIALS_FILE, JSON.stringify(store, null, 2), { mode: 0o600 });
}

export function loadCredentials(host: string): StoredCredentials | null {
  const store = readStore();
  return store[host] ?? null;
}

export function saveCredentials(host: string, clientId: string, tokens: AuthTokens): void {
  const store = readStore();
  store[host] = {
    host,
    clientId,
    tokens,
    storedAt: new Date().toISOString(),
  };
  writeStore(store);
}

export function clearCredentials(host: string): void {
  const store = readStore();
  delete store[host];
  writeStore(store);
}

export function isTokenExpired(creds: StoredCredentials): boolean {
  const storedAt = new Date(creds.storedAt).getTime();
  const expiresAt = storedAt + creds.tokens.expiresIn * 1000;
  return Date.now() >= expiresAt;
}
