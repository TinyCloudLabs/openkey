// Re-export shared types from core (backward compatibility)
export type { AuthTokens, OpenKeyErrorCode, SHA256Fn } from '@openkey/core';
export { OpenKeyError, base64UrlEncode, generateCodeVerifier, generateCodeChallenge, generateState } from '@openkey/core';

// RN-specific config
export type { OpenKeyRNConfig } from './types';

export type { BrowserOpener } from './OpenKeyRN';
export { OpenKeyRN, type OpenKeyRNFullConfig } from './OpenKeyRN';

import { OpenKeyRN } from './OpenKeyRN';
import type { OpenKeyRNFullConfig } from './OpenKeyRN';

// Singleton helper
let defaultInstance: OpenKeyRN | null = null;
export function getOpenKeyRN(config?: OpenKeyRNFullConfig): OpenKeyRN {
  if (!defaultInstance || config) {
    defaultInstance = new OpenKeyRN(config!);
  }
  return defaultInstance;
}

export default OpenKeyRN;
