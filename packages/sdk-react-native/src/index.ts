export type { OpenKeyRNConfig, AuthTokens, OpenKeyErrorCode } from './types';
export { OpenKeyError } from './types';

export type { SHA256Fn } from './pkce';
export { base64UrlEncode, generateCodeVerifier, generateCodeChallenge, generateState } from './pkce';

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
