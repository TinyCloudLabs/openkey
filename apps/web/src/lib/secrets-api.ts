// API client for secrets and variables management
// Secrets are encrypted client-side with the user's RSA public key before sending
import { getSessionToken } from '$lib/embed-passkey';

const API_URL = import.meta.env.VITE_API_URL || '';

async function fetchAPI<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string>),
  };

  const sessionToken = getSessionToken();
  if (sessionToken) {
    headers['Authorization'] = `Bearer ${sessionToken}`;
  }

  const res = await fetch(`${API_URL}${path}`, {
    ...options,
    credentials: sessionToken ? 'omit' : 'include',
    headers,
  });

  if (res.status === 204) {
    return undefined as T;
  }

  if (!res.ok) {
    const error = await res.json().catch(() => ({ error: 'Unknown error' }));
    throw new Error(error.error || `HTTP ${res.status}`);
  }

  return res.json();
}

// =========================================================================
// Client-side encryption utilities (Web Crypto API)
// =========================================================================

let cachedPublicKey: CryptoKey | null = null;
let cachedPublicKeyPem: string | null = null;

async function getPublicKey(): Promise<CryptoKey> {
  if (cachedPublicKey) return cachedPublicKey;

  const { publicKey: pem } = await fetchAPI<{ publicKey: string }>('/api/secrets/public-key');
  cachedPublicKeyPem = pem;

  // Parse PEM to ArrayBuffer
  const pemBody = pem
    .replace(/-----BEGIN PUBLIC KEY-----/, '')
    .replace(/-----END PUBLIC KEY-----/, '')
    .replace(/\s/g, '');
  const binaryDer = Uint8Array.from(atob(pemBody), (c) => c.charCodeAt(0));

  cachedPublicKey = await crypto.subtle.importKey(
    'spki',
    binaryDer.buffer,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['encrypt'],
  );

  return cachedPublicKey;
}

// RSA-OAEP with SHA-256 and 2048-bit key can encrypt up to 190 bytes
const RSA_MAX_PLAINTEXT = 190;

async function encryptValue(value: string): Promise<{ encryptedValue: string; encryptedKey?: string; iv?: string }> {
  const pubKey = await getPublicKey();
  const encoded = new TextEncoder().encode(value);

  if (encoded.byteLength <= RSA_MAX_PLAINTEXT) {
    // Direct RSA encryption for small values
    const ciphertext = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pubKey, encoded);
    return {
      encryptedValue: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
    };
  }

  // Hybrid encryption for larger values
  // 1. Generate random AES-256-GCM key
  const aesKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // 2. Encrypt value with AES-GCM
  const aesCiphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', length: 256 }, aesKey, encoded);

  // 3. Export and RSA-encrypt the AES key
  const rawAesKey = await crypto.subtle.exportKey('raw', aesKey);
  const encryptedAesKey = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pubKey, rawAesKey);

  return {
    encryptedKey: btoa(String.fromCharCode(...new Uint8Array(encryptedAesKey))),
    encryptedValue: btoa(String.fromCharCode(...new Uint8Array(aesCiphertext))),
    iv: btoa(String.fromCharCode(...iv)),
  };
}

// =========================================================================
// Public API
// =========================================================================

export interface Secret {
  name: string;
  createdAt: string;
  updatedAt?: string;
}

export interface Variable {
  name: string;
  value: string;
  createdAt: string;
  updatedAt?: string;
}

export const secretsApi = {
  async getStatus(): Promise<{ enabled: boolean; secretCount?: number; variableCount?: number }> {
    return fetchAPI('/api/secrets/status');
  },

  async enable(): Promise<{ enabled: boolean; spaceId: string }> {
    return fetchAPI('/api/secrets/enable', { method: 'POST' });
  },

  async getPublicKey(): Promise<{ publicKey: string }> {
    return fetchAPI('/api/secrets/public-key');
  },

  async listSecrets(): Promise<{ secrets: Secret[] }> {
    return fetchAPI('/api/secrets');
  },

  async createSecret(name: string, value: string): Promise<{ name: string; createdAt: string }> {
    const encrypted = await encryptValue(value);
    return fetchAPI('/api/secrets', {
      method: 'POST',
      body: JSON.stringify({ name, ...encrypted }),
    });
  },

  async updateSecret(name: string, value: string): Promise<{ name: string; updatedAt: string }> {
    const encrypted = await encryptValue(value);
    return fetchAPI(`/api/secrets/${encodeURIComponent(name)}`, {
      method: 'PUT',
      body: JSON.stringify(encrypted),
    });
  },

  async deleteSecret(name: string): Promise<void> {
    return fetchAPI(`/api/secrets/${encodeURIComponent(name)}`, {
      method: 'DELETE',
    });
  },

  async listVariables(): Promise<{ variables: Variable[] }> {
    return fetchAPI('/api/variables');
  },

  async createVariable(name: string, value: string): Promise<{ name: string; value: string; createdAt: string }> {
    return fetchAPI('/api/variables', {
      method: 'POST',
      body: JSON.stringify({ name, value }),
    });
  },

  async updateVariable(name: string, value: string): Promise<{ name: string; value: string; updatedAt: string }> {
    return fetchAPI(`/api/variables/${encodeURIComponent(name)}`, {
      method: 'PUT',
      body: JSON.stringify({ value }),
    });
  },

  async deleteVariable(name: string): Promise<void> {
    return fetchAPI(`/api/variables/${encodeURIComponent(name)}`, {
      method: 'DELETE',
    });
  },
};
