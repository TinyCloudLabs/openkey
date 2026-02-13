// API client for key management
import { getSessionToken } from '$lib/embed-passkey';

const API_URL = import.meta.env.VITE_API_URL;

async function fetchAPI<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string>),
  };

  // In embed context, use bearer token instead of cookies
  const sessionToken = getSessionToken();
  if (sessionToken) {
    headers['Authorization'] = `Bearer ${sessionToken}`;
  }

  const res = await fetch(`${API_URL}${path}`, {
    ...options,
    credentials: sessionToken ? 'omit' : 'include',
    headers,
  });

  if (!res.ok) {
    const error = await res.json().catch(() => ({ error: 'Unknown error' }));
    throw new Error(error.error || `HTTP ${res.status}`);
  }

  return res.json();
}

export interface EthereumKey {
  id: string;
  address: string;
  publicKey: string;
  keyIndex: number;
  label: string | null;
  keyType: 'MANAGED' | 'EXTERNAL';
  createdAt: string;
}

export const api = {
  // Key management
  async listKeys(): Promise<{ keys: EthereumKey[] }> {
    return fetchAPI('/api/keys');
  },

  async generateKey(label?: string): Promise<{ key: EthereumKey }> {
    return fetchAPI('/api/keys/generate', {
      method: 'POST',
      body: JSON.stringify({ label }),
    });
  },

  async getKey(keyId: string): Promise<{ key: EthereumKey }> {
    return fetchAPI(`/api/keys/${keyId}`);
  },

  async updateKey(keyId: string, label: string): Promise<{ success: boolean }> {
    return fetchAPI(`/api/keys/${keyId}`, {
      method: 'PATCH',
      body: JSON.stringify({ label }),
    });
  },

  async signMessage(keyId: string, message: string): Promise<{ signature: string; address: string }> {
    return fetchAPI(`/api/keys/${keyId}/sign`, {
      method: 'POST',
      body: JSON.stringify({ message }),
    });
  },

  async signTypedData(
    keyId: string,
    data: { domain: any; types: any; primaryType: string; message: any }
  ): Promise<{ signature: string; address: string }> {
    return fetchAPI(`/api/keys/${keyId}/sign-typed-data`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async getQuote(keyId: string): Promise<{ quote: string; address: string; inTee: boolean }> {
    return fetchAPI(`/api/keys/${keyId}/quote`);
  },

  async getLinkChallenge(): Promise<{ message: string; nonce: string }> {
    return fetchAPI('/api/keys/link/challenge', {
      method: 'POST',
    });
  },

  async linkWallet(data: { address: string; signature: string; message: string; label?: string }): Promise<{ key: EthereumKey }> {
    return fetchAPI('/api/keys/link', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },
};
