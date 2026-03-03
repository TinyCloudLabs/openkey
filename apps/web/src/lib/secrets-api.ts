// API client for secrets and variables management
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

  async listSecrets(): Promise<{ secrets: Secret[] }> {
    return fetchAPI('/api/secrets');
  },

  async createSecret(name: string, value: string): Promise<{ name: string; createdAt: string }> {
    return fetchAPI('/api/secrets', {
      method: 'POST',
      body: JSON.stringify({ name, value }),
    });
  },

  async updateSecret(name: string, value: string): Promise<{ name: string; updatedAt: string }> {
    return fetchAPI(`/api/secrets/${encodeURIComponent(name)}`, {
      method: 'PUT',
      body: JSON.stringify({ value }),
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
