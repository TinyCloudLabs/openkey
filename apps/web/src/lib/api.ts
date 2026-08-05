// API client for key management
import { getSessionToken } from '$lib/embed-passkey';

const API_URL = import.meta.env.VITE_API_URL || '';

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
    const detail = error?.error;
    const message = typeof detail === 'string' ? detail : detail?.message;
    const failure = new Error(message || `HTTP ${res.status}`);
    Object.assign(failure, {
      code: detail?.code,
      status: res.status,
      policyEpoch: typeof error?.policyEpoch === 'number' ? error.policyEpoch : undefined,
    });
    throw failure;
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
  archivedAt?: string | null;
  createdAt: string;
}

export interface AutoSignPreference {
  autoSignEnabled: boolean;
}

export interface TinyCloudManageKeyPreference {
  tinyCloudManageKeyEnabled: boolean;
  mode: 'APP_MANAGED' | 'USER_CONTROLLED_SHARED' | 'USER_CONTROLLED_EXCLUSIVE';
  policyEpoch: number;
}

export interface TinyCloudManageKeyApp {
  clientId: string;
  name: string;
  uri: string | null;
  icon: string | null;
  disabled: boolean;
  enabled: boolean;
  status?: 'ENABLED' | 'DISABLED' | 'PENDING_USER_APPROVAL' | 'CONSENT_WITHDRAWN';
}

export interface TinyCloudManageKeyActivity {
  clientId: string;
  clientName: string;
  allowed: boolean;
  reason: string;
  policyEpoch: number;
  createdAt: string;
}

export interface TinyCloudManageKeyAppsResponse {
  apps: TinyCloudManageKeyApp[];
  activity: TinyCloudManageKeyActivity[];
  mode: TinyCloudManageKeyPreference['mode'];
  policyEpoch: number;
}

export interface OrganizationSummary {
  id: string; name: string; role: "ADMIN" | "MEMBER"; plan: "FREE" | "PRO" | "ENTERPRISE"; billingState: string;
  entitlements: null | { version: number; maxApps: number; maxOrganizationMembers: number; requestsPerMinute: number; auditRetentionDays: number };
  usage: { apps: number; members: number };
}
export interface ConsoleOverview {
  organization: OrganizationSummary & { createdAt: string; updatedAt: string };
  entitlements: OrganizationSummary["entitlements"]; usage: { apps: number; members: number };
}
export interface ConsoleApp { id: string; clientId: string; name: string; uri: string | null; icon: string | null; redirectUris: string[]; scopes: string[]; type: "web" | "spa" | "native"; public: boolean; tokenEndpointAuthMethod: string | null; grantTypes: string[]; responseTypes: string[]; tinycloudSessionPolicy: string | null; tinycloudSessionOrigin: string | null; disabled: boolean; createdAt: string; updatedAt: string; }
export interface ConsoleMember { id: string; userId: string; email: string; name: string | null; role: "ADMIN" | "MEMBER"; validFrom: string; createdAt: string; }

export const api = {
  // Key management
  async listKeys(options?: { includeArchived?: boolean }): Promise<{ keys: EthereumKey[] }> {
    const query = options?.includeArchived ? '?archived=true' : '';
    return fetchAPI(`/api/keys${query}`);
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

  async archiveKey(keyId: string): Promise<{ success: boolean; archivedAt: string }> {
    return fetchAPI(`/api/keys/${keyId}/archive`, {
      method: 'POST',
    });
  },

  async unarchiveKey(keyId: string): Promise<{ success: boolean }> {
    return fetchAPI(`/api/keys/${keyId}/unarchive`, {
      method: 'POST',
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

  async getAutoSignPreference(): Promise<AutoSignPreference> {
    return fetchAPI('/api/account/auto-sign');
  },

  async updateAutoSignPreference(autoSignEnabled: boolean): Promise<AutoSignPreference> {
    return fetchAPI('/api/account/auto-sign', {
      method: 'PATCH',
      body: JSON.stringify({ autoSignEnabled }),
    });
  },

  async getTinyCloudManageKeyPreference(): Promise<TinyCloudManageKeyPreference> {
    return fetchAPI('/api/account/tinycloud-manage-key');
  },

  async updateTinyCloudManageKeyPreference(mode: TinyCloudManageKeyPreference['mode'], policyEpoch: number, confirmation: string): Promise<TinyCloudManageKeyPreference> {
    return fetchAPI('/api/account/tinycloud-manage-key', {
      method: 'PATCH',
      body: JSON.stringify({ mode, expectedEpoch: policyEpoch, confirmation }),
    });
  },

  async listTinyCloudManageKeyApps(): Promise<TinyCloudManageKeyAppsResponse> {
    return fetchAPI('/api/account/tinycloud-apps');
  },

  async updateTinyCloudManageKeyApp(clientId: string, enabled: boolean, policyEpoch: number, confirmation: string): Promise<{
    clientId: string; enabled: boolean; status: string; policyEpoch: number;
  }> {
    return fetchAPI(`/api/account/tinycloud-apps/${encodeURIComponent(clientId)}`, {
      method: 'PATCH',
      body: JSON.stringify({ enabled, expectedEpoch: policyEpoch, confirmation }),
    });
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

  async listOrganizations(): Promise<{ organizations: OrganizationSummary[] }> {
    return fetchAPI('/api/organizations');
  },

  async createOrganization(name: string) {
    return fetchAPI<{ organization: { id: string; name: string; plan: 'FREE' } }>('/api/organizations', {
      method: 'POST', body: JSON.stringify({ name }),
    });
  },

  async listConsoleOrganizations(): Promise<{ organizations: OrganizationSummary[] }> {
    return fetchAPI('/api/organizations');
  },

  async getConsoleOverview(organizationId: string): Promise<ConsoleOverview> {
    return fetchAPI(`/api/console/organizations/${encodeURIComponent(organizationId)}/overview`);
  },

  async listConsoleMembers(organizationId: string): Promise<{ members: ConsoleMember[] }> {
    return fetchAPI(`/api/console/organizations/${encodeURIComponent(organizationId)}/members`);
  },

  async addConsoleAdmin(organizationId: string, address: string): Promise<{ member: ConsoleMember }> {
    return fetchAPI(`/api/console/organizations/${encodeURIComponent(organizationId)}/members`, {
      method: 'POST',
      body: JSON.stringify({ address }),
    });
  },

  async listConsoleApps(organizationId: string): Promise<{ apps: ConsoleApp[] }> {
    return fetchAPI(`/api/console/organizations/${encodeURIComponent(organizationId)}/apps`);
  },

  async createConsoleApp(
    organizationId: string,
    input: {
      name: string;
      redirectUris: string[];
      type?: 'spa' | 'native';
      uri?: string | null;
      icon?: string | null;
    },
  ): Promise<{ client: ConsoleApp }> {
    return fetchAPI(`/api/console/organizations/${encodeURIComponent(organizationId)}/apps`, {
      method: 'POST',
      body: JSON.stringify(input),
    });
  },

  async updateConsoleApp(
    organizationId: string,
    appId: string,
    input: {
      name?: string;
      redirectUris?: string[];
      type?: 'spa' | 'native';
      uri?: string | null;
      icon?: string | null;
      disabled?: boolean;
      tinycloudSessionOrigin?: string | null;
    },
  ): Promise<{ client: ConsoleApp }> {
    return fetchAPI(`/api/console/organizations/${encodeURIComponent(organizationId)}/apps/${encodeURIComponent(appId)}`, {
      method: 'PATCH',
      body: JSON.stringify(input),
    });
  },

};
