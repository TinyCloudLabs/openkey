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
    Object.assign(failure, { code: detail?.code, status: res.status });
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

export interface OwnerManagedAccount {
  managedAccountId: string;
  managedBy: string;
  state: 'MANAGED' | 'EJECTING' | 'USER_OWNED';
  custodyEpoch: number;
  custody: 'ORGANIZATION_MANAGED' | 'USER_OWNED';
  tenantAccess: 'NOT_REQUIRED' | 'PENDING' | 'REVOKED';
  tenantParentExpiresAt: string | null;
  address: string;
  ownerDid: string;
  revocationReceipts: Array<{ status: 'PENDING' | 'SUBMITTED' | 'CONFIRMED' | 'FAILED' }>;
}

export interface HostedRegistrationIntent {
  organization: { id: string; name: string; plan: 'FREE' | 'PRO' | 'ENTERPRISE' };
  clientId: string;
  redirectUri: string;
  policyTemplate: string;
  policyVersion: number;
  metadata: Record<string, unknown> | null;
  status: 'PENDING' | 'CONSUMED' | 'EXPIRED' | 'FAILED';
  expiresAt: string;
}

export interface OrganizationSummary {
  id: string;
  name: string;
  role: 'ADMIN' | 'MEMBER';
  plan: 'FREE' | 'PRO' | 'ENTERPRISE';
  billingState: 'FREE' | 'ACTIVE' | 'PAST_DUE' | 'CANCELLED';
  brokerDid: string | null;
  entitlements: null | {
    version: number; maxApps: number; maxOrganizationMembers: number; maxManagedAccounts: number;
    monthlyActiveManagedUsers: number; storageBytesPerManagedAccount: string; requestsPerMinute: number;
    maxTenantDelegationTtlSeconds: number; maxTenantPolicyVersion: number; webhookDelivery: boolean;
    auditRetentionDays: number;
  };
  usage: { apps: number; managedAccounts: number; members: number };
}

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

  async getHostedRegistrationIntent(token: string): Promise<{ intent: HostedRegistrationIntent }> {
    return fetchAPI(`/api/managed-account-registration/${encodeURIComponent(token)}`);
  },

  async completeHostedRegistration(token: string): Promise<{ account: {
    managedAccountId: string; address: string; ownerDid: string; state: string; custodyEpoch: number;
  } }> {
    return fetchAPI(`/api/managed-account-registration/${encodeURIComponent(token)}/complete`, { method: 'POST' });
  },

  async listManagedAccounts(): Promise<{ accounts: OwnerManagedAccount[] }> {
    return fetchAPI('/api/managed-accounts');
  },

  async ejectManagedAccount(id: string, expectedEpoch: number, idempotencyKey: string): Promise<{
    managedAccountId: string; custody: 'USER_OWNED'; custodyEpoch: number;
    custodyResult: 'CUSTODY_TRANSFERRED'; tenantAccess: 'PENDING' | 'REVOKED';
    address: string; ownerDid: string; eventHash: string;
  }> {
    return fetchAPI(`/api/managed-accounts/${encodeURIComponent(id)}/eject`, {
      method: 'POST',
      headers: { 'Idempotency-Key': idempotencyKey },
      body: JSON.stringify({ expectedEpoch }),
    });
  },

  async getManagedAccountRevocation(id: string) {
    return fetchAPI<{
      custody: string; custodyEpoch: number; tenantAccess: 'PENDING' | 'REVOKED';
      nodes: Array<{ status: string; submittedAt: string | null; confirmedAt: string | null; node: { nodeId: string; baseUrl: string } }>;
    }>(`/api/managed-accounts/${encodeURIComponent(id)}/revocation`);
  },

  async listOrganizations(): Promise<{ organizations: OrganizationSummary[] }> {
    return fetchAPI('/api/organizations');
  },

  async createOrganization(name: string, brokerDid: string) {
    return fetchAPI<{ organization: { id: string; name: string; plan: 'FREE' } }>('/api/organizations', {
      method: 'POST', body: JSON.stringify({ name, brokerDid }),
    });
  },
};
