export interface ApplicationReadPermission {
  service: string;
  space: string;
  path: string;
  actions: string[];
}

export interface ReadableApplication {
  appId: string;
  name?: string;
  description?: string;
  manifests: unknown[];
  manifestHash: string;
  selectionDigest: string;
  permissions: ApplicationReadPermission[];
}

export interface AppReadDiscovery {
  schemaVersion: 1;
  discoveryToken: string;
  ownerDid: string;
  host: string;
  clientKeyDigest: string;
  expiresAt: string;
  applications: ReadableApplication[];
  issues: unknown[];
  complete: boolean;
}

interface DiscoveryRequest {
  keyId: string;
  keyType: string;
  jwk: object;
  host: string;
  reason?: string;
}

const messages: Record<string, string> = {
  app_read_managed_key_required: 'Choose an OpenKey-managed key to find applications before approval. External wallets cannot complete this lookup in one approval.',
  app_read_registry_unavailable: 'Your application registry could not be read. No access has been approved. Try again after registry access is restored.',
  app_read_discovery_invalid: 'The application lookup returned an invalid or expired read-access request. No access has been approved. Choose your key again to retry.',
  app_read_discovery_failed: 'Your applications could not be loaded. No access has been approved. Try again.',
  app_read_selection_invalid: 'Choose an application from this sign-in before approving access.',
};

function failure(code: string): never {
  throw Object.assign(new Error(messages[code] ?? messages.app_read_discovery_failed), { code });
}

const nonempty = (value: unknown): value is string => typeof value === 'string' && value.length > 0;

function validateDiscovery(value: unknown, requestedHost: string): AppReadDiscovery {
  const data = value as AppReadDiscovery | null;
  if (!data || data.schemaVersion !== 1 || typeof data.complete !== 'boolean' || !nonempty(data.discoveryToken) ||
      !/^did:pkh:eip155:[1-9][0-9]*:0x[a-fA-F0-9]{40}$/.test(data.ownerDid ?? '') ||
      data.host !== new URL(requestedHost).origin || !nonempty(data.clientKeyDigest) ||
      !Number.isFinite(Date.parse(data.expiresAt)) || Date.parse(data.expiresAt) <= Date.now() ||
      !Array.isArray(data.applications) || !Array.isArray(data.issues)) failure('app_read_discovery_invalid');
  const ownerPrefix = `tinycloud:${data.ownerDid.slice(4)}:`;
  const appIds = new Set<string>();
  for (const app of data.applications) {
    if (!app || !nonempty(app.appId) || appIds.has(app.appId) || !nonempty(app.manifestHash) || !nonempty(app.selectionDigest) ||
        !Array.isArray(app.manifests) || !Array.isArray(app.permissions) || app.permissions.length === 0 ||
        (app.name !== undefined && typeof app.name !== 'string') ||
        (app.description !== undefined && typeof app.description !== 'string')) failure('app_read_discovery_invalid');
    appIds.add(app.appId);
    for (const permission of app.permissions) {
      const allowed = permission?.service === 'tinycloud.kv' ? ['get', 'list', 'metadata']
        : permission?.service === 'tinycloud.sql' || permission?.service === 'tinycloud.capabilities' ? ['read'] : [];
      if (typeof permission?.space !== 'string' || !permission.space.toLowerCase().startsWith(ownerPrefix.toLowerCase()) ||
          permission.space.length === ownerPrefix.length || typeof permission.path !== 'string' ||
          !Array.isArray(permission.actions) || permission.actions.length === 0 ||
          permission.actions.some(action => typeof action !== 'string' || !allowed.includes(action.startsWith(`${permission.service}/`) ? action.slice(permission.service.length + 1) : action))) failure('app_read_discovery_invalid');
    }
  }
  return data;
}

/** Registry discovery precedes consent and never signs a client delegation. */
export async function discoverApplicationReads(
  request: DiscoveryRequest,
  requestFetch: typeof fetch = fetch,
  apiUrl = '',
): Promise<AppReadDiscovery> {
  if (request.keyType !== 'MANAGED') failure('app_read_managed_key_required');
  let response: Response;
  try {
    response = await requestFetch(`${apiUrl}/api/delegate/app-read-discovery`, {
      method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ keyId: request.keyId, jwk: request.jwk, host: request.host, ...(request.reason ? { reason: request.reason } : {}) }),
    });
  } catch { failure('app_read_discovery_failed'); }
  const value = await response.json().catch(() => null);
  if (!response.ok) failure(typeof value?.code === 'string' && Object.hasOwn(messages, value.code) ? value.code : 'app_read_discovery_failed');
  return validateDiscovery(value, request.host);
}

/** The API resolves these bindings to the exact selected union; no broad defaults. */
export function selectApplicationRead(discovery: AppReadDiscovery, appId: string) {
  const app = discovery.applications.find(candidate => candidate.appId === appId);
  if (!app || Date.parse(discovery.expiresAt) <= Date.now()) failure('app_read_selection_invalid');
  return { discoveryToken: discovery.discoveryToken, appId: app.appId, selectionDigest: app.selectionDigest };
}
