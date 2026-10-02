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
  protocolVersion: 1;
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
  discoveryProtocolVersion: number;
  keyId: string;
  keyType: string;
  jwk: object;
  host: string;
  reason?: string;
}

const messages: Record<string, string> = {
  app_read_protocol_incompatible: 'This application-read protocol is incompatible. No access has been approved. Update the TinyCloud CLI and OpenKey release together before retrying.',
  app_read_discovery_expired: 'Application selection expired or the API restarted. No access has been approved. Choose your key and application again to review a fresh request.',
  app_read_scope_unsupported: 'This registration does not declare supported app-scoped KV or SQL reads. Update its registration before retrying.',
  app_read_untrusted_host: 'This node host is not supported for one-approval application discovery.',
  app_read_deployment_incompatible: 'This OpenKey API does not support this application-read protocol. No access has been approved. Update the OpenKey web and API deployments together before retrying.',
  app_read_managed_key_required: 'Choose an OpenKey-managed key to find applications before approval. External wallets cannot complete this lookup in one approval.',
  app_read_registry_unavailable: 'Your application registry could not be read. No access has been approved. Try again after registry access is restored.',
  app_read_discovery_invalid: 'The application lookup returned an invalid or expired read-access request. No access has been approved. Choose your key again to retry.',
  app_read_discovery_failed: 'Your applications could not be loaded. No access has been approved. Try again.',
  app_read_selection_invalid: 'Choose an application from this sign-in before approving access.',
};

export const APP_READ_PROTOCOL_VERSION = 1;

/** Check the same running API that will discover and sign; never a static web marker. */
export async function getApplicationReadCapabilities(requestFetch: typeof fetch = fetch, apiUrl = '') {
  let response: Response;
  try {
    response = await requestFetch(`${apiUrl}/api/delegate/app-read-capabilities`, { cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(10000) });
  } catch { failure('app_read_deployment_incompatible'); }
  const value = await response.json().catch(() => null);
  if (!response.ok || value?.schemaVersion !== 1 || value?.protocolVersion !== APP_READ_PROTOCOL_VERSION ||
      value?.implementationVersion !== '1' || value?.discovery !== 'app-read' || value?.scope !== 'registry-and-selected-app' || value?.transport !== 'paste') failure('app_read_deployment_incompatible');
  return { schemaVersion: 1, protocolVersion: APP_READ_PROTOCOL_VERSION, implementationVersion: '1', discovery: 'app-read', scope: 'registry-and-selected-app', transport: 'paste' } as const;
}

/** Uncached well-known relay for CLI preflight through the deployed web origin. */
export async function applicationReadCapabilitiesResponse(requestFetch: typeof fetch = fetch, apiUrl = '') {
  const headers = { 'Cache-Control': 'no-store' };
  try {
    const capabilities = await getApplicationReadCapabilities(requestFetch, apiUrl);
    return Response.json({ ...capabilities, apiBacked: true }, { headers });
  } catch {
    return Response.json({ code: 'app_read_deployment_incompatible' }, { status: 503, headers });
  }
}

function failure(code: string): never {
  throw Object.assign(new Error(messages[code] ?? messages.app_read_discovery_failed), { code });
}

const nonempty = (value: unknown): value is string => typeof value === 'string' && value.length > 0;

function validateDiscovery(value: unknown, requestedHost: string): AppReadDiscovery {
  const data = value as AppReadDiscovery | null;
  if (!data || data.schemaVersion !== 1 || data.protocolVersion !== APP_READ_PROTOCOL_VERSION || typeof data.complete !== 'boolean' || !nonempty(data.discoveryToken) ||
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
  if (request.discoveryProtocolVersion !== APP_READ_PROTOCOL_VERSION) failure('app_read_protocol_incompatible');
  if (request.keyType !== 'MANAGED') failure('app_read_managed_key_required');
  await getApplicationReadCapabilities(requestFetch, apiUrl);
  let response: Response;
  try {
    response = await requestFetch(`${apiUrl}/api/delegate/app-read-discovery`, {
      method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ discoveryProtocolVersion: APP_READ_PROTOCOL_VERSION, keyId: request.keyId, jwk: request.jwk, host: request.host, ...(request.reason ? { reason: request.reason } : {}) }),
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
  return { discoveryProtocolVersion: APP_READ_PROTOCOL_VERSION, discoveryToken: discovery.discoveryToken, appId: app.appId, selectionDigest: app.selectionDigest };
}
