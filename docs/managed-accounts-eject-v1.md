# OpenKey Managed Accounts and Eject v1

**Status:** Draft

**Target:** Demo-capable v1, followed by production hardening

**Last updated:** 2026-07-15

**Visual walkthrough:** [Managed accounts architecture and flows](../apps/web/static/managed-accounts-architecture.html)

## Summary

OpenKey will let an application provision an OpenKey identity, managed Ethereum key, and TinyCloud account for an end user. The application controls the managed experience and receives narrowly scoped access through its organization. The user retains an independent OpenKey credential and may unilaterally eject from the application on OpenKey's site.

Ejection in v1 transfers the unchanged key from organization-managed OpenKey custody to personal OpenKey custody. The Ethereum address, DID, TinyCloud space IDs, and encrypted data remain unchanged. Ejection does not export the private key from OpenKey's TEE and is not self-custody.

The service is multi-tenant. Every OAuth client belongs to an organization, and every organization has one of three plans: Free, Pro, or Enterprise. Plans control quotas, features, and support; they never control a user's right to eject.

The demo cut deliberately defers external anti-rollback enforcement. It records a hash-chained, key-signed custody event from day one, but PostgreSQL remains the canonical custody head until the post-demo hardening track adds a monotonic external witness and old-image denial. The demo must not be represented as cryptographically rollback-proof.

## Product promise

> An app can give every user an embedded OpenKey and TinyCloud account. The app manages it by default. The user can leave the app without changing their address, DID, spaces, or data.

OpenKey must describe the v1 exit as **transfer to personal OpenKey custody**, not self-custody or key export.

## Goals

1. Support multiple isolated organizations, each with multiple apps and managed accounts.
2. Let tenant apps initiate user registration through OpenKey's hosted or embedded UI.
3. Establish a user-controlled OpenKey credential before an account becomes managed.
4. Give the tenant useful, policy-bounded access without giving it arbitrary signing authority.
5. Let the user eject unilaterally from OpenKey's site without tenant approval.
6. Preserve the managed key, address, DID, TinyCloud spaces, vault access, and data across eject.
7. Revoke all tenant TinyCloud access by revoking one ancestor delegation.
8. Provide Free, Pro, and Enterprise organization plans with enforced entitlements.
9. Keep TinyCloud nodes protocol-generic; OpenKey is a custody and capability control plane, not a required data-path dependency.
10. Preserve an upgrade path to rollback-resistant custody and eventual key export or external self-custody.

## Non-goals

- Exporting the private key from the TEE in v1.
- Rotating the account to a different root key or DID.
- Moving a TinyCloud space to a user-selected node in v1.
- General-purpose multi-owner or shareable keys.
- Migrating existing OpenKey keys into managed accounts.
- Returning a `USER_OWNED` account to tenant management in v1.
- Letting a tenant reset the user's OpenKey credential or recovery policy.
- Making billing or plan state part of a cryptographic capability.
- Adding tenant-specific authorization rules to tinycloud-node.

## Terms

| Term | Meaning |
| --- | --- |
| Organization | Durable tenant boundary that owns apps, API credentials, plan state, and tenant policies. |
| App | OAuth client registered to one organization. |
| OpenKey principal | User or organization identity used by the OpenKey authorization layer. |
| Managed account | One relationship among a user principal, an organization, one managed key, and its TinyCloud resources. |
| Owner | The user principal with unilateral authority over credential recovery and eject. The owner exists before `MANAGED`. |
| Custodian | The principal currently permitted to request approved key operations. It is the organization while managed and the user after eject. |
| Tenant custodian | Organization acting through OpenKey's typed capability broker, never through unrestricted signing. |
| Personal custody | The user is the active OpenKey custodian; the key remains sealed in OpenKey's TEE. |
| Tenant-parent delegation | The single direct delegation from the managed account root to the organization's broker DID. All tenant TinyCloud sessions descend from it. |
| Custody epoch | Monotonically increasing version checked by every custody-sensitive operation. |
| Custody event | Hash-chained record of a custody transition, signed by the managed account key when possible. |
| Eject | Unilateral transition from tenant custody to personal OpenKey custody plus revocation of tenant access. |

## Core invariants

1. Every managed account has exactly one user owner.
2. Every managed account has exactly one active custodian.
3. In v1 the custodian may transition only from its original organization to its user owner.
4. A user must have at least one independent passkey before the account enters `MANAGED`.
5. A tenant cannot add, remove, replace, or recover the user's credentials.
6. A tenant cannot approve, delay, cancel, or reverse eject.
7. A key's sealing context is immutable even when custody changes.
8. Every key operation is authorized through one resolver and rechecked immediately before unsealing.
9. Every custody-sensitive request carries the expected custody epoch. Stale epochs fail closed.
10. Tenant access is rooted in exactly one tenant-parent delegation per managed account.
11. Every tenant-issued TinyCloud delegation must descend from that parent and be no broader or longer-lived than its policy permits.
12. Billing state may stop new billable writes or provisioning, but may not block authentication, reads, export of user data, or eject.
13. Eject never changes the Ethereum address, root DID, or TinyCloud space IDs.
14. Organization IDs are derived from authenticated server credentials, never accepted from a request body as authority.

## Identity and account boundaries

OpenKey's `User` is a global identity and credential record. A person may authenticate to several tenant apps with the same OpenKey principal, but each tenant relationship creates a separate managed account and managed key.

This separation is required because v1 allows only one active custodian per key. Two organizations must never become co-custodians of one key merely because a person used the same email or passkey in both apps.

An organization sees an opaque subject identifier for its managed account. It does not receive the user's passkey public keys, recovery configuration, other organizations, other keys, or global OpenKey user ID.

Email matching alone must not link an existing OpenKey user to a new organization. The user must authenticate and approve the link inside OpenKey. This avoids account-existence leaks and tenant-driven account linking.

## Organization and plan model

### Organization ownership

The current `DeveloperAccount` and `OauthClient.userId` shape makes an individual developer the tenant boundary. V1 replaces that boundary with an organization:

- Organizations own OAuth clients and server credentials.
- Organization members are rotating administrators with roles; they are not the organization principal.
- Removing an administrator does not change managed accounts or tenant delegations.
- API keys and OAuth clients are scoped to exactly one organization.
- `externalUserId` is unique only within an organization and is treated as opaque tenant data.

### Plans

The public v1 plans are `FREE`, `PRO`, and `ENTERPRISE`. The existing `SCALE` enum value is not part of the public v1 model. Before changing the database enum, a migration must audit and explicitly map any existing `SCALE` rows; the migration must not guess silently.

Exact prices and numerical limits are commercial configuration, not protocol constants. Entitlements are versioned server-side so they can change without reminting delegations.

| Entitlement | Free | Pro | Enterprise |
| --- | --- | --- | --- |
| Managed accounts, embedded registration, and eject | Included with low limits | Included with higher limits | Included with contracted limits |
| Apps and organization members | Limited | Expanded | Contracted |
| Monthly active managed users | Limited | Expanded | Contracted |
| TinyCloud storage and request quotas | Base allocation | Higher allocation | Contracted or dedicated allocation |
| Tenant policy | Fixed safe templates | Configurable within OpenKey's ceiling | Versioned custom policy within OpenKey's ceiling |
| Webhooks | Basic lifecycle events | Full lifecycle events and retries | Full events, custom retention, and delivery controls |
| Audit retention | Short | Extended | Contracted |
| Support and SLA | Community | Standard | Contracted |
| Enterprise controls | Not included | Not included | SSO, SCIM, compliance exports, and optional dedicated infrastructure |

Every plan must include the complete eject path. There is no paid "unlock" for custody transfer.

### Entitlement enforcement

At minimum, `PlanEntitlements` resolves these dimensions for an organization:

- `maxApps`
- `maxOrganizationMembers`
- `maxManagedAccounts`
- `monthlyActiveManagedUsers`
- `storageBytesPerManagedAccount`
- `requestsPerMinute`
- `maxTenantDelegationTtlSeconds`
- `maxTenantPolicyVersion`
- `webhookDelivery`
- `auditRetentionDays`

Capabilities answer **what** a tenant may do. Entitlements answer **how much** service it may consume. Plan checks must not broaden a capability, and a capability must not bypass a plan limit.

New organizations start on Free. Pro becomes active through the billing system. Enterprise is assigned from a contract-controlled entitlement record. For the demo, plans may be assigned by an admin fixture; a complete checkout flow is not required.

On downgrade or failed payment:

1. Do not delete keys or user data.
2. Do not revoke the user's owner role or block eject.
3. Stop new managed-account provisioning above the new limit.
4. Preserve reads and export paths.
5. Reject new billable writes above quota with a structured quota error.
6. Apply a configured grace period before reducing active service where practical.

After eject, future usage is charged to a personal OpenKey account on a personal Free entitlement unless the user selects a personal paid plan later. Existing data remains readable if it exceeds the personal Free limit; new writes may be rejected until usage falls below quota or the user upgrades.

## Registration flow

Tenant apps use OpenKey to register users. The app may embed OpenKey's hosted UI, but the credential ceremony and all credential material remain on an OpenKey origin.

### Registration intent

The tenant backend creates a short-lived, single-use registration intent:

```http
POST /v1/managed-account-registration-intents
Authorization: Bearer <organization server credential>
Idempotency-Key: <tenant-generated value>
Content-Type: application/json

{
  "clientId": "ok_client_...",
  "externalUserId": "tenant-user-123",
  "redirectUri": "https://app.example/callback",
  "policyTemplate": "tinycloud-standard-v1",
  "metadata": { "displayName": "Optional tenant label" }
}
```

The response contains an opaque, expiring `registrationIntent` suitable for the hosted or embedded OpenKey flow. It does not contain a key, user ID, passkey, or reusable bearer credential.

The intent binds:

- organization ID and client ID;
- opaque external user ID;
- exact redirect URI;
- requested policy template and version;
- nonce, creation time, expiry, and one-time-use state;
- idempotency key;
- optional non-authoritative display metadata.

### User ceremony

1. The app opens OpenKey with the registration intent.
2. The user signs in to an existing OpenKey principal or creates one with email/social bootstrap.
3. OpenKey requires an independent passkey before management activates. Email or social login alone is insufficient for eject authority.
4. OpenKey shows which organization will manage the new account and links to the applicable policy.
5. The user approves creation or linking of a new managed account for that organization.
6. OpenKey generates the managed key in the TEE with a new immutable sealing context.
7. OpenKey creates the TinyCloud bootstrap resources and one tenant-parent delegation.
8. The managed account enters `MANAGED` only after the owner credential, custodian binding, policy, and parent delegation are durable.
9. OpenKey redirects to the exact registered redirect URI and sends a signed lifecycle webhook.

The tenant receives `managedAccountId`, its original `externalUserId`, the public address, lifecycle state, and policy version. It does not receive arbitrary root-key signing access.

### Account creation rule

The existing auth hook creates one key automatically whenever a global `User` is created. That behavior cannot represent multiple tenant relationships. V1 must move tenant-managed key creation out of the global user hook and into managed-account provisioning. Personal sign-up behavior may continue to create a separate personal key, but it must not be silently reused as a tenant-managed key.

## Lifecycle

```text
PROVISIONED -> MANAGED -> EJECTING -> USER_OWNED
      |           |
      v           v
   EXPIRED      FAILED (retryable before custody commit)
```

| State | Meaning | Allowed custodian |
| --- | --- | --- |
| `PROVISIONED` | Registration intent exists, but the user credential/key/delegation set is incomplete. | None |
| `MANAGED` | User owner exists; organization is the active custodian through its typed broker. | Organization |
| `EJECTING` | Signing barrier is active and the custody transition is being committed. | No new tenant operation |
| `USER_OWNED` | User is the personal OpenKey custodian. This is terminal in v1. | User |
| `EXPIRED` | Registration intent expired before activation. | None |
| `FAILED` | Provisioning failed before a complete managed account existed. | None; retry or compensate |

`USER_OWNED` describes custody state, not confirmation that every known TinyCloud node has observed the tenant delegation revocation. Revocation convergence has a separate status.

## Custody and key model

### Immutable key record

The existing key row ties both ownership and TEE sealing to `User.id`. A transferable managed key instead needs a stable record whose cryptographic context never changes:

```text
ManagedKey
  id
  address
  publicKey
  sealedBlob
  sealingContext        // immutable, random per key; never derived from custodian ID
  keyType
  keyIndex
  createdAt
  archivedAt
```

For existing keys, a later migration may preserve `openkey/user/{legacyUserId}/keys` as their recorded legacy sealing context. V1 managed accounts are greenfield, so no legacy key becomes tenant-managed.

### Ownership and custody records

```text
ManagedAccount
  id
  ownerUserId
  organizationId
  externalUserId
  keyId
  state
  custodyEpoch
  policyVersion
  tenantParentDelegationCid
  revocationStatus
  createdAt
  updatedAt

KeyCustody
  managedAccountId
  custodianType         // ORGANIZATION | USER
  custodianId
  epoch
  active
  activatedAt
  revokedAt

PossessionEvent
  managedAccountId
  epoch
  previousEventHash
  fromPrincipal
  toPrincipal
  reason
  credentialPolicyHash
  createdAt
  accountKeySignature
  witnessReceipt        // null in demo cut
```

Database constraints enforce one active custody row per managed account and uniqueness of `(organizationId, externalUserId)`.

The owner is a stable OpenKey user principal, not a passkey public key. Passkeys are replaceable credentials governed by the owner's credential policy. Every custody event commits to the current credential-policy hash so credential rotation is auditable without making one device permanent.

### Central authorization boundary

All routes that touch managed key material must call one resolver:

```ts
authorizeKeyOperation({
  actor,
  managedAccountId,
  keyId,
  operation,
  expectedEpoch,
}): AuthorizedKeyOperation
```

The resolver:

1. derives organization and user scope from authenticated credentials;
2. loads the managed account, active custody row, plan entitlements, and policy;
3. verifies actor role, operation, lifecycle state, and expected epoch;
4. returns the immutable sealing context and a short-lived authorization result;
5. rechecks state and epoch immediately before the TEE derives a sealing key or signs.

No route may authorize managed keys with an ad hoc `(keyId, userId)` query. This applies to key signing, delegation, autosign, secrets, TinyCloud bootstrap, OAuth claims, export, archive, and future recovery routes.

### Allowed operations

While `MANAGED`, the organization custodian may call only typed operations approved by the account's versioned policy, such as requesting a bounded TinyCloud child delegation. It may not request:

- arbitrary `personal_sign`;
- arbitrary EIP-712 signatures;
- raw transaction signing;
- new custodians or owners;
- credential or recovery changes;
- key export;
- eject cancellation;
- a delegation outside the OpenKey policy ceiling.

After `USER_OWNED`, organization operations fail with `CUSTODY_EPOCH_STALE` or `TENANT_CUSTODY_REVOKED`. The user may use OpenKey's personal approval and autosign flows.

## Tenant capability topology

OpenKey creates one tenant-parent delegation for each managed account:

```text
Managed account root DID
  -> organization broker DID (tenant-parent delegation)
       -> app/session delegation
       -> app/session delegation
       -> service-agent delegation
```

The parent capability envelope is tenant-requested under a versioned OpenKey ceiling. The effective policy is the intersection of:

1. the immutable OpenKey safety ceiling;
2. plan entitlements;
3. the organization's approved policy version;
4. the managed account's selected policy template;
5. the requested child capability and expiry.

The parent is never a broad root delegation. A broker bug must not be able to manufacture capabilities the parent did not receive.

Every child must cite the tenant-parent delegation as an ancestor. Ejection revokes the parent through TinyCloud's `/revoke` protocol endpoint, and TinyCloud's ancestor validation invalidates its descendants. OpenKey must not model protocol revocation as deletion of a KV record.

Tenant-parent delegation expiry provides a backstop, not the primary eject mechanism. Its maximum lifetime is an entitlement and policy value. Shorter expiry reduces residual risk on unreachable nodes.

## Eject protocol

Eject is available only from an authenticated OpenKey-owned surface. A tenant app may link or redirect to that surface but cannot proxy the confirmation or invoke eject with a tenant credential.

### Preconditions

- The managed account is `MANAGED`.
- The caller is its user owner.
- The user completes fresh passkey authentication.
- The current credential policy satisfies the minimum recovery policy.
- The request includes an idempotency key and expected custody epoch.

### Synchronous custody transfer

1. OpenKey sets a signing barrier for the managed account and transitions it to `EJECTING` with a compare-and-swap on the expected epoch.
2. The broker stops issuing descendants of the tenant-parent delegation.
3. In-flight key operations recheck the epoch immediately before unsealing; stale operations fail.
4. OpenKey snapshots the authoritative set of known TinyCloud hosts/replicas for this managed account.
5. OpenKey constructs the next canonical custody event and asks the TEE to sign it with the unchanged managed key while the barrier and expected epoch are still valid. A signature failure aborts without changing custody.
6. In one database transaction, OpenKey:
   - deactivates the organization custody row;
   - creates the user custody row;
   - increments the custody epoch;
   - revokes tenant OAuth access and refresh tokens for this managed account;
   - disables tenant broker access;
   - appends the signed, hash-chained `PossessionEvent`;
   - marks the account `USER_OWNED` and revocation status `PENDING`.
7. In the demo cut the event signature is stored in PostgreSQL; production hardening also commits the event head to an external monotonic witness before the transition is reported complete.
8. OpenKey returns `CUSTODY_TRANSFERRED` to the user. The address, DID, and space IDs are unchanged.

If a failure occurs before the custody transaction commits, the operation may retry or return to `MANAGED` after proving that no epoch change occurred. After the transaction commits, the system must never restore tenant custody as compensation.

### Asynchronous tenant-access revocation

1. OpenKey submits a signed revocation for the tenant-parent CID to every node in the ejection snapshot.
2. A node counts as acknowledged only after `/revoke` succeeds and a status query confirms the parent is revoked.
3. OpenKey retries unreachable nodes and records per-node receipts.
4. When all snapshotted nodes acknowledge, status becomes `TENANT_ACCESS_REVOKED`.
5. Nodes discovered after the snapshot must receive the revocation before OpenKey treats them as eligible hosts for that space.

An unreachable node does not keep the account in tenant custody. The UI reports:

- **Personal custody active** — OpenKey no longer signs for the tenant.
- **Tenant access revocation pending** — one or more known nodes have not confirmed the revocation.

The security bound for a node that has not observed revocation is the earlier of revocation propagation and tenant-parent expiry.

### Eject response

```json
{
  "managedAccountId": "ma_...",
  "custody": "USER_OWNED",
  "custodyEpoch": 2,
  "custodyResult": "CUSTODY_TRANSFERRED",
  "tenantAccess": "PENDING",
  "address": "0x...",
  "ownerDid": "did:pkh:eip155:1:0x...",
  "eventHash": "..."
}
```

## Node registry and revocation receipts

Eject needs an authoritative node set. OpenKey therefore records each host or replica registered through bootstrap or later replication:

```text
ManagedAccountNode
  managedAccountId
  nodeId
  baseUrl
  role                  // HOST | REPLICA
  firstSeenAt
  lastConfirmedAt
  active

EjectRevocationReceipt
  possessionEventId
  nodeId
  tenantParentDelegationCid
  submittedAt
  confirmedAt
  status
  responseDigest
```

The demo may support one bootstrap host but must use this data shape and completion model so multi-node revocation is not retrofitted later.

## Tenant APIs and SDK

The server SDK exposes:

- create and consume a managed-account registration intent;
- get a managed account by tenant `externalUserId`;
- list managed accounts in the caller's organization;
- request typed, policy-bounded app access;
- read plan usage and entitlement errors;
- manage webhook endpoints;
- observe custody and revocation state.

The tenant API does not expose a raw signing endpoint and does not expose an eject approval endpoint.

Lifecycle webhooks include:

- `managed_account.created`
- `managed_account.provisioning_failed`
- `custody.transfer_started`
- `custody.transferred`
- `tenant_access.revocation_pending`
- `tenant_access.revoked`
- `managed_account.quota_changed`

Webhook payloads contain organization-scoped identifiers and are signed. Delivery is idempotent, ordered per managed account by custody epoch, and safe to replay.

## Tenant isolation requirements

1. All tenant API requests derive `organizationId` from the authenticated client or API key.
2. Every tenant-owned table includes `organizationId` or reaches it through a required foreign key.
3. Unique constraints that accept tenant data include the organization boundary.
4. Tenant list and lookup queries always scope by organization before applying user-supplied filters.
5. OAuth tokens include an immutable organization/client binding and managed-account subject.
6. API keys are shown once, stored hashed, individually revocable, and auditable.
7. Organization admins cannot query another organization by email, address, external ID, or error behavior.
8. Worker jobs and webhooks carry organization scope explicitly and re-resolve it before mutation.
9. Usage metering is recorded by organization and managed account without exposing personal activity across tenants.
10. Cross-tenant isolation has database and API tests, including guessed IDs and conflicting `externalUserId` values.

## Recovery

The user owner controls credential recovery from the start. The tenant may ask OpenKey to send the user back through OpenKey's recovery UI, but it cannot reset credentials, substitute an email, approve a new passkey, or remove a recovery factor.

The minimum v1 policy is:

- at least one passkey before `MANAGED`;
- fresh passkey authentication for eject;
- credential changes require the existing credential policy or a separately defined OpenKey recovery ceremony;
- tenant-supplied email metadata is not by itself sufficient recovery authority.

Passkey loss and account recovery are security-sensitive product flows and must be specified separately before production GA. The demo may use a single registered passkey and explicitly exclude lost-device recovery.

## Anti-rollback and trust boundary

The demo records custody state and signed custody events in PostgreSQL. That provides auditability but not canonical ordering after rollback: a restored database and old approved TEE image could sign from a stale custody epoch and create a competing valid event chain.

Therefore:

- The demo is suitable for demonstrating the product flow, not proving irreversible exclusivity.
- Production GA is blocked on an external monotonic witness or equivalent KMS-enforced state.
- The witness must reject a second successor for an already advanced `(managedAccountId, epoch, headHash)`.
- Key release must be denied to obsolete application measurements that do not consult the witness.
- A second table or service restored with the same database is not an external witness.

Candidate production mechanisms, in order of evaluation:

1. dstack/Phala KMS version policy plus monotonic state, if it can permanently deny old measurements;
2. an independently operated transparency log with witnessed checkpoints;
3. a small on-chain registry of custody epoch and event-head hash.

The key-signed `PossessionEvent` is retained in every option, but its signature is evidence of the transition, not proof that its branch is canonical.

## Demo cut

The demo proves the smallest honest end-to-end story:

1. Create two organizations and show tenant isolation.
2. Assign Free and Pro entitlements with admin fixtures; show at least one enforced plan difference.
3. From a tenant app, create a registration intent and complete OpenKey-hosted passkey registration.
4. Provision a greenfield managed key with an immutable sealing context.
5. Bootstrap TinyCloud and mint one tenant-parent delegation to the organization broker.
6. Let the tenant write and read representative KV, SQL, and vault data through descendant access.
7. From OpenKey's site, reauthenticate and eject.
8. Show the same address, DID, space IDs, and vault data under personal OpenKey custody.
9. Show tenant signing and new child-delegation requests fail at the new custody epoch.
10. Revoke the tenant-parent delegation on the demo node and confirm an existing descendant invocation is rejected.
11. Show `CUSTODY_TRANSFERRED` and `TENANT_ACCESS_REVOKED` as separate observable results.
12. Display an internal/demo disclaimer that rollback-resistant custody is post-demo hardening.

The demo does not require self-serve billing checkout, multi-node replication, key export, legacy migration, or a production anti-rollback witness.

## Implementation sequence

### Phase A: tenancy and registration

- Add organization, membership, organization-client, server credential, plan, and entitlement models.
- Move OAuth client ownership from `User` to `Organization`.
- Add registration intents and organization-scoped opaque subjects.
- Move tenant-managed key creation out of the global user creation hook.
- Add SDK support for registration intents and lifecycle webhooks.

**Verify:** Two organizations may use the same `externalUserId` without collision, cannot read each other's accounts, and each provisions a distinct key for the same OpenKey user principal.

### Phase B: custody model and authorization

- Add immutable per-key sealing context.
- Add managed account, custody, custody epoch, and possession event models.
- Implement `authorizeKeyOperation` and route every managed-key use through it.
- Add a transaction/signing barrier around custody transitions.
- Restrict organization custody to typed operations.

**Verify:** Ad hoc `(keyId, userId)` authorization is absent from managed-key routes, and a stale epoch cannot produce a signature after the barrier.

### Phase C: capability topology and eject

- Mint one policy-bounded tenant-parent delegation.
- Ensure every tenant child cites that parent.
- Add the OpenKey-site eject ceremony.
- Revoke tenant OAuth tokens and broker access at custody commit.
- Submit protocol revocation and persist per-node receipts.

**Verify:** Revoking the parent rejects old and new descendants while the unchanged key still opens all personal data.

### Phase D: plans and demo UX

- Enforce organization entitlements at provisioning and service boundaries.
- Add Free, Pro, and Enterprise admin and usage views.
- Add managed-by and eject surfaces to OpenKey.
- Add signed lifecycle webhooks and demo fixtures.
- Run the complete demo acceptance flow.

**Verify:** Free and Pro differ in an enforced entitlement, and plan changes cannot block eject or delete data.

### Post-demo production hardening

- Add external monotonic witness and old-image key-release denial.
- Run restored-database, stale-process, and competing-event tests until stale custody fails closed.
- Complete recovery design and testing.
- Exercise revocation across multiple hosts and replicas.
- Define portable TinyCloud snapshot/migration for a later full-sovereignty exit.
- Evaluate TEE key export or a stable rotatable account DID as a separate protocol.

## Acceptance criteria

### Registration and tenancy

- A tenant app can register a user only through a valid, single-use OpenKey intent.
- A user passkey exists before `MANAGED`.
- One OpenKey user may have distinct managed accounts for two organizations.
- Organization A cannot observe or mutate Organization B's managed account.
- A tenant cannot enumerate global OpenKey identities by email or address.

### Custody

- Key sealing and unsealing use the immutable key sealing context before and after eject.
- The address, DID, TinyCloud space IDs, and vault access remain identical after eject.
- Tenant key operations fail after the custody transaction commits.
- A tenant request racing eject cannot sign or mint a child after the barrier wins.
- Retrying eject with the same idempotency key returns the committed result.
- `USER_OWNED` cannot transition back to `MANAGED` in v1.

### Revocation

- Every tenant delegation descends from the recorded tenant-parent CID.
- Eject uses TinyCloud's `/revoke` endpoint and confirms status; it does not delete a KV record.
- Invocations using both direct children and deeper descendants fail after the node records the parent revocation.
- Personal custody becomes active even when a node is unreachable, while revocation remains visibly pending.

### Plans and billing

- New organizations default to Free.
- Provisioning and usage limits are organization-scoped and enforced server-side.
- Downgrade and failed payment do not delete data or disable eject.
- Ejected accounts receive personal access independent of the former organization's billing state.
- Exact plan limits are returned as versioned entitlements, not hard-coded in SDK behavior.

### Production hardening gate

- Restoring a pre-eject database does not allow the old organization to obtain a signature.
- An obsolete approved application image cannot release or use the key after custody advances.
- A competing custody event at an already-used epoch is rejected by the external witness.

These three criteria are explicitly deferred for the demo and required before production GA.

## Security and operational telemetry

Audit without logging keys, plaintext secrets, passkey material, OAuth tokens, or signed user payloads. Record:

- organization, app, managed account, actor type, operation type, and custody epoch;
- policy and entitlement versions used for each authorization decision;
- signing-barrier acquisition and stale-epoch denials;
- possession event hash and witness status;
- tenant-parent CID and per-node revocation receipts;
- webhook delivery attempts and acknowledgements;
- plan-limit denials and billing transitions.

Alert on cross-tenant authorization failures, repeated stale-epoch operations, signing attempts during `EJECTING`, revocation retry exhaustion, event-chain forks, and use of obsolete application measurements.

## Follow-up decisions that do not block the demo spec

1. Exact Free and Pro prices and numerical quotas.
2. Which existing `SCALE` accounts map to Pro versus Enterprise.
3. Whether personal paid plans ship with tenant plans or later.
4. The production external witness implementation.
5. Multi-node registry discovery beyond OpenKey-managed bootstrap.
6. Lost-passkey recovery requirements.
7. Full key export and user-selected-node migration.

## Current-code impact summary

| Current area | Required change |
| --- | --- |
| `packages/db/prisma/schema.prisma` | Add organizations, memberships, managed accounts, custody, events, nodes, receipts, and entitlements. Replace user-owned tenant boundary. |
| `User -> EthereumKey` | Decouple tenant-managed key lifecycle from global user creation. Preserve personal-key behavior separately. |
| TEE derive path | Record immutable per-key sealing context instead of deriving it from the current custodian. |
| `keys.ts`, `delegate.ts`, `secrets.ts`, bootstrap, OAuth claims | Route managed-key access through the central authorization resolver and expected custody epoch. |
| OAuth clients and tokens | Bind to organization and managed-account subject; revoke tenant grants at eject. |
| TinyCloud bootstrap | Mint and record one tenant-parent delegation and register known nodes. |
| OpenKey web | Add managed-by disclosure, custody status, passkey reauthentication, eject, and revocation progress. |
| OpenKey SDK | Add registration-intent, managed-account status, typed access, entitlement, and webhook contracts. |
| tinycloud-node | No tenant-specific authorization changes; rely on protocol revocation, ancestor checks, and status receipts. |
