import { expect, test } from 'bun:test';
import { parseCapabilityReview } from '../../../../packages/capability-review/src/index';
import { courierContext } from '../../../../packages/capability-review/test/fixtures/courier';
import { evaluateBootstrapSigningScope } from '../routes/delegate-autosign';

// Capability presentation and signing policy evaluate the same signed grants. Details: TC-2905
 test('recognizing Courier keeps the producer request outside bootstrap Auto-Sign', () => {
  const context = courierContext();
  const model = parseCapabilityReview(context);
  expect(model.permissions.every(grant => grant.family === 'courier')).toBe(true);
  const entries = model.permissions.map(grant => ({ service: grant.service, space: grant.space, path: grant.path, actions: grant.actions.map(action => action.ability) }));
  expect(evaluateBootstrapSigningScope({ address: context.signer.address, chainId: 1, entries })).toMatchObject({ allowed: false });
});

test('owner approval and order writes retain their Auto-Sign policy result beside Courier grants', () => {
  const context = courierContext();
  const model = parseCapabilityReview(context);
  const courierEntries = model.permissions.map(grant => ({ service: grant.service, space: grant.space, path: grant.path, actions: grant.actions.map(action => action.ability) }));
  for (const path of ['xyz.tinycloud.courier/me/approvals/', 'xyz.tinycloud.courier/me/orders/']) {
    const entries = [...courierEntries, { service: 'tinycloud.kv', space: courierEntries[0]!.space, path, actions: ['tinycloud.kv/put'] }];
    expect(evaluateBootstrapSigningScope({ address: context.signer.address, chainId: 1, entries }, [{
      kind: 'session', service: 'tinycloud.session', space: 'agents', actions: ['siwe'],
      resources: entries.map(entry => ({ ...entry, space: 'agents' as const })),
    }])).toMatchObject({ allowed: false, code: 'owner_only_path' });
  }
});
