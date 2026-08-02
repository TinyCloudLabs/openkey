// @ts-expect-error bun:test is a runtime-only module; tsc doesn't ship types
import { describe, expect, test } from 'bun:test';
import { actionId } from '@openkey/capability-review';
import { validatePreviewSelection } from './preview-review';

const permission = {
  service: 'tinycloud.encryption',
  space: 'urn:tinycloud:encryption:example:default',
  path: '',
  actions: ['tinycloud.encryption/network.create'],
};
const createId = actionId(
  permission.service,
  permission.space,
  permission.path,
  permission.actions[0]!,
);

describe('server preview review projection', () => {
  test('accepts exact selectedActionKeys and permission agreement', () => {
    expect(
      validatePreviewSelection(
        { selectedActionKeys: [createId], permissions: [permission] },
        [createId],
      ),
    ).toEqual(new Set([createId]));
  });

  test('rejects a server selection that differs from the reviewed selection', () => {
    expect(() =>
      validatePreviewSelection(
        { selectedActionKeys: [], permissions: [] },
        [createId],
      ),
    ).toThrow(/differ from the reviewed selection/);
  });

  test('rejects grouped permissions that disagree with the returned keys', () => {
    expect(() =>
      validatePreviewSelection(
        { selectedActionKeys: [createId], permissions: [] },
        [createId],
      ),
    ).toThrow(/permissions disagree/);
  });
});
