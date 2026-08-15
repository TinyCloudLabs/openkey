import { expect, test } from 'bun:test';
import { acceptanceVerdict } from './device-authorization-acceptance-verdict';

test('health, lookup, and mocked auto-approval can never produce an acceptance pass', () => {
  expect(acceptanceVerdict({
    publicCliProcess: true, apiTransactionStart: true, renderedDescriptor: true,
    authenticatedApproval: true, descriptorBoundConsumption: true, shareAuthorityVerified: true,
    oneShotUpload: true, finalShareUrl: true, mockedApproval: true,
  })).toEqual(expect.objectContaining({ passed: false }));
  expect(acceptanceVerdict({ healthOnly: true })).toEqual(expect.objectContaining({ passed: false }));
});
