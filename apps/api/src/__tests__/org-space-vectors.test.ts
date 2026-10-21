import { describe, expect, test } from 'bun:test';
import { classifyOrgSpaceMessage, type OrgRole } from '../services/org-space-signing';
import vectorsFile from '../services/fixtures/org-space-v1/vectors.json';

// Golden vectors shared with scripts/org-space-recompute.mjs. The Node script re-derives
// each expected outcome without this parser, so a shared bug in the TS path fails both.
type Vector = {
  name: string;
  message: string;
  ctx: {
    allowedOrigins: string[];
    requestingOrigin: string;
    address: string;
    grantId: string;
    role: OrgRole;
    now: string;
  };
  expected: { ok: true; kind: string; role: OrgRole } | { ok: false; code: string };
};

const vectors = vectorsFile.cases as Vector[];

describe('org-space golden vectors', () => {
  for (const v of vectors) {
    test(v.name, () => {
      const result = classifyOrgSpaceMessage(v.message, {
        allowedOrigins: v.ctx.allowedOrigins,
        requestingOrigin: v.ctx.requestingOrigin,
        address: v.ctx.address,
        grantId: v.ctx.grantId,
        role: v.ctx.role,
        now: new Date(v.ctx.now),
      });
      if (v.expected.ok) {
        expect(result).toMatchObject({ ok: true, kind: v.expected.kind, role: v.expected.role });
      } else {
        expect(result).toEqual({ ok: false, refusal: v.expected.code });
      }
    });
  }
});
