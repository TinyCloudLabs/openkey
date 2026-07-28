import { Hono, type Context } from 'hono';
import { createPrismaClient } from '@openkey/db';
import { requireOrganizationCredential, type OrganizationContext } from '../middleware/organization';
import {
  issueOrganizationCredential,
  OrganizationCredentialError,
} from '../services/organization-credentials';
import { resolveManagementCredential, TenantManagedAccountError } from '../services/tenant-managed-accounts';

const prisma = createPrismaClient();

type CredentialRotationReplayResponse = {
  alreadyRotated: true;
  credentialId: string | null;
  message: string;
};

function error(c: Context, status: 400 | 401 | 403 | 404 | 409 | 410 | 500, code: string, message: string) {
  return c.json({ error: { code, message } }, status);
}

function idempotencyKey(c: Context) {
  const value = c.req.header('Idempotency-Key');
  return value && value.length <= 200 ? value : null;
}

async function loadCredential(db: typeof prisma, organizationId: string, credentialId: string) {
  const credential = await db.organizationServerCredential.findFirst({
    where: {
      id: credentialId,
      organizationId,
    },
    select: {
      id: true,
      organizationId: true,
      name: true,
      subjectUserId: true,
      kind: true,
      revokedAt: true,
    },
  });
  if (!credential) {
    throw new OrganizationCredentialError('INVALID_CREDENTIAL');
  }
  return credential;
}

export const managementCredentialsRouter = new Hono<OrganizationContext>();
managementCredentialsRouter.use('*', requireOrganizationCredential);

managementCredentialsRouter.post('/:id/rotate', async (c) => {
  const key = idempotencyKey(c);
  if (!key) return error(c, 400, 'INVALID_REQUEST', 'Idempotency-Key is required');
  const actor = c.get('organizationActor');
  try {
    const result = await prisma.$transaction(async (tx) => {
      const managementActor = await resolveManagementCredential(tx as typeof prisma, actor.credentialId, actor.organizationId);
      const target = await loadCredential(tx as typeof prisma, actor.organizationId, c.req.param('id'));
      if (target.kind !== 'MANAGEMENT') {
        return null;
      }
      if (target.id === managementActor.credentialId) {
        throw new TenantManagedAccountError(
          'OPERATION_NOT_ALLOWED',
          'A different management credential is required for rotation',
        );
      }
      const requestHash = JSON.stringify({ credentialId: target.id, name: target.name, subjectUserId: target.subjectUserId });

      const replay = await tx.managedAccountOperation.findUnique({
        where: {
          organizationId_action_idempotencyKey: {
            organizationId: actor.organizationId,
            action: 'ROTATE_CREDENTIAL',
            idempotencyKey: key,
          },
        },
      });
      if (replay && replay.requestHash === requestHash) {
        return { replay: replay.response as any } as const;
      }
      if (replay && replay.requestHash !== requestHash) {
        return { conflict: true } as const;
      }

      if (target.revokedAt) {
        return null;
      }

      const subjectUserId = target.subjectUserId ?? managementActor.subjectUserId;
      if (!subjectUserId) {
        return { invalid: true } as const;
      }
      const issued = await issueOrganizationCredential(tx as typeof prisma, {
        organizationId: actor.organizationId,
        subjectUserId,
        name: target.name,
      });
      await tx.organizationServerCredential.updateMany({
        where: { id: target.id },
        data: { revokedAt: new Date() },
      });
      // Store only the new credential ID, never the plaintext secret.
      // The secret is a one-time value returned in the HTTP response only.
      // Persisting it would allow retrieval from DB backups or audit logs.
      await tx.managedAccountOperation.create({
        data: {
          organizationId: actor.organizationId,
          managedAccountId: null,
          credentialId: managementActor.credentialId,
          action: 'ROTATE_CREDENTIAL',
          idempotencyKey: key,
          requestHash,
          response: { credentialId: issued.credential.id, rotated: true },
          expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
        },
      });
      return { issued } as const;
    });
    if (result === null) return error(c, 404, 'NOT_FOUND', 'Credential not found');
    if ('conflict' in result) return error(c, 409, 'IDEMPOTENCY_CONFLICT', 'Idempotency-Key was used for a different request');
    if ('invalid' in result) return error(c, 400, 'INVALID_REQUEST', 'Credential has no associated subject user');
    // The rotation already completed. The secret was returned in the original response
    // and is never persisted; it cannot be retrieved from a replay. Callers that missed
    // the original response must rotate again with a new idempotency key.
    if ('replay' in result) {
      const response: CredentialRotationReplayResponse = {
        alreadyRotated: true,
        credentialId: (result.replay as any).credentialId ?? null,
        message: 'Credential was already rotated. The secret was issued in the original response and cannot be retrieved again.',
      };
      return c.json(response);
    }
    return c.json(result.issued);
  } catch (caught) {
    if (caught instanceof OrganizationCredentialError) {
      return error(c, 401, 'INVALID_CREDENTIAL', 'Invalid organization credential');
    }
    if (caught instanceof TenantManagedAccountError) {
      return error(c, 403, caught.code, caught.message);
    }
    throw caught;
  }
});

managementCredentialsRouter.delete('/:id', async (c) => {
  const actor = c.get('organizationActor');
  try {
    const managementActor = await resolveManagementCredential(prisma, actor.credentialId, actor.organizationId);
    const target = await loadCredential(prisma, actor.organizationId, c.req.param('id'));
    if (target.kind !== 'MANAGEMENT') {
      return error(c, 404, 'NOT_FOUND', 'Credential not found');
    }
    if (target.revokedAt) {
      return c.json({ success: true });
    }
    await prisma.organizationServerCredential.update({
      where: { id: target.id },
      data: { revokedAt: new Date() },
    });
    await prisma.managedAccountOperation.create({
      data: {
        organizationId: actor.organizationId,
        managedAccountId: null,
        credentialId: managementActor.credentialId,
        action: 'REVOKE_CREDENTIAL',
        idempotencyKey: `revoke:${target.id}:${Date.now()}`,
        requestHash: target.id,
        response: { success: true, credentialId: target.id },
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      },
    });
    return c.json({ success: true });
  } catch (caught) {
    if (caught instanceof OrganizationCredentialError) {
      return error(c, 404, 'NOT_FOUND', 'Credential not found');
    }
    if (caught instanceof TenantManagedAccountError) {
      return error(c, 403, caught.code, caught.message);
    }
    throw caught;
  }
});
