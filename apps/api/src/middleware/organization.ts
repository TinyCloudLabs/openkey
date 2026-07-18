import { createMiddleware } from 'hono/factory';
import { createPrismaClient } from '@openkey/db';
import {
  authenticateOrganizationCredential,
  bearerToken,
  OrganizationCredentialError,
  type AuthenticatedOrganization,
} from '../services/organization-credentials';

const prisma = createPrismaClient();

export type OrganizationContext = {
  Variables: {
    organizationActor: AuthenticatedOrganization;
  };
};

export const requireOrganizationCredential = createMiddleware<OrganizationContext>(async (c, next) => {
  try {
    const actor = await authenticateOrganizationCredential(
      prisma,
      bearerToken(c.req.header('Authorization')),
    );
    c.set('organizationActor', actor);
    await next();
  } catch (error) {
    if (error instanceof OrganizationCredentialError) {
      return c.json({ error: { code: error.code, message: 'Invalid organization credential' } }, 401);
    }
    throw error;
  }
});
