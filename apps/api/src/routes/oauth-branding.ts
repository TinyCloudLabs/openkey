import { Hono } from 'hono';
import type { PrismaClient } from '@openkey/db';

export function createOauthBrandingRouter(database: PrismaClient): Hono {
  const router = new Hono();
  router.get('/clients/:clientId/branding', async (c) => {
    const client = await database.oauthClient.findFirst({
      where: { clientId: c.req.param('clientId'), disabled: false },
      select: {
        clientId: true,
        name: true,
        icon: true,
        organization: { select: { name: true } },
        themeBackgroundColor: true,
        themeAccentColor: true,
      },
    });
    if (!client) return c.json({ error: 'Client not found' }, 404);
    c.header('Cache-Control', 'public, max-age=300');
    return c.json({
      clientId: client.clientId,
      name: client.name,
      icon: client.icon,
      organization: client.organization?.name ?? null,
      theme: {
        backgroundColor: client.themeBackgroundColor,
        accentColor: client.themeAccentColor,
      },
    });
  });
  return router;
}
