import { env } from '$env/dynamic/private';
import { error } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = ({ setHeaders }) => {
  if (env.ORG_KEY_CUSTODY_ENABLED !== 'true') error(404);
  setHeaders({
    'referrer-policy': 'no-referrer',
    'content-security-policy': "frame-ancestors 'none'; script-src 'self' 'unsafe-inline'; frame-src 'none'; img-src 'self' data:",
  });
};
