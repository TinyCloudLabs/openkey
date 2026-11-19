import type { PageServerLoad } from './$types';

export const load: PageServerLoad = ({ setHeaders }) => {
  setHeaders({
    'referrer-policy': 'no-referrer',
    'content-security-policy': "frame-ancestors 'none'; script-src 'self' 'unsafe-inline'; frame-src 'none'; img-src 'self' data:",
  });
};
