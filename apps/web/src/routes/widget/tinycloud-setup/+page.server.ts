// TC-3657 Bobbie N1 (14:53:16Z) authoritative guard: `frame-ancestors 'none'` on every GET
// of this widget page. Belt-and-braces with the client-side check in `+layout.ts` (which only
// fires if the header was dropped by a proxy). The outside app can never render the setup
// consent inside its own origin.
import type { LayoutServerLoad } from './$types';

export const load: LayoutServerLoad = ({ setHeaders }) => {
  setHeaders({
    'Content-Security-Policy': "frame-ancestors 'none'",
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
  });
  return {};
};
