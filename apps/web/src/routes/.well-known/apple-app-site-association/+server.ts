import type { RequestHandler } from './$types';

/**
 * Apple App Site Association for openkey.so (TC-1188, TC-520).
 *
 * `webcredentials` lets an iOS app that declares
 * `com.apple.developer.associated-domains = webcredentials:openkey.so` use
 * passkeys whose relying party is openkey.so, and match an HTTPS
 * ASWebAuthenticationSession callback on this host. The entry is
 * `<Team ID>.<bundle ID>` for TinyCloud Home under the TinyCloud, Inc. team.
 * It grants nothing until the app ships that entitlement.
 *
 * Apple's CDN fetches this path over HTTPS without following redirects and
 * requires a JSON body, so it is a worker route with an explicit content type
 * rather than a static asset (an extensionless asset would not be served as
 * application/json).
 */
const association = {
  webcredentials: {
    apps: ['R4QVKA785H.xyz.tinycloud.home'],
  },
};

export const GET: RequestHandler = () =>
  new Response(JSON.stringify(association), {
    headers: {
      'content-type': 'application/json',
      'cache-control': 'public, max-age=3600',
    },
  });
