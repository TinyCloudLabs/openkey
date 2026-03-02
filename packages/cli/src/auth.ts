import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import {
  generateCodeVerifier,
  generateCodeChallenge,
  generateState,
  buildAuthorizationUrl,
  exchangeAuthorizationCode,
  OpenKeyError,
} from '@openkey/core';
import type { AuthTokens } from '@openkey/core';
import open from 'open';

export interface LoginOptions {
  host: string;
  clientId: string;
  noBrowser?: boolean;
  scopes?: string[];
}

const SUCCESS_HTML = `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>OpenKey CLI</title></head>
<body style="font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#fafafa">
  <div style="text-align:center;max-width:400px">
    <h1 style="font-size:24px;margin-bottom:8px">Authenticated</h1>
    <p style="color:#6b7280">You can close this tab and return to the terminal.</p>
  </div>
</body>
</html>`;

const ERROR_HTML = (message: string) => `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>OpenKey CLI - Error</title></head>
<body style="font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#fafafa">
  <div style="text-align:center;max-width:400px">
    <h1 style="font-size:24px;color:#dc2626;margin-bottom:8px">Authentication Failed</h1>
    <p style="color:#6b7280">${message}</p>
  </div>
</body>
</html>`;

interface CallbackServer {
  port: number;
  waitForCallback: () => Promise<string>;
  close: () => void;
}

function startCallbackServer(expectedState: string): Promise<CallbackServer> {
  return new Promise((resolveServer, rejectServer) => {
    let resolveCallback: ((code: string) => void) | null = null;
    let rejectCallback: ((error: OpenKeyError) => void) | null = null;

    const callbackPromise = new Promise<string>((res, rej) => {
      resolveCallback = res;
      rejectCallback = rej;
    });

    const server = createServer((req: IncomingMessage, res: ServerResponse) => {
      const url = new URL(req.url!, `http://localhost`);

      if (url.pathname !== '/callback') {
        res.writeHead(404);
        res.end('Not found');
        return;
      }

      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');
      const error = url.searchParams.get('error');

      if (error) {
        const description = url.searchParams.get('error_description') || error;
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(ERROR_HTML(description));
        rejectCallback!(new OpenKeyError('UNAUTHORIZED', description));
        return;
      }

      if (!code || !state) {
        res.writeHead(400, { 'Content-Type': 'text/html' });
        res.end(ERROR_HTML('Missing code or state parameter'));
        rejectCallback!(new OpenKeyError('UNKNOWN', 'Missing code or state parameter'));
        return;
      }

      if (state !== expectedState) {
        res.writeHead(400, { 'Content-Type': 'text/html' });
        res.end(ERROR_HTML('State mismatch - possible CSRF attack'));
        rejectCallback!(new OpenKeyError('STATE_MISMATCH', 'State mismatch'));
        return;
      }

      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(SUCCESS_HTML);
      resolveCallback!(code);
    });

    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      if (!addr || typeof addr === 'string') {
        rejectServer(new Error('Failed to start callback server'));
        return;
      }

      resolveServer({
        port: addr.port,
        waitForCallback: () => callbackPromise,
        close: () => server.close(),
      });
    });

    server.on('error', (err) => {
      rejectServer(err);
    });
  });
}

export async function login(options: LoginOptions): Promise<AuthTokens> {
  const { host, clientId, noBrowser = false } = options;
  const scopes = options.scopes ?? ['openid', 'email', 'keys', 'offline_access'];

  const verifier = generateCodeVerifier();
  const challenge = await generateCodeChallenge(verifier);
  const state = generateState();

  const { port, waitForCallback, close } = await startCallbackServer(state);
  const redirectUri = `http://127.0.0.1:${port}/callback`;

  const authUrl = buildAuthorizationUrl({
    host,
    clientId,
    redirectUri,
    codeChallenge: challenge,
    state,
    scopes,
  });

  if (noBrowser) {
    console.log('\nOpen this URL in your browser to sign in:\n');
    console.log(`  ${authUrl}\n`);
    console.log('Waiting for authentication...\n');
  } else {
    console.log('Opening browser for authentication...');
    await open(authUrl);
  }

  try {
    const code = await waitForCallback();

    const tokens = await exchangeAuthorizationCode({
      host,
      code,
      redirectUri,
      clientId,
      codeVerifier: verifier,
    });

    return tokens;
  } finally {
    close();
  }
}
