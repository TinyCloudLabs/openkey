// The one place that names the browser specs' dev-server port (TC-2124). The default is 5779, which
// CI uses; set OPENKEY_E2E_PORT to run a second copy of the suite beside another one on the same host.
// Every spec and the Playwright config take the port from here: a test, e2e-port.test.ts, fails if a
// literal port appears anywhere else.

export const DEFAULT_E2E_PORT = 5779;

function readPort(value: string | undefined): number {
  if (value === undefined || value === '') return DEFAULT_E2E_PORT;
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) {
    throw new Error(`OPENKEY_E2E_PORT must be an integer from 1024 to 65535, got "${value}"`);
  }
  return port;
}

export const E2E_PORT = readPort(process.env.OPENKEY_E2E_PORT);
/** `localhost:<port>`: the host the pages and the SIWE messages under test name. */
export const HOST = `localhost:${E2E_PORT}`;
/** `http://localhost:<port>`: the app's origin, and the Playwright `baseURL`. */
export const ORIGIN = `http://${HOST}`;
/** `http://127.0.0.1:<port>`: the same server by its loopback address, a different origin. */
export const LOOPBACK_ORIGIN = `http://127.0.0.1:${E2E_PORT}`;
