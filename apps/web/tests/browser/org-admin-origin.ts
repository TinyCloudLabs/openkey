import { E2E_PORT } from './e2e-port';

export const ORG_ADMIN_PORT = E2E_PORT === 65535 ? E2E_PORT - 1 : E2E_PORT + 1;
export const ORG_ADMIN_ORIGIN = `http://localhost:${ORG_ADMIN_PORT}`;
