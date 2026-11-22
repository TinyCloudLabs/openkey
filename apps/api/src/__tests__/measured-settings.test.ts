import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { checkMeasuredSettings } from '../measured-settings';

const prodCompose = readFileSync(resolve(import.meta.dir, '../../../../docker-compose.prod.yml'), 'utf8');

function appCompose(dockerCompose: string): string {
  return JSON.stringify({ manifest_version: 2, name: 'openkey', runner: 'docker-compose', docker_compose_file: dockerCompose });
}

/** What Compose hands the api container for the literal entries of the production compose. */
function literalEnv(dockerCompose: string): Record<string, string> {
  const env: Record<string, string> = {};
  for (const line of dockerCompose.split('\n')) {
    const match = /^ {6}- ([A-Z0-9_]+)=([^$\n]*)$/.exec(line);
    if (match) env[match[1]!] = match[2]!;
  }
  return env;
}

describe('checkMeasuredSettings', () => {
  test('the production compose fixes every measured setting, and a matching process passes', () => {
    expect(checkMeasuredSettings(appCompose(prodCompose), literalEnv(prodCompose))).toEqual({ ok: true });
  });

  test('an env value that differs from the measured literal is refused by name', () => {
    const env = { ...literalEnv(prodCompose), GOOGLE_CLIENT_ID: 'attacker.apps.googleusercontent.com', NODE_STATS_URL: 'https://stats.invalid' };
    expect(checkMeasuredSettings(appCompose(prodCompose), env))
      .toEqual({ ok: false, unreadable: false, settings: ['GOOGLE_CLIENT_ID', 'NODE_STATS_URL'] });
  });

  test('a setting taken from the encrypted env is refused even when the value matches', () => {
    const compose = prodCompose.replace('- WEBAUTHN_RP_ID=openkey.so', '- WEBAUTHN_RP_ID=${WEBAUTHN_RP_ID}');
    expect(checkMeasuredSettings(appCompose(compose), { ...literalEnv(prodCompose), WEBAUTHN_RP_ID: 'openkey.so' }))
      .toEqual({ ok: false, unreadable: false, settings: ['WEBAUTHN_RP_ID'] });
  });

  test('a missing or repeated entry is refused', () => {
    const compose = prodCompose
      .replace('      - OAUTH_DYNAMIC_CLIENT_REGISTRATION=true\n', '')
      .replace('      - TEE_MODE=production\n', '      - TEE_MODE=production\n      - TEE_MODE=development\n');
    expect(checkMeasuredSettings(appCompose(compose), literalEnv(prodCompose)))
      .toEqual({ ok: false, unreadable: false, settings: ['OAUTH_DYNAMIC_CLIENT_REGISTRATION', 'TEE_MODE'] });
  });

  test('an empty literal passes only when the process sees it empty or unset', () => {
    const env = literalEnv(prodCompose);
    expect(env.OPENKEY_NATIVE_RENEW_DISABLED).toBe('');
    delete env.OPENKEY_NATIVE_RENEW_DISABLED;
    expect(checkMeasuredSettings(appCompose(prodCompose), env)).toEqual({ ok: true });
    expect(checkMeasuredSettings(appCompose(prodCompose), { ...env, OPENKEY_NATIVE_RENEW_DISABLED: 'true' }))
      .toEqual({ ok: false, unreadable: false, settings: ['OPENKEY_NATIVE_RENEW_DISABLED'] });
  });

  test('an app-compose without a readable api environment is refused', () => {
    for (const measured of ['not json', JSON.stringify({}), appCompose('services: {}'), appCompose(': [')]) {
      expect(checkMeasuredSettings(measured, literalEnv(prodCompose))).toEqual({ ok: false, unreadable: true });
    }
  });
});
