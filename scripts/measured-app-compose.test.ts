import { describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { checkMeasurement } from './measured-app-compose';

const API_IMAGE = `skgbafa/openkey-api@sha256:${'ab'.repeat(32)}`;
const INGRESS_IMAGE = `dstacktee/dstack-ingress:20250924@sha256:${'cd'.repeat(32)}`;

function appCompose(apiImage: string): string {
  const dockerCompose = `services:\n  api:\n    image: ${apiImage}\n  dstack-ingress:\n    image: ${INGRESS_IMAGE}\n`;
  return JSON.stringify({ allowed_envs: ['DATABASE_URL'], docker_compose_file: dockerCompose, runner: 'docker-compose' });
}

const sha256 = (text: string) => createHash('sha256').update(text, 'utf8').digest('hex');

// One reading as Phala returns it: /cvms/<name> and /cvms/<vm_uuid>/attestation.
function reading(compose: string, { reported = sha256(compose), event = sha256(compose) } = {}) {
  return {
    info: { compose_hash: reported },
    attestation: {
      tcb_info: {
        app_compose: compose,
        event_log: [
          { event: 'app-id', event_payload: 'b7d6e87778f73904a8f5fd26e4d0f1d1310234be' },
          { event: 'compose-hash', event_payload: event },
        ],
      },
    },
  };
}

describe('saving the measured app-compose (TC-3837)', () => {
  test('a consistent reading returns the exact measured bytes and their hash', () => {
    const compose = appCompose(API_IMAGE);
    const { info, attestation } = reading(compose);
    expect(checkMeasurement(info, attestation, API_IMAGE)).toEqual({ composeHash: sha256(compose), appCompose: compose });
  });

  test('a compose-hash event that differs from the app-compose is refused', () => {
    const compose = appCompose(API_IMAGE);
    const { info, attestation } = reading(compose, { event: sha256(appCompose(API_IMAGE.replace('ab', 'ef'))) });
    expect(checkMeasurement(info, attestation, API_IMAGE)).toHaveProperty('problem');
  });

  test('a stale compose_hash from Phala is refused', () => {
    const compose = appCompose(API_IMAGE);
    const { info, attestation } = reading(compose, { reported: '0'.repeat(64) });
    expect(checkMeasurement(info, attestation, API_IMAGE)).toHaveProperty('problem');
  });

  test('the previous deploy still running is refused', () => {
    const previous = `skgbafa/openkey-api@sha256:${'99'.repeat(32)}`;
    const { info, attestation } = reading(appCompose(previous));
    expect(checkMeasurement(info, attestation, API_IMAGE)).toEqual({
      problem: `measured api image is ${previous}, not ${API_IMAGE}`,
    });
  });

  test('a measured compose that names the api image by tag is refused', () => {
    const { info, attestation } = reading(appCompose('skgbafa/openkey-api:0d0d319b9d3d1464586505a2b9c8d7f3d9da1d95'));
    expect(checkMeasurement(info, attestation, API_IMAGE)).toHaveProperty('problem');
  });
});
