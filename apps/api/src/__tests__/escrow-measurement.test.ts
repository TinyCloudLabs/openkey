import { expect, test } from 'bun:test';
import { escrowMeasurementFromInfo } from '../services/escrow-measurement';
test('measurement comes from guest compose and every image must be digest pinned', () => {
  const digest = 'a'.repeat(64), composeHash = 'b'.repeat(64);
  const info = { app_id: 'c'.repeat(40), instance_id: 'd'.repeat(40), compose_hash: composeHash, tcb_info: { compose_hash: composeHash, os_image_hash: 'e'.repeat(64), app_compose: JSON.stringify({ runner: 'docker-compose', docker_compose_file: `services:\n  api:\n    image: test@sha256:${digest}\n  ingress:\n    image: ingress@sha256:${digest}\n` }) } };
  const boot = '12345678-1234-1234-1234-123456789abc';
  expect(escrowMeasurementFromInfo(info, 'f'.repeat(64), boot, 'unknown').imageDigest).toBe('sha256:' + digest);
  const unpinned = { ...info, tcb_info: { ...info.tcb_info, app_compose: JSON.stringify({ runner: 'docker-compose', docker_compose_file: 'services:\n  api:\n    image: test:latest\n' }) } };
  expect(() => escrowMeasurementFromInfo(unpinned, 'f'.repeat(64), boot, 'unknown')).toThrow();
  expect(() => escrowMeasurementFromInfo(info, null, boot, 'unknown')).toThrow();
  expect(() => escrowMeasurementFromInfo({ ...info, compose_hash: '0'.repeat(64) }, 'f'.repeat(64), boot, 'unknown')).toThrow();
});
