import { createHash } from 'node:crypto';
import { expect, test } from 'bun:test';
import { escrowMeasurementFromInfo } from '../services/escrow-measurement';
test('measurement comes from guest compose and every image must be digest pinned', () => {
  const digest = 'a'.repeat(64), composeHash = 'b'.repeat(64);
  const info = { app_id: 'c'.repeat(40), instance_id: 'd'.repeat(40), compose_hash: composeHash, tcb_info: { compose_hash: composeHash, os_image_hash: 'e'.repeat(64), app_compose: JSON.stringify({ runner: 'docker-compose', docker_compose_file: `services:\n  api:\n    image: test@sha256:${digest}\n  ingress:\n    image: ingress@sha256:${digest}\n` }) } };
  info.compose_hash = createHash('sha256').update(info.tcb_info.app_compose).digest('hex'); info.tcb_info.compose_hash = info.compose_hash;
  const boot = '12345678-1234-1234-1234-123456789abc';
  expect(escrowMeasurementFromInfo(info, 'f'.repeat(64), boot, 'unknown').imageDigest).toBe('sha256:' + digest);
  const unpinned = { ...info, tcb_info: { ...info.tcb_info, app_compose: JSON.stringify({ runner: 'docker-compose', docker_compose_file: 'services:\n  api:\n    image: test:latest\n' }) } };
  unpinned.compose_hash = createHash('sha256').update(unpinned.tcb_info.app_compose).digest('hex'); unpinned.tcb_info.compose_hash = unpinned.compose_hash;
  expect(() => escrowMeasurementFromInfo(unpinned, 'f'.repeat(64), boot, 'unknown')).toThrow();
  expect(() => escrowMeasurementFromInfo({ ...info, tcb_info: { ...info.tcb_info, app_compose: info.tcb_info.app_compose + ' ' } }, 'f'.repeat(64), boot, 'unknown')).toThrow('hash mismatch');
  expect(() => escrowMeasurementFromInfo(info, null, boot, 'unknown')).toThrow();
  expect(() => escrowMeasurementFromInfo({ ...info, compose_hash: '0'.repeat(64) }, 'f'.repeat(64), boot, 'unknown')).toThrow();
});
