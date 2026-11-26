import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { unpinnedImages } from './compose-image-digests';

const DIGEST = `sha256:${'ab'.repeat(32)}`;
const prodCompose = readFileSync(resolve(import.meta.dir, '../docker-compose.prod.yml'), 'utf8');

function compose(image: string): string {
  return `services:\n  api:\n    image: ${image}\n`;
}

describe('production compose image pinning (TC-3837)', () => {
  test('the production compose as deploy-api.yml renders it passes', () => {
    const rendered = prodCompose.replaceAll('${DOCKER_IMAGE}', `skgbafa/openkey-api@${DIGEST}`);
    expect(unpinnedImages(rendered)).toEqual([]);
  });

  test('the production compose with the image placeholder left in fails', () => {
    expect(unpinnedImages(prodCompose)).toEqual(['api: image "${DOCKER_IMAGE}" is not pinned by @sha256 digest']);
  });

  test('a tag alone fails; a tag with a digest passes', () => {
    expect(unpinnedImages(compose('skgbafa/openkey-api:0123abc'))).toHaveLength(1);
    expect(unpinnedImages(compose('skgbafa/openkey-api:latest'))).toHaveLength(1);
    expect(unpinnedImages(compose(`dstacktee/dstack-ingress:20250924@${DIGEST}`))).toEqual([]);
    expect(unpinnedImages(compose(`ghcr.io/tinycloudlabs/openkey-api@${DIGEST}`))).toEqual([]);
  });

  test('a digest built from a variable fails', () => {
    expect(unpinnedImages(compose('skgbafa/openkey-api@${IMAGE_DIGEST}'))).toHaveLength(1);
    expect(unpinnedImages(compose(`\${REGISTRY}/openkey-api@${DIGEST}`))).toHaveLength(1);
  });

  test('a short or non-sha256 digest fails', () => {
    expect(unpinnedImages(compose(`skgbafa/openkey-api@sha256:${'ab'.repeat(31)}`))).toHaveLength(1);
    expect(unpinnedImages(compose(`skgbafa/openkey-api@sha512:${'ab'.repeat(64)}`))).toHaveLength(1);
  });

  test('a service that builds in the CVM or has no image fails', () => {
    expect(unpinnedImages(`services:\n  api:\n    build: .\n    image: skgbafa/openkey-api@${DIGEST}\n`))
      .toEqual(['api: builds its image in the CVM']);
    expect(unpinnedImages('services:\n  api:\n    restart: always\n')).toHaveLength(1);
  });

  test('every service is checked, not only the first', () => {
    const text = `services:\n  api:\n    image: skgbafa/openkey-api@${DIGEST}\n  sidecar:\n    image: busybox:1\n`;
    expect(unpinnedImages(text)).toEqual(['sidecar: image "busybox:1" is not pinned by @sha256 digest']);
  });

  test('a compose without services fails', () => {
    expect(unpinnedImages('volumes:\n  data:\n')).toEqual(['compose has no services']);
  });
});
