import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm', 'cjs'],
  dts: true,
  clean: true,
  platform: 'browser',
  external: ['@capacitor/core', '@tinycloud/web-sdk'],
  noExternal: ['@openkey/core', /^@noble\//],
});
