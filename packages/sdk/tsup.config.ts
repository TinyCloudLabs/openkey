import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm', 'cjs'],
  dts: true,
  clean: true,
  sourcemap: true,
  minify: false,
  // Inline the internal @openkey/core workspace package into the bundle so
  // consumers never need it resolvable on disk (npm consumers already get
  // this "for free" since it isn't in package.json dependencies; local/
  // vendored consumption - e.g. a Docker additional-context copy of this
  // package that isn't inside the OpenKey bun workspace - depends on it).
  noExternal: ['@openkey/core'],
});
