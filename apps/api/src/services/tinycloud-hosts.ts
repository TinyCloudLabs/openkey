// TinyCloud nodes OpenKey may sign for or host spaces on. Shared by the
// bootstrap flow and the native delegation client ceiling.
export const DEFAULT_TINYCLOUD_BOOTSTRAP_HOST = 'https://node.tinycloud.xyz';
export const TRUSTED_TINYCLOUD_BOOTSTRAP_HOSTS: ReadonlySet<string> = new Set([
  DEFAULT_TINYCLOUD_BOOTSTRAP_HOST,
  'https://tee.node.tinycloud.xyz',
]);
