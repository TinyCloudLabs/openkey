const PRODUCTION_NODE_HOSTS = new Set([
  'https://node.tinycloud.xyz',
  'https://tee.node.tinycloud.xyz',
]);

/** The two production names identify the same TinyCloud node. */
export function sameTinyCloudHost(left: string, right: string): boolean {
  return left === right || (PRODUCTION_NODE_HOSTS.has(left) && PRODUCTION_NODE_HOSTS.has(right));
}
