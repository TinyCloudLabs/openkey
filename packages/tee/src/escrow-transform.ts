/** Closed v1 material encodings; never truncate or pad GetKey material. */
export type EscrowTransform = 'sha256-getkey' | 'dstack-getkey-raw-v1';

export function escrowMaterialLength(transform: EscrowTransform): number {
  switch (transform) {
    case 'sha256-getkey': return 32;
    case 'dstack-getkey-raw-v1': return 32;
    default: throw new Error('Unknown escrow transform');
  }
}
