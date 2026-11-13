import openkey from '../pins/openkey.json';
import witness from '../pins/witness.json';

export interface ServiceReleasePin {
  appId: string; composeHash: string; imageDigest: string; kmsRootPublicKey: string;
  mrTd: string; rtmr0: string; rtmr1: string; rtmr2: string;
}

// Reviewed additions only. No env, runtime file or public input can replace trust.
export const SERVICE_RELEASES: readonly ServiceReleasePin[] = Object.freeze(
  [...openkey, ...witness].map(pin => Object.freeze(pin)),
);
