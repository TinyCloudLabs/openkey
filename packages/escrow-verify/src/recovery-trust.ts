import recovery from '../pins/recovery.json';
import type { ServiceReleasePin } from './trust';

export interface RecoveryReleasePin extends ServiceReleasePin { codeHash: string }
// Only reviewed release entries can enable recovery holder release.
export const RECOVERY_RELEASES: readonly RecoveryReleasePin[] = Object.freeze(recovery.map(pin => Object.freeze(pin)));
