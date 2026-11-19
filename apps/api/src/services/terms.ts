// TC-3232: the Terms of Service every account accepts before it can use OpenKey (the Privacy Policy is
// acknowledged under the same version). The release is the checked-in `terms-release.json`, so turning
// the gate on, or publishing a new version, is a reviewed change:
//   version          YYYY-MM-DD the account accepts now (also the effective date shown); null = no gate
//   requiredVersion  oldest acceptance that still counts (an editorial fix keeps it); null = version
//   textSha256       SHA-256 (hex) of the published text of `version`
//   whatChanged      one plain line shown to accounts re-accepting; null = none
//   privacyChanged   the Privacy Policy changed in the same release
// A file that does not fit this shape stops the API at boot.
import { randomUUID } from 'node:crypto';
import type { PrismaClient } from '@openkey/db';
import { readBuildInfo } from '../build-info';
import releaseFile from '../terms-release.json';

export type TermsRelease = {
  /** YYYY-MM-DD: the version an account accepts now, and the date it takes effect. */
  version: string;
  /** An acceptance of this version or later still counts (an editorial fix leaves it unchanged). */
  requiredVersion: string;
  /** SHA-256 (hex) of the published text of `version`. */
  textSha256: string;
  whatChanged: string | null;
  privacyChanged: boolean;
};

type TermsDatabase = Pick<PrismaClient, 'termsAcceptance'>;

const SHA256 = /^[0-9a-f]{64}$/;

function isDate(value: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const date = new Date(`${value}T00:00:00Z`);
  return !Number.isNaN(date.getTime()) && date.toISOString().startsWith(value);
}

/** Null when the file sets no version. Throws on a file that does not fit the shape above. */
export function termsRelease(file: unknown = releaseFile): TermsRelease | null {
  const invalid = () => new Error('Invalid terms-release.json');
  if (!file || typeof file !== 'object' || Array.isArray(file)) throw invalid();
  const { version, requiredVersion, textSha256, whatChanged, privacyChanged, ...rest } = file as Record<string, unknown>;
  // Exactly the five fields: none missing (so a null is always written out), none unknown.
  if (Object.keys(rest).length || Object.keys(file).length !== 5 || typeof privacyChanged !== 'boolean'
    || (whatChanged !== null && typeof whatChanged !== 'string')) throw invalid();
  if (version === null) {
    if (requiredVersion !== null || textSha256 !== null || whatChanged !== null || privacyChanged) throw invalid();
    return null;
  }
  const required = requiredVersion ?? version;
  // Versions are dates, so string order is version order.
  if (typeof version !== 'string' || !isDate(version) || typeof required !== 'string' || !isDate(required)
    || required > version || typeof textSha256 !== 'string' || !SHA256.test(textSha256)) throw invalid();
  const changed = typeof whatChanged === 'string' ? whatChanged.trim() || null : null;
  return { version, requiredVersion: required, textSha256, whatChanged: changed, privacyChanged };
}

/** The refusal every gated route answers until the account accepts. Callers without a screen show the URL. */
export function termsRequired() {
  const termsUrl = `${process.env.WEBAUTHN_ORIGIN}/auth/terms`;
  return {
    error: 'terms_required',
    error_description: `Open ${termsUrl} to accept the Terms of Service.`,
    terms_url: termsUrl,
  } as const;
}

/** True when no release is configured, or the account accepted a version that still counts. */
export async function hasAcceptedTerms(database: TermsDatabase, userId: string, release = termsRelease()): Promise<boolean> {
  if (!release) return true;
  return await database.termsAcceptance.findFirst({
    where: { userId, version: { gte: release.requiredVersion } },
    select: { id: true },
  }) !== null;
}

export async function termsStatus(database: TermsDatabase, userId: string, release: TermsRelease | null) {
  const latest = await database.termsAcceptance.findFirst({
    where: { userId }, orderBy: { version: 'desc' }, select: { version: true },
  });
  return {
    version: release?.version ?? null,
    effective: release?.version ?? null,
    whatChanged: release?.whatChanged ?? null,
    privacyChanged: release?.privacyChanged ?? false,
    requiresAcceptance: release !== null && (latest === null || latest.version < release.requiredVersion),
    // Accepted an earlier version: the screen says the Terms were updated.
    previouslyAccepted: latest !== null,
  };
}

/**
 * Records that the account accepted `release.version`. A second acceptance of the same version (another
 * tab, a retry) keeps the first row: the insert skips a row the (userId, version) key already holds.
 */
export async function recordTermsAcceptance(database: TermsDatabase, userId: string, release: TermsRelease, surface: string): Promise<void> {
  const build = readBuildInfo();
  await database.termsAcceptance.createMany({
    data: [{
      id: randomUUID(),
      userId,
      documentId: 'terms',
      version: release.version,
      textSha256: release.textSha256,
      surface,
      appVersion: `${build.version}+${build.commit}`,
    }],
    skipDuplicates: true,
  });
}
