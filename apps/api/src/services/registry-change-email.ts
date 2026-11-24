// TC-3893: post-publish notice email sent via the Resend client (same EmailSender
// interface as `email-otp-delivery.ts` and `auth.ts`). Wording is Monica's final copy
// from tc3890-wording-monica.md §2 + 16:49Z F3 mode labels.

import type { LocationRecordV2Payload } from '@tinycloud/sdk-core';
import type { EmailSender } from './email-otp-delivery';
import { displayNodeHost } from './registry-change-client';
import { log, logRegistryChangeNoticeFailed } from '../log';

export const REGISTRY_CHANGE_EMAIL_FROM = 'OpenKey <noreply@openkey.so>';
export const DEFAULT_ONE_REGISTRY_SETTINGS_URL = 'https://tinycloud.one/chat/settings';

export const REGISTRY_CHANGE_EMAIL_COPY = {
  subject: 'Where your TinyCloud data lives was changed',
  notSet: 'Not set',
  encryptionLabel: 'Secrets and keys',
  modeReadOnly: 'read-only',
  modeReadWrite: 'read and write',
  whatChangedHeading: 'What changed:',
  newDataLine: 'Your apps save new data at the new hosts. Data you saved before stays where it was.',
  undoPrefix: "If this wasn't you, undo it in TinyCloud One → Settings → Where your data lives:",
  noActionLine: "If it was you, you don't need to do anything.",
} as const;

export interface RegistryChangeNoticeInput {
  readonly to: string;
  readonly requestingOrigin: string;
  readonly before: LocationRecordV2Payload;
  readonly after: LocationRecordV2Payload;
  readonly publishedAt: Date;
  readonly historyId?: string;
  readonly undoUrl?: string;
}

export interface FormattedRegistryChangeNotice {
  readonly subject: string;
  readonly text: string;
  readonly html: string;
  readonly changes: string[];
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  })[ch] ?? ch);
}

function formatUtcDate(date: Date): { date: string; time: string } {
  const iso = date.toISOString();
  return {
    date: iso.slice(0, 10),
    time: iso.slice(11, 16),
  };
}

function spaceDisplayName(spaceUri: string): string {
  const lastColon = spaceUri.lastIndexOf(':');
  return lastColon >= 0 && lastColon + 1 < spaceUri.length ? spaceUri.slice(lastColon + 1) : spaceUri;
}

function modeLabel(mode: string): string {
  return mode === 'read-only'
    ? REGISTRY_CHANGE_EMAIL_COPY.modeReadOnly
    : REGISTRY_CHANGE_EMAIL_COPY.modeReadWrite;
}

type ResolvedMembership = { host: string; mode: string };

function resolveSpaceMemberships(
  nodes: ReadonlyArray<{ did: string; mode: string }>,
  nodeUrlByDid: ReadonlyMap<string, string>,
): ResolvedMembership[] {
  return nodes
    .map((m) => {
      const url = nodeUrlByDid.get(m.did);
      return { host: url ? displayNodeHost(url) : m.did, mode: m.mode };
    })
    .sort((a, b) => a.host.localeCompare(b.host) || a.mode.localeCompare(b.mode));
}

function membershipsEqual(a: ResolvedMembership[], b: ResolvedMembership[]): boolean {
  if (a.length !== b.length) return false;
  return a.every((item, i) => item.host === b[i]!.host && item.mode === b[i]!.mode);
}

function hostsOnlyEqual(a: ResolvedMembership[], b: ResolvedMembership[]): boolean {
  if (a.length !== b.length) return false;
  return a.every((item, i) => item.host === b[i]!.host);
}

function formatMembershipList(memberships: ResolvedMembership[], showModes: boolean): string {
  if (memberships.length === 0) return REGISTRY_CHANGE_EMAIL_COPY.notSet;
  return memberships
    .map((m) => (showModes ? `${m.host} (${modeLabel(m.mode)})` : m.host))
    .join(', ');
}

export function formatRegistryChangeNoticeEmail(input: RegistryChangeNoticeInput): FormattedRegistryChangeNotice {
  const { date, time } = formatUtcDate(input.publishedAt);
  const undoUrl = input.undoUrl ?? DEFAULT_ONE_REGISTRY_SETTINGS_URL;

  const beforeUrls = new Map(input.before.nodes.map((n) => [n.did, n.url]));
  const afterUrls = new Map(input.after.nodes.map((n) => [n.did, n.url]));
  const beforeSpaces = new Map(input.before.spaces.map((s) => [s.space, s.nodes]));
  const afterSpaces = new Map(input.after.spaces.map((s) => [s.space, s.nodes]));

  const allSpaces = [...new Set([...beforeSpaces.keys(), ...afterSpaces.keys()])].sort();
  const changes: string[] = [];

  for (const spaceUri of allSpaces) {
    const beforeMem = resolveSpaceMemberships(beforeSpaces.get(spaceUri) ?? [], beforeUrls);
    const afterMem = resolveSpaceMemberships(afterSpaces.get(spaceUri) ?? [], afterUrls);
    if (membershipsEqual(beforeMem, afterMem)) continue;

    const name = spaceDisplayName(spaceUri);
    // F3 mode-only change on a single host: "{space}: {host}, read-only → read and write" (Monica 16:49Z).
    if (beforeMem.length === 1 && afterMem.length === 1 && hostsOnlyEqual(beforeMem, afterMem)) {
      changes.push(`${name}: ${beforeMem[0]!.host}, ${modeLabel(beforeMem[0]!.mode)} → ${modeLabel(afterMem[0]!.mode)}`);
    } else {
      const showModes =
        hostsOnlyEqual(beforeMem, afterMem) ||
        beforeMem.some((m) => m.mode === 'read-only') ||
        afterMem.some((m) => m.mode === 'read-only');
      const oldText = formatMembershipList(beforeMem, showModes);
      const newText = formatMembershipList(afterMem, showModes);
      changes.push(`${name}: ${oldText} → ${newText}`);
    }
  }

  const oldEncUrl = input.before.encryptionNode ? beforeUrls.get(input.before.encryptionNode) ?? null : null;
  const newEncUrl = input.after.encryptionNode ? afterUrls.get(input.after.encryptionNode) ?? null : null;
  if (input.before.encryptionNode !== input.after.encryptionNode || oldEncUrl !== newEncUrl) {
    const oldEncHost = oldEncUrl ? displayNodeHost(oldEncUrl) : REGISTRY_CHANGE_EMAIL_COPY.notSet;
    const newEncHost = newEncUrl ? displayNodeHost(newEncUrl) : REGISTRY_CHANGE_EMAIL_COPY.notSet;
    changes.push(`${REGISTRY_CHANGE_EMAIL_COPY.encryptionLabel}: ${oldEncHost} → ${newEncHost}`);
  }

  const introLine = `On ${date} at ${time} UTC, ${input.requestingOrigin} changed where your TinyCloud data lives, and you approved it with your passkey.`;
  const changeSectionText = changes.length > 0
    ? `${REGISTRY_CHANGE_EMAIL_COPY.whatChangedHeading}\n${changes.map((line) => `- ${line}`).join('\n')}`
    : `${REGISTRY_CHANGE_EMAIL_COPY.whatChangedHeading}\n- No host changes`;

  const text = [
    introLine,
    '',
    changeSectionText,
    '',
    REGISTRY_CHANGE_EMAIL_COPY.newDataLine,
    '',
    `${REGISTRY_CHANGE_EMAIL_COPY.undoPrefix} ${undoUrl}`,
    '',
    REGISTRY_CHANGE_EMAIL_COPY.noActionLine,
  ].join('\n');

  const changesHtml = changes.length > 0
    ? `<ul style="padding-left: 20px; margin: 8px 0 16px;">${changes.map((line) => `<li style="margin-bottom: 4px;">${escapeHtml(line)}</li>`).join('')}</ul>`
    : '<p style="margin: 8px 0 16px;">No host changes</p>';

  const html = `
<div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 560px; margin: 0 auto; padding: 20px; color: #1a1a1a; line-height: 1.5;">
  <p>${escapeHtml(introLine)}</p>
  <p style="font-weight: 600; margin-bottom: 4px;">${escapeHtml(REGISTRY_CHANGE_EMAIL_COPY.whatChangedHeading)}</p>
  ${changesHtml}
  <p>${escapeHtml(REGISTRY_CHANGE_EMAIL_COPY.newDataLine)}</p>
  <p>${escapeHtml(REGISTRY_CHANGE_EMAIL_COPY.undoPrefix)} <a href="${escapeHtml(undoUrl)}">${escapeHtml(undoUrl)}</a></p>
  <p style="color: #666; font-size: 14px;">${escapeHtml(REGISTRY_CHANGE_EMAIL_COPY.noActionLine)}</p>
</div>`.trim();

  return {
    subject: REGISTRY_CHANGE_EMAIL_COPY.subject,
    text,
    html,
    changes,
  };
}

/**
 * Send the registry-change notice email via Resend. Best-effort after publish succeeds:
 * logs failures without rolling back or failing the already-published registry update.
 */
export async function sendRegistryChangeNoticeEmail(
  resend: EmailSender | null,
  input: RegistryChangeNoticeInput,
): Promise<boolean> {
  if (!resend) {
    log('warn', 'registry_change_notice_email_unconfigured');
    return false;
  }
  const formatted = formatRegistryChangeNoticeEmail(input);
  try {
    const result = await resend.emails.send({
      from: REGISTRY_CHANGE_EMAIL_FROM,
      to: input.to,
      subject: formatted.subject,
      html: formatted.html,
    });
    if (result.error) {
      logRegistryChangeNoticeFailed(input.historyId);
      return false;
    }
    return true;
  } catch {
    logRegistryChangeNoticeFailed(input.historyId);
    return false;
  }
}
