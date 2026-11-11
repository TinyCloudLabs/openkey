import { Resend } from 'resend';
import type { PrismaClient } from '@openkey/db';
import type { InvitationDelivery } from './org-key-admins';

export function invitationEmailDelivery(prisma: PrismaClient): InvitationDelivery {
  return async mail => {
    if (!process.env.RESEND_API_KEY) throw new Error('Email transport unavailable');
    const [owner, org] = await Promise.all([
      prisma.user.findUniqueOrThrow({ where: { id: mail.ownerId }, select: { name: true, email: true } }),
      prisma.orgKey.findUniqueOrThrow({ where: { keyId: mail.keyId }, select: { orgName: true } }),
    ]);
    const ownerName = (owner.name || owner.email).replace(/[\r\n]/g, ' ');
    const orgName = org.orgName.replace(/[\r\n]/g, ' ');
    const link = `https://openkey.so/org-key-invitations/${encodeURIComponent(mail.invitationId)}#token=${mail.token}`;
    const expires = mail.expiresAt.toLocaleString('en-GB', { timeZone: 'UTC', dateStyle: 'long', timeStyle: 'short' }) + ' UTC';
    const sent = await new Resend(process.env.RESEND_API_KEY).emails.send({
      from: 'OpenKey <noreply@openkey.so>', to: mail.to,
      subject: `${ownerName} invited you to be an admin for ${orgName} on OpenKey`,
      text: `${ownerName} (${owner.email}) invited you to be an admin for ${orgName}'s organisation key on OpenKey.\n\nReview the invitation on OpenKey before you accept:\n${link}\n\nThis invitation expires ${expires}. Only someone signed in to OpenKey who has verified ${mail.to} can accept it.\n\nIf you weren't expecting this, you can ignore this email.`,
    }, { idempotencyKey: `org-admin-invitation/${mail.invitationId}` });
    if (sent.error) throw new Error('Email transport failed');
  };
}
