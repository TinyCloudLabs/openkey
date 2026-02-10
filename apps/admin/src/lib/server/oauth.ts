import { randomBytes, createHash } from 'crypto';

export function generateClientId(): string {
	return `ok_${randomBytes(16).toString('hex')}`;
}

export function generateClientSecret(): string {
	return `oks_${randomBytes(32).toString('hex')}`;
}

export function hashSecret(secret: string): string {
	return createHash('sha256').update(secret).digest('hex');
}
