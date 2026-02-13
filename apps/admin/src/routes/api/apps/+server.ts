import { json } from '@sveltejs/kit';
import type { RequestHandler } from './$types';
import { db } from '$lib/server/db';
import { generateClientId, generateClientSecret, hashSecret } from '$lib/server/oauth';

export const GET: RequestHandler = async ({ locals }) => {
	const user = locals.user;
	if (!user) return new Response('Unauthorized', { status: 401 });

	const apps = await db.oauthClient.findMany({
		where: { userId: user.id },
		orderBy: { createdAt: 'desc' },
		select: {
			id: true,
			clientId: true,
			name: true,
			uri: true,
			icon: true,
			redirectUris: true,
			scopes: true,
			type: true,
			disabled: true,
			createdAt: true,
			updatedAt: true,
		},
	});

	return json(apps);
};

export const POST: RequestHandler = async ({ request, locals }) => {
	const user = locals.user;
	if (!user) return new Response('Unauthorized', { status: 401 });

	let body: {
		name?: string;
		redirectUris?: string[];
		uri?: string;
		icon?: string;
		type?: string;
		scopes?: string[];
	};

	try {
		body = await request.json();
	} catch {
		return json({ error: 'Invalid JSON body' }, { status: 400 });
	}

	const { name, redirectUris, uri, icon, type, scopes } = body;

	if (!name || typeof name !== 'string' || name.trim().length === 0) {
		return json({ error: 'App name is required' }, { status: 400 });
	}

	if (!redirectUris || !Array.isArray(redirectUris) || redirectUris.length === 0) {
		return json({ error: 'At least one redirect URI is required' }, { status: 400 });
	}

	for (const uri of redirectUris) {
		if (typeof uri !== 'string' || uri.trim().length === 0) {
			return json({ error: 'Invalid redirect URI' }, { status: 400 });
		}
	}

	const appType = type || 'web';
	if (!['web', 'spa', 'native'].includes(appType)) {
		return json({ error: 'Type must be web, spa, or native' }, { status: 400 });
	}

	const clientId = generateClientId();
	const isPublicClient = appType === 'spa';

	let plaintextSecret: string | null = null;
	let hashedSecret: string | null = null;

	if (!isPublicClient) {
		plaintextSecret = generateClientSecret();
		hashedSecret = hashSecret(plaintextSecret);
	}

	const resolvedScopes = scopes && Array.isArray(scopes) ? scopes : ['openid'];
	if (!resolvedScopes.includes('openid')) {
		resolvedScopes.unshift('openid');
	}

	const app = await db.oauthClient.create({
		data: {
			id: clientId,
			clientId,
			clientSecret: hashedSecret,
			name: name.trim(),
			uri: uri?.trim() || null,
			icon: icon?.trim() || null,
			redirectUris,
			scopes: resolvedScopes,
			type: appType,
			public: isPublicClient,
			tokenEndpointAuthMethod: isPublicClient ? 'none' : 'client_secret_post',
			userId: user.id,
		},
	});

	return json(
		{
			id: app.id,
			clientId: app.clientId,
			clientSecret: plaintextSecret,
			name: app.name,
			uri: app.uri,
			icon: app.icon,
			redirectUris: app.redirectUris,
			scopes: app.scopes,
			type: app.type,
			createdAt: app.createdAt,
		},
		{ status: 201 },
	);
};
