import { json } from '@sveltejs/kit';
import type { RequestHandler } from './$types';
import { db } from '$lib/server/db';

export const GET: RequestHandler = async ({ params, locals }) => {
	const user = locals.user;
	if (!user) return new Response('Unauthorized', { status: 401 });

	const app = await db.oauthClient.findUnique({
		where: { clientId: params.clientId },
		select: {
			id: true,
			clientId: true,
			name: true,
			uri: true,
			icon: true,
			redirectUris: true,
			scopes: true,
			type: true,
			public: true,
			disabled: true,
			createdAt: true,
			updatedAt: true,
			userId: true,
		},
	});

	if (!app) {
		return json({ error: 'App not found' }, { status: 404 });
	}

	if (app.userId !== user.id) {
		return json({ error: 'Forbidden' }, { status: 403 });
	}

	return json(app);
};

export const PATCH: RequestHandler = async ({ params, request, locals }) => {
	const user = locals.user;
	if (!user) return new Response('Unauthorized', { status: 401 });

	const app = await db.oauthClient.findUnique({
		where: { clientId: params.clientId },
		select: { userId: true },
	});

	if (!app) {
		return json({ error: 'App not found' }, { status: 404 });
	}

	if (app.userId !== user.id) {
		return json({ error: 'Forbidden' }, { status: 403 });
	}

	let body: {
		name?: string;
		redirectUris?: string[];
		uri?: string;
		icon?: string;
		disabled?: boolean;
	};

	try {
		body = await request.json();
	} catch {
		return json({ error: 'Invalid JSON body' }, { status: 400 });
	}

	const data: Record<string, unknown> = {};

	if (body.name !== undefined) {
		if (typeof body.name !== 'string' || body.name.trim().length === 0) {
			return json({ error: 'App name cannot be empty' }, { status: 400 });
		}
		data.name = body.name.trim();
	}

	if (body.redirectUris !== undefined) {
		if (!Array.isArray(body.redirectUris) || body.redirectUris.length === 0) {
			return json({ error: 'At least one redirect URI is required' }, { status: 400 });
		}
		data.redirectUris = body.redirectUris;
	}

	if (body.uri !== undefined) {
		data.uri = body.uri?.trim() || null;
	}

	if (body.icon !== undefined) {
		data.icon = body.icon?.trim() || null;
	}

	if (body.disabled !== undefined) {
		data.disabled = Boolean(body.disabled);
	}

	const updated = await db.oauthClient.update({
		where: { clientId: params.clientId },
		data,
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

	return json(updated);
};

export const DELETE: RequestHandler = async ({ params, locals }) => {
	const user = locals.user;
	if (!user) return new Response('Unauthorized', { status: 401 });

	const app = await db.oauthClient.findUnique({
		where: { clientId: params.clientId },
		select: { userId: true, clientId: true },
	});

	if (!app) {
		return json({ error: 'App not found' }, { status: 404 });
	}

	if (app.userId !== user.id) {
		return json({ error: 'Forbidden' }, { status: 403 });
	}

	// Cascade delete: remove tokens, consents, then the client
	await db.$transaction([
		db.oauthAccessToken.deleteMany({ where: { clientId: app.clientId } }),
		db.oauthRefreshToken.deleteMany({ where: { clientId: app.clientId } }),
		db.oauthConsent.deleteMany({ where: { clientId: app.clientId } }),
		db.oauthClient.delete({ where: { clientId: params.clientId } }),
	]);

	return json({ success: true });
};
