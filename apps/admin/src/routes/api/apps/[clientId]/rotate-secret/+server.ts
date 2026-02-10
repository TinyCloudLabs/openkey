import { json } from '@sveltejs/kit';
import type { RequestHandler } from './$types';
import { db } from '$lib/server/db';
import { generateClientSecret, hashSecret } from '$lib/server/oauth';

export const POST: RequestHandler = async ({ params, locals }) => {
	const user = locals.user;
	if (!user) return new Response('Unauthorized', { status: 401 });

	const app = await db.oauthClient.findUnique({
		where: { clientId: params.clientId },
		select: { userId: true, type: true, public: true },
	});

	if (!app) {
		return json({ error: 'App not found' }, { status: 404 });
	}

	if (app.userId !== user.id) {
		return json({ error: 'Forbidden' }, { status: 403 });
	}

	if (app.public) {
		return json({ error: 'Public clients (SPA) do not have a client secret' }, { status: 400 });
	}

	const plaintextSecret = generateClientSecret();
	const hashedSecret = hashSecret(plaintextSecret);

	await db.oauthClient.update({
		where: { clientId: params.clientId },
		data: { clientSecret: hashedSecret },
	});

	return json({ clientSecret: plaintextSecret });
};
