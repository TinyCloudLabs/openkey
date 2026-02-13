import { error, redirect } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';
import { db } from '$lib/server/db';

export const load: PageServerLoad = async ({ params, locals }) => {
	const user = locals.user;
	if (!user) throw redirect(302, '/');

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
		throw error(404, 'Application not found');
	}

	if (app.userId !== user.id) {
		throw error(403, 'Forbidden');
	}

	return { app };
};
